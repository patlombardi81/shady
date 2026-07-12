#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from collections import defaultdict

SECTION_FIELD_RE = re.compile(r'\[s(\d+)_(\w+)=(.*?)\]')


def load_config():
    raw = os.environ.get("CONFIG")
    if not raw:
        raise RuntimeError("CONFIG environment variable not set")
    return json.loads(raw)


def download_config(cfg, idl="it", pa="IT", idusu="0", cod_g="0",
                    fus="010100000000", aid="000000000000000",
                    gp="1", am="0", timeout=30):
    params = {
        "v": "197", "vname": cfg["app_version"], "idapp": cfg["app_id"],
        "idusu": idusu, "cod_g": cod_g, "gp": gp, "am": am,
        "idl": idl, "pa_env": "1", "pa": pa, "pn": cfg["package_name"],
        "fus": fus, "aid": aid,
    }
    url = cfg["config_url"] + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url)
    req.add_header("User-Agent", cfg["user_agent"])
    req.add_header("Accept", "*/*")
    req.add_header("Accept-Encoding", "identity")

    print(f"[1/4] Download config...", file=sys.stderr)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read().decode("utf-8", errors="replace")
            print(f"      Risposta: {len(content)} byte", file=sys.stderr)
            if not content or content.strip() == "[APLICNODISP][FIN]":
                raise RuntimeError("Server risposto APLICNODISP")
            return content
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.reason}")


def extract_cad_rep(config_text, cad_rep_orig):
    m = re.search(r'\[cr=([^\]]+)\]', config_text)
    if not m:
        raise RuntimeError("Campo [cr=...] non trovato")
    cad_rep = m.group(1)
    if len(cad_rep) != len(cad_rep_orig):
        raise RuntimeError(f"cad_rep lunghezza {len(cad_rep)}, expected {len(cad_rep_orig)}")
    if sorted(cad_rep) != sorted(cad_rep_orig):
        raise RuntimeError("cad_rep non valido")
    return cad_rep


def parse_config(config_text, cad_rep, cad_rep_orig, t_video):
    sections = defaultdict(dict)
    for m in SECTION_FIELD_RE.finditer(config_text):
        sec_id = m.group(1)
        field = m.group(2)
        value = m.group(3)
        sections[sec_id][field] = value

    print(f"[3/4] Sezioni totali: {len(sections)}", file=sys.stderr)

    video_sections = []
    for sec_id, fields in sections.items():
        if fields.get("tipo") != str(t_video):
            continue
        video_sections.append({"section_id": sec_id, **fields})

    print(f"      Sezioni video: {len(video_sections)}", file=sys.stderr)

    for sec in video_sections:
        sec["decoded_url"] = decode_url(sec.get("url", ""), cad_rep, cad_rep_orig)
        sec["decoded_headers"] = decode_headers(sec.get("h", ""), cad_rep, cad_rep_orig)
        sec["decoded_headers_drm"] = decode_headers(sec.get("hd", ""), cad_rep, cad_rep_orig)

    return video_sections


def decode_url(obf, cad_rep, cad_rep_orig):
    if not obf or not obf.startswith("@y@"):
        return obf or ""
    body = obf[3:]
    if body.startswith("@yy"):
        idx = body.find("@", 3)
        if idx >= 0:
            body = body[idx + 1:]
    decoded = []
    for ch in body:
        idx = cad_rep.find(ch)
        if idx >= 0:
            decoded.append(cad_rep_orig[idx])
        else:
            decoded.append(ch)
    return "".join(decoded)


def decode_headers(h, cad_rep, cad_rep_orig):
    if not h:
        return {}
    parts = h.split("@@Y@@")
    result = {}
    for p in parts:
        if "@@X@@" in p:
            k, v = p.split("@@X@@", 1)
            if k.startswith("@y@"):
                k = decode_url(k, cad_rep, cad_rep_orig)
            if v.startswith("@y@"):
                v = decode_url(v, cad_rep, cad_rep_orig)
            result[k.strip()] = v.strip()
    return result


def normalize_url(url):
    if not url:
        return ""
    url = url.strip()
    url = url.replace(":/\\/", "://")
    url = url.replace("\\/", "/")
    url = url.replace("?\\", "?")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def is_mpd_url(url):
    if not url:
        return False
    url_lower = url.lower()
    if ".mpd" in url_lower:
        return True
    if ".m3u8" in url_lower:
        return False
    if ".ism" in url_lower or "/manifest(" in url_lower:
        return False
    return False


def extract_clearkey_from_url(license_url):
    if not license_url:
        return None, None
    parsed = urllib.parse.urlparse(license_url)
    qs = urllib.parse.parse_qs(parsed.query)
    kid = qs.get("keyid", [None])[0]
    key = qs.get("key", [None])[0]
    if kid and key and len(kid) == 32 and len(key) == 32:
        try:
            int(kid, 16)
            int(key, 16)
            return kid.lower(), key.lower()
        except ValueError:
            pass
    return None, None


def format_stream_headers(headers_dict):
    if not headers_dict:
        return ""
    return "&".join(f"{k}={v}" for k, v in headers_dict.items())


def build_kodiprop_lines(sec, drm_widevine, drm_clearkey):
    lines = []
    url = normalize_url(sec.get("decoded_url", ""))
    if not url:
        return lines, url

    tipo_drm = sec.get("i3", "0")
    license_url = (sec.get("li", "") or "").replace("\\/", "/")
    headers = sec.get("decoded_headers", {}) or {}
    headers_drm = sec.get("decoded_headers_drm", {}) or {}
    ua = sec.get("ua", "") or ""

    lines.append("#KODIPROP:inputstream.adaptive.manifest_type=mpd")

    if tipo_drm == drm_widevine:
        lines.append("#KODIPROP:inputstream.adaptive.license_type=com.widevine.alpha")
        if license_url:
            if headers_drm:
                hdr_str = "&".join(f"{k}={v}" for k, v in headers_drm.items())
                lines.append(f"#KODIPROP:inputstream.adaptive.license_key={license_url}|{hdr_str}")
            else:
                lines.append(f"#KODIPROP:inputstream.adaptive.license_key={license_url}")
    elif tipo_drm == drm_clearkey:
        kid, key = extract_clearkey_from_url(license_url)
        if kid and key:
            lines.append("#KODIPROP:inputstream.adaptive.license_type=clearkey")
            lines.append(f"#KODIPROP:inputstream.adaptive.license_key={kid}:{key}")
        elif license_url:
            lines.append("#KODIPROP:inputstream.adaptive.license_type=clearkey")
            lines.append(f"#KODIPROP:inputstream.adaptive.license_key={license_url}")

    if ua and "User-Agent" not in headers:
        lines.append(f'#EXTHTTP:{{"User-Agent":"{ua}"}}')

    if headers:
        hdr_str = format_stream_headers(headers)
        lines.append(f"#KODIPROP:inputstream.adaptive.stream_headers={hdr_str}")

    return lines, url


def pick_group(sec, group_mode, default_group):
    if group_mode == "none":
        return default_group
    title = (sec.get("tit", "") or "").upper()
    if any(k in title for k in ["SPORT", "ESPN", "NBA", "NFL", "UFC", "DAZN", "FIGHT",
                                 "FOOTBALL", "GOLF", "TENNIS", "F1", "MOTOGP", "RACING",
                                 "PREMIER", "ELEVEN"]):
        return "Sport"
    if any(k in title for k in ["KIDS", "DISNEY", "CARTOON", "POKEMON", "NICK",
                                 "BOOMERANG", "BABY", "CHILDREN"]):
        return "Kids"
    if any(k in title for k in ["NEWS", "CNN", "BBC", "SKY NEWS", "TG", "AL JAZEERA"]):
        return "News"
    if any(k in title for k in ["MOVIE", "CINEMA", "FILM", "HBO", "CINE"]):
        return "Movies"
    if any(k in title for k in ["MUSIC", "MTV", "VEVO", "RADIO"]):
        return "Musica"
    if any(k in title for k in ["ADULT", "XXX", "BABES", "BRAZZERS", "PORN",
                                 "PASSION", "PURITY", "BAWAL"]):
        return "Adult"
    if any(k in title for k in ["ITALIA", "RAI", "MEDIASET", "LA7", "ITALIAN"]):
        return "Italia"
    if any(k in title for k in ["UK", "USA", "NBC", "CBS", "ABC", "FOX", "AMC",
                                 "TNT", "TBS", "SYFY", "SHOWTIME", "STARZ"]):
        return "USA/UK"
    return default_group


def generate_m3u(video_sections, output_path, cfg, group_mode="auto"):
    default_group = cfg.get("group_name", "IPTV")
    drm_widevine = cfg.get("drm_widevine", "1")
    drm_clearkey = cfg.get("drm_clearkey", "2")

    print(f"[4/4] Generazione playlist M3U...", file=sys.stderr)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("#EXTM3U\n")
        f.write(f"# Data: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("\n")

        stats = {"total": 0, "widevine": 0, "clearkey": 0, "no_drm": 0,
                 "skipped_no_mpd": 0, "written": 0}

        for sec in video_sections:
            stats["total"] += 1

            url = normalize_url(sec.get("decoded_url", ""))
            if not url:
                stats["skipped_no_mpd"] += 1
                continue

            if not is_mpd_url(url):
                stats["skipped_no_mpd"] += 1
                continue

            title = sec.get("tit", "") or f"Canale {sec['section_id']}"
            sid = sec["section_id"]
            tipo_drm = sec.get("i3", "0")
            group = pick_group(sec, group_mode, default_group)
            ua = sec.get("ua", "") or ""

            if tipo_drm == drm_widevine:
                stats["widevine"] += 1
            elif tipo_drm == drm_clearkey:
                stats["clearkey"] += 1
            else:
                stats["no_drm"] += 1

            extinf = (
                f"#EXTINF:-1 "
                f'tvg-id="{sid}" '
                f'tvg-name="{title}" '
                f'tvg-logo="" '
                f'group-title="{group}",'
                f"{title}"
            )
            f.write(extinf + "\n")

            kodi_lines, final_url = build_kodiprop_lines(sec, drm_widevine, drm_clearkey)
            for line in kodi_lines:
                f.write(line + "\n")

            if ua:
                f.write(f"#EXTVLCOPT:http-user-agent={ua}\n")

            f.write(final_url + "\n\n")
            stats["written"] += 1

    print(f"\n  Statistiche:", file=sys.stderr)
    print(f"    Totale sezioni video:    {stats['total']}", file=sys.stderr)
    print(f"    Scritti in playlist:     {stats['written']}", file=sys.stderr)
    print(f"      di cui Widevine:       {stats['widevine']}", file=sys.stderr)
    print(f"      di cui ClearKey:       {stats['clearkey']}", file=sys.stderr)
    print(f"      di cui senza DRM:      {stats['no_drm']}", file=sys.stderr)
    print(f"    Saltati (non MPD):       {stats['skipped_no_mpd']}", file=sys.stderr)
    print(f"\n  Playlist salvata in: {output_path}", file=sys.stderr)

    return stats


def main():
    cfg = load_config()

    parser = argparse.ArgumentParser(
        description="Genera playlist M3U",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--output", "-o",
        default=cfg.get("output", "playlist.m3u"),
        help="Output file")
    parser.add_argument("--group-mode", choices=["auto", "none"], default="auto")
    parser.add_argument("--lang", default="it")
    parser.add_argument("--country", default="IT")
    parser.add_argument("--idusu", default="0")
    parser.add_argument("--cod-g", default="0")
    parser.add_argument("--save-config")
    parser.add_argument("--offline")
    args = parser.parse_args()

    if args.offline:
        print(f"[1/4] Carico config da file: {args.offline}", file=sys.stderr)
        with open(args.offline, "r", encoding="utf-8") as f:
            config_text = f.read()
    else:
        config_text = download_config(cfg, idl=args.lang, pa=args.country,
                                      idusu=args.idusu, cod_g=args.cod_g)

    if args.save_config:
        with open(args.save_config, "w", encoding="utf-8") as f:
            f.write(config_text)
        print(f"      Config salvato in: {args.save_config}", file=sys.stderr)

    cad_rep_orig = cfg["cad_rep_orig"]
    cad_rep = extract_cad_rep(config_text, cad_rep_orig)
    t_video = cfg.get("t_video", 6)
    video_sections = parse_config(config_text, cad_rep, cad_rep_orig, t_video)

    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    generate_m3u(video_sections, args.output, cfg, group_mode=args.group_mode)

    print(f"\nDone. Output: {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
