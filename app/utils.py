import json
import re
from email.header import decode_header, make_header
from functools import lru_cache
from pathlib import Path

_LICENSES_FILE = Path(__file__).parent / "data" / "licenses.json"


def _clean_author(raw: str) -> str:
    # fastapi отдаёт автора в MIME-кодировке (=?utf-8?q?...), декодируем
    text = str(make_header(decode_header(raw or "")))
    text = re.sub(r"\s*<[^>]*>", "", text)  # выкидываем email'ы, публиковать их незачем
    text = text.replace('"', "").strip()
    if text.upper() == "UNKNOWN":
        return ""
    names = [n.strip() for n in text.split(",") if n.strip()]
    if len(names) > 3:
        return ", ".join(names[:3]) + " et al."
    return ", ".join(names)


@lru_cache
def load_licenses() -> list[dict]:
    try:
        raw = json.loads(_LICENSES_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return []
    packages = []
    for p in raw:
        url = p.get("URL", "")
        packages.append({
            "name": p["Name"],
            "version": p["Version"],
            "license": p["License"],
            "author": _clean_author(p.get("Author", "")),
            "url": url if url.startswith("https://") else "",
        })
    return sorted(packages, key=lambda x: x["name"].lower())

def make_excerpt(md: str, limit: int = 160) -> str:
    text = re.sub(r"```.*?```", "", md or "", flags=re.S)
    text = re.sub(r"\A\s*#\s+[^\n]*\n?", "", text)
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"^#{1,6}\s*", "", text, flags=re.M)
    text = re.sub(r"[*_>~]+", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit].rstrip() + ("…" if len(text) > limit else "")
