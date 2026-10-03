import re

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
