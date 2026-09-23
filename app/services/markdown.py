"""Markdown rendering, sanitising, slugs and Obsidian [[wikilinks]]."""
import re

import markdown
import nh3

ALLOWED_HTML_TAGS = {
    "p", "br", "strong", "em", "code", "pre", "blockquote",
    "ul", "ol", "li", "a", "img",
    "h1", "h2", "h3", "h4",
    "table", "thead", "tbody", "tr", "th", "td",
    "del", "hr", "details", "summary",
}
ALLOWED_HTML_ATTRS = {"a": {"href", "title"}, "img": {"src", "alt"}}

_WIKILINK_RE = re.compile(r"\[\[([^\|\]]+)(?:\|([^\]]+))?\]\]")


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def convert_obsidian_wikilinks(text: str, default_prefix: str = "kb") -> str:
    """[[Target|Shown]] -> [Shown](/prefix/target)"""

    def replace(match: re.Match) -> str:
        target = match.group(1).strip()
        display = match.group(2).strip() if match.group(2) else target
        return f"[{display}](/{default_prefix}/{slugify(target)})"

    return _WIKILINK_RE.sub(replace, text)


def render_markdown(text: str) -> str:
    if not text:
        return ""
    raw_html = markdown.markdown(
        text,
        extensions=[
            "markdown.extensions.extra",
            "markdown.extensions.fenced_code",
            "markdown.extensions.tables",
            "markdown.extensions.nl2br",
            "markdown.extensions.sane_lists",
            "pymdownx.tilde",
            "pymdownx.tasklist",
        ],
    )
    return nh3.clean(raw_html, tags=ALLOWED_HTML_TAGS, attributes=ALLOWED_HTML_ATTRS)
