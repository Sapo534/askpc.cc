"""GitHub content sync: wiki/*.md -> WikiTerm, docs/*.md -> Article."""
import hashlib
import hmac
import os
from datetime import datetime
from pathlib import Path
from typing import List

import frontmatter
import requests
from sqlalchemy.orm import Session

from ..config import SYNC_DIRECTORIES
from ..models import Article, ArticleTag, User, WikiTerm
from .markdown import convert_obsidian_wikilinks, slugify
from .tags import get_or_create_tag


# --- transport ---------------------------------------------------------------

def _headers() -> dict:
    headers = {"User-Agent": "FastAPI-Docs-Webhook"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def verify_github_signature(raw_body: bytes, signature_header: str, secret: str) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature_header)


def is_syncable_path(path: str) -> bool:
    """Only .md files inside wiki/ or docs/ are ever synced."""
    return path.endswith(".md") and path.startswith(SYNC_DIRECTORIES)


def fetch_raw_markdown(repo: str, branch: str, path: str) -> str:
    url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
    resp = requests.get(url, headers=_headers(), timeout=15)
    resp.raise_for_status()
    resp.encoding = "utf-8"
    return resp.text


def list_repo_markdown_paths(repo: str, branch: str) -> List[str]:
    url = f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1"
    resp = requests.get(url, headers=_headers(), timeout=15)
    resp.raise_for_status()
    return [
        e["path"]
        for e in resp.json().get("tree", [])
        if e.get("type") == "blob" and is_syncable_path(e.get("path", ""))
    ]


# --- articles (docs/) --------------------------------------------------------

def sync_article(md_content: str, file_path: str, db: Session) -> None:
    post = frontmatter.loads(md_content)
    raw_title = post.get("title", Path(file_path).stem)
    slug = slugify(raw_title)

    author = db.query(User).filter(User.username == "admin").first()
    author_id = author.id if author else 1

    article = db.query(Article).filter(Article.file_path == file_path).first()
    if not article:
        article = db.query(Article).filter(Article.slug == slug).first()
    if not article:
        article = Article(title=raw_title, slug=slug, file_path=file_path, author_id=author_id)
        db.add(article)

    article.title = raw_title
    article.slug = slug
    article.file_path = file_path
    article.category = post.get("category", "General")
    article.difficulty = post.get("difficulty", "Beginner")
    article.license = post.get("license", "CC-BY-SA-4.0")
    article.content_markdown = convert_obsidian_wikilinks(post.content, "kb")
    article.updated_at = datetime.utcnow()

    raw_tags = post.get("tags", [])
    if isinstance(raw_tags, str):
        raw_tags = [t.strip() for t in raw_tags.split(",")]

    article.tags = []
    for raw in raw_tags:
        tag = get_or_create_tag(db, raw)
        if tag and tag not in article.tags:
            article.tags.append(tag)

    db.commit()


def delete_article(file_path: str, db: Session) -> None:
    article = db.query(Article).filter(Article.file_path == file_path).first()
    if article:
        db.query(ArticleTag).filter(ArticleTag.article_id == article.id).delete()
        db.delete(article)
        db.commit()


# --- wiki terms (wiki/) ------------------------------------------------------

def sync_wiki_term(md_content: str, file_path: str, db: Session) -> None:
    post = frontmatter.loads(md_content)
    stem = Path(file_path).stem
    term_title = post.get("term") or post.get("title") or stem.replace("-", " ").title()
    slug = slugify(stem)

    summary = post.get("summary")
    if not summary:
        lines = [l.strip() for l in post.content.split("\n") if l.strip() and not l.startswith("#")]
        summary = lines[0][:300] if lines else f"Technical definition for {term_title}"

    term = db.query(WikiTerm).filter(WikiTerm.slug == slug).first()
    if not term:
        term = WikiTerm(term=term_title, slug=slug, summary=summary)
        db.add(term)

    term.term = term_title
    term.slug = slug
    term.summary = summary
    term.category = post.get("category", "General")
    term.content_markdown = convert_obsidian_wikilinks(post.content, "wiki")
    term.updated_at = datetime.utcnow()

    db.commit()
    print(f"✅ Webhook Synced Wiki Term: {term_title} (slug: {slug})")


def delete_wiki_term(file_path: str, db: Session) -> None:
    slug = slugify(Path(file_path).stem)
    term = db.query(WikiTerm).filter(WikiTerm.slug == slug).first()
    if term:
        db.delete(term)
        db.commit()
        print(f"🗑️ Cleaned up deleted wiki term: {slug}")


# --- dispatch by directory ---------------------------------------------------

def sync_markdown_file(file_path: str, md_text: str, db: Session) -> None:
    if file_path.startswith("wiki/"):
        sync_wiki_term(md_text, file_path, db)
    else:
        sync_article(md_text, file_path, db)


def delete_markdown_file(file_path: str, db: Session) -> None:
    if file_path.startswith("wiki/"):
        delete_wiki_term(file_path, db)
    else:
        delete_article(file_path, db)
