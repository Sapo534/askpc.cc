"""Knowledge base (articles synced from docs/)."""
from typing import Optional

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..core import templates
from ..database import get_db
from ..deps import get_current_user, redirect
from ..models import Article, ArticleTag, Tag

router = APIRouter()


@router.get("/kb")
@router.get("/kb.html")
def kb_page(
    request: Request,
    q: Optional[str] = None,
    tag: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Article).distinct()

    if q:
        pattern = f"%{q.strip()}%"
        query = (
            query.outerjoin(ArticleTag, ArticleTag.article_id == Article.id)
            .outerjoin(Tag, Tag.id == ArticleTag.tag_id)
            .filter(
                (Article.title.ilike(pattern))
                | (Article.content_markdown.ilike(pattern))
                | (Article.category.ilike(pattern))
                | (Tag.name.ilike(pattern))
            )
        )

    if tag:
        query = query.filter(Article.tags.any(Tag.name == tag.lower().strip()))

    return templates.TemplateResponse(
        request=request,
        name="kb.html",
        context={"user": get_current_user(request, db), "articles": query.all(), "q": q},
    )


@router.get("/kb/{slug}")
def article_detail(slug: str, request: Request, db: Session = Depends(get_db)):
    article = db.query(Article).filter(Article.slug == slug).first()
    if not article:
        return redirect("/kb")
    return templates.TemplateResponse(
        request=request,
        name="article_detail.html",
        context={"user": get_current_user(request, db), "article": article},
    )
