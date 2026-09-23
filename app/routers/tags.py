from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..core import templates
from ..database import get_db
from ..deps import get_current_user, redirect
from ..models import Article, ArticleTag, ForumThread, Tag, ThreadTag

router = APIRouter()


@router.get("/tag/{tag_name}")
def tag_detail_page(tag_name: str, request: Request, db: Session = Depends(get_db)):
    tag = db.query(Tag).filter(Tag.name == tag_name.lower().strip()).first()
    if not tag:
        return redirect("/")
    articles = db.query(Article).join(ArticleTag).filter(ArticleTag.tag_id == tag.id).all()
    threads = db.query(ForumThread).join(ThreadTag).filter(ThreadTag.tag_id == tag.id).all()
    return templates.TemplateResponse(
        request=request,
        name="tag_detail.html",
        context={
            "user": get_current_user(request, db),
            "tag": tag,
            "articles": articles,
            "threads": threads,
        },
    )
