"""Home, static info pages, favicon."""
import base64

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.utils import load_licenses

from ..core import templates
from ..database import get_db
from ..deps import get_current_user
from ..models import Article, ForumThread

router = APIRouter()

# Inline 16x16 PNG favicon (no external asset required)
_FAVICON = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAA"
    "AARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAYdEVYdFNvZnR3"
    "YXJlAHBhaW50Lm5ldCA0LjAuMhYSP0YAAAAcSURBVDhPYxgFWAZQGxgYGP4zMDAw"
    "/KfSGA0YAGqYAgZ8bL1PAAAAAElFTkSuQmCC"
)


@router.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(content=_FAVICON, media_type="image/png")


@router.get("/privacy")
@router.get("/privacy.html")
def privacy_page(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(
        request=request, name="privacy.html", context={"user": get_current_user(request, db)}
    )

@router.get("/rules")
@router.get("/rules.html")
def rules_page(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(
        request=request, name="rules.html", context={"user": get_current_user(request, db)}
    )

@router.get("/licenses")
@router.get("/licenses.html")
def licenses_page(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(
        request=request,
        name="licenses.html",
        context={"user": get_current_user(request, db), "packages": load_licenses()},
    )

@router.get("/contribute")
@router.get("/contribute.html")
def privacy_page(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(
        request=request, name="contribute.html", context={"user": get_current_user(request, db)}
    )

@router.get("/")
@router.get("/index.html")
def home_page(request: Request, db: Session = Depends(get_db)):
    latest_articles = db.query(Article).order_by(Article.updated_at.desc()).limit(3).all()
    latest_threads = db.query(ForumThread).order_by(ForumThread.created_at.desc()).limit(5).all()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "user": get_current_user(request, db),
            "articles": latest_articles,
            "threads": latest_threads,
        },
    )
