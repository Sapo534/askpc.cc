"""Wiki / glossary pages + JSON API for hover previews."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..core import templates
from ..database import get_db
from ..deps import get_current_user, redirect
from ..models import WikiTerm
from ..schemas import WikiSummary

router = APIRouter()


@router.get("/wiki")
@router.get("/wiki.html")
def wiki_index(request: Request, q: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(WikiTerm)
    if q:
        pattern = f"%{q.strip()}%"
        query = query.filter(
            (WikiTerm.term.ilike(pattern))
            | (WikiTerm.summary.ilike(pattern))
            | (WikiTerm.category.ilike(pattern))
        )

    # Group alphabetically A-Z ('#' for anything non-alphabetic)
    terms_by_letter: dict = {}
    for t in query.order_by(WikiTerm.term.asc()).all():
        letter = t.term[0].upper() if t.term else "#"
        if not letter.isalpha():
            letter = "#"
        terms_by_letter.setdefault(letter, []).append(t)

    return templates.TemplateResponse(
        request=request,
        name="wiki.html",
        context={
            "user": get_current_user(request, db),
            "terms_by_letter": dict(sorted(terms_by_letter.items())),
            "q": q,
        },
    )


@router.get("/wiki/{slug}")
def wiki_detail(slug: str, request: Request, db: Session = Depends(get_db)):
    term = db.query(WikiTerm).filter(WikiTerm.slug == slug.lower().strip()).first()
    if not term:
        return redirect("/wiki")
    return templates.TemplateResponse(
        request=request,
        name="wiki_detail.html",
        context={"user": get_current_user(request, db), "term": term},
    )


@router.get("/api/wiki/{slug}/summary", response_model=WikiSummary)
def wiki_summary_api(slug: str, db: Session = Depends(get_db)):
    term = db.query(WikiTerm).filter(WikiTerm.slug == slug.lower().strip()).first()
    if not term:
        raise HTTPException(status_code=404, detail="Term not found")
    return term
