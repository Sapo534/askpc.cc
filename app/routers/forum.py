"""Forum threads, replies and voting."""
import re
import time
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from sqlalchemy.orm import Session

from ..core import limiter, templates
from ..database import get_db
from ..deps import get_current_user, redirect
from ..models import (
    ForumReply,
    ForumThread,
    ReplyVote,
    Tag,
    ThreadTag,
    ThreadVote,
    User,
)
from ..services.files import save_secure_file
from ..services.markdown import slugify
from ..services.tags import get_or_create_tag
from ..services.voting import apply_vote, vote_value

router = APIRouter()


def _thread_page(request: Request, user, thread: ForumThread, db: Session, **extra):
    replies = (
        db.query(ForumReply)
        .filter(ForumReply.thread_id == thread.id)
        .order_by(ForumReply.created_at.asc())
        .all()
    )
    return templates.TemplateResponse(
        request=request,
        name="thread_detail.html",
        context={"user": user, "thread": thread, "replies": replies, **extra},
    )


def _new_thread_page(request: Request, user, **extra):
    return templates.TemplateResponse(
        request=request, name="create_thread.html", context={"user": user, **extra}
    )


# --- listing ---


@router.get("/forum")
@router.get("/forum.html")
def forum_page(
    request: Request,
    q: Optional[str] = None,
    tag: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(ForumThread).distinct()

    if q:
        pattern = f"%{q.strip()}%"
        query = (
            query.outerjoin(ThreadTag, ThreadTag.thread_id == ForumThread.id)
            .outerjoin(Tag, Tag.id == ThreadTag.tag_id)
            .outerjoin(User, ForumThread.author_id == User.id)
            .filter(
                (ForumThread.title.ilike(pattern))
                | (ForumThread.content.ilike(pattern))
                | (Tag.name.ilike(pattern))
                | (User.username.ilike(pattern))
            )
        )

    if tag:
        query = query.filter(ForumThread.tags.any(Tag.name == tag.lower().strip()))

    threads = query.order_by(ForumThread.created_at.desc()).all()
    return templates.TemplateResponse(
        request=request,
        name="forum.html",
        context={"user": get_current_user(request, db), "threads": threads, "q": q},
    )


# --- create thread ---


@router.get("/forum/new")
def new_thread_page(request: Request, db: Session = Depends(get_db)):
    current_user = get_current_user(request, db)
    if not current_user:
        return redirect("/login")
    return _new_thread_page(request, current_user)


@router.post("/forum/new")
@limiter.limit("10/hour")
def create_thread(
    request: Request,
    title: str = Form(...),
    tags: str = Form(...),
    content: str = Form(...),
    attachment: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
):
    current_user = get_current_user(request, db)
    if not current_user:
        return redirect("/login")
    if not current_user.is_email_verified:
        return _new_thread_page(
            request,
            current_user,
            error="Email verification required before posting. Please check your inbox or settings.",
        )

    try:
        attach_url, attach_name = save_secure_file(attachment, "uploads")
    except ValueError as err:
        return _new_thread_page(request, current_user, error=str(err))

    new_thread = ForumThread(
        title=title,
        slug=f"{slugify(title)}-{int(time.time())}",
        content=content,
        attachment_url=attach_url,
        attachment_name=attach_name,
        author_id=current_user.id,
    )
    db.add(new_thread)
    db.commit()

    for raw in tags.split():
        tag = get_or_create_tag(db, raw)
        if tag and tag not in new_thread.tags:
            new_thread.tags.append(tag)
    db.commit()
    return redirect("/forum")


# --- thread page / replies ---


@router.get("/forum/thread/{slug}")
def thread_detail(slug: str, request: Request, db: Session = Depends(get_db)):
    thread = db.query(ForumThread).filter(ForumThread.slug == slug).first()
    if not thread:
        return redirect("/forum")
    return _thread_page(request, get_current_user(request, db), thread, db)


@router.post("/forum/thread/{slug}/reply")
@limiter.limit("20/minute")
def add_reply(
    slug: str,
    request: Request,
    content: str = Form(...),
    attachment: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
):
    current_user = get_current_user(request, db)
    if not current_user:
        return redirect("/login")

    thread = db.query(ForumThread).filter(ForumThread.slug == slug).first()
    if not thread:
        return redirect("/forum")

    if not current_user.is_email_verified:
        return _thread_page(
            request, current_user, thread, db,
            error="Email verification required before replying.",
        )

    try:
        attach_url, attach_name = save_secure_file(attachment, "uploads")
    except ValueError as err:
        return _thread_page(request, current_user, thread, db, error=str(err))

    db.add(
        ForumReply(
            thread_id=thread.id,
            author_id=current_user.id,
            content=content,
            attachment_url=attach_url,
            attachment_name=attach_name,
        )
    )
    db.commit()
    return redirect(f"/forum/thread/{slug}")


# --- voting ---


@router.post("/forum/thread/{slug}/vote")
@limiter.limit("30/minute")
def vote_thread(
    slug: str,
    request: Request,
    direction: str = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_current_user(request, db)
    if not current_user:
        return redirect("/login")
    if not current_user.is_email_verified:
        return redirect("/forum")

    thread = db.query(ForumThread).filter(ForumThread.slug == slug).first()
    if not thread:
        return redirect("/forum")

    apply_vote(
        db, vote_model=ThreadVote, fk_name="thread_id", target=thread,
        user_id=current_user.id, value=vote_value(direction),
    )
    return redirect(f"/forum/thread/{slug}")


@router.post("/forum/reply/{reply_id}/vote")
@limiter.limit("30/minute")
def vote_reply(
    reply_id: int,
    request: Request,
    direction: str = Form(...),
    db: Session = Depends(get_db),
):
    current_user = get_current_user(request, db)
    if not current_user:
        return redirect("/login")

    reply = db.query(ForumReply).filter(ForumReply.id == reply_id).first()
    if not reply:
        return redirect("/forum")

    thread_url = f"/forum/thread/{reply.thread.slug}"
    if not current_user.is_email_verified:
        return redirect(thread_url)

    apply_vote(
        db, vote_model=ReplyVote, fk_name="reply_id", target=reply,
        user_id=current_user.id, value=vote_value(direction),
    )
    return redirect(thread_url)
