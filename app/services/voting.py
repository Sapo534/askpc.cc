from sqlalchemy.orm import Session

from ..models import User


def vote_value(direction: str) -> int:
    return 1 if direction == "up" else -1


def apply_vote(db: Session, *, vote_model, fk_name: str, target, user_id: int, value: int) -> None:
    """Toggle / flip / create a vote and keep target.score + author karma in sync.

    vote_model: ThreadVote or ReplyVote
    fk_name:    'thread_id' or 'reply_id'
    target:     the ForumThread / ForumReply being voted on
    """
    author = db.query(User).filter(User.id == target.author_id).first()
    existing = (
        db.query(vote_model)
        .filter(vote_model.user_id == user_id, getattr(vote_model, fk_name) == target.id)
        .first()
    )

    if existing and existing.value == value:  # same vote again -> undo
        target.score -= value
        if author:
            author.karma -= value
        db.delete(existing)
    elif existing:  # flip
        target.score += value * 2
        if author:
            author.karma += value * 2
        existing.value = value
    else:  # new
        db.add(vote_model(**{"user_id": user_id, fk_name: target.id, "value": value}))
        target.score += value
        if author:
            author.karma += value
    db.commit()
