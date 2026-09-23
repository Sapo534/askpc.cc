import re
from typing import Optional

from sqlalchemy.orm import Session

from ..models import Tag


def clean_tag_name(raw: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "", str(raw).strip().lstrip("#").lower())


def get_or_create_tag(db: Session, raw: str) -> Optional[Tag]:
    name = clean_tag_name(raw)
    if not name:
        return None
    tag = db.query(Tag).filter(Tag.name == name).first()
    if not tag:
        tag = Tag(name=name)
        db.add(tag)
        db.flush()
    return tag
