"""Pydantic models for JSON endpoints."""
from typing import List, Optional

from pydantic import BaseModel, ConfigDict


class WikiSummary(BaseModel):
    """Payload for hover/popover previews (see static/wiki.js)."""

    model_config = ConfigDict(from_attributes=True)

    term: str
    slug: str
    summary: Optional[str] = None
    category: Optional[str] = None


class SyncResult(BaseModel):
    synced: List[str]
    failed: List[str]
    total: int


class WebhookResult(BaseModel):
    status: str
    synced: bool
