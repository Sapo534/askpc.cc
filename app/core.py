"""Shared singletons: rate limiter, Jinja templates, OAuth client."""
import os

from authlib.integrations.starlette_client import OAuth
from fastapi.templating import Jinja2Templates
from slowapi import Limiter
from slowapi.util import get_remote_address

from .services.markdown import render_markdown

limiter = Limiter(key_func=get_remote_address)

templates = Jinja2Templates(directory="app/templates")
from app.utils import make_excerpt
templates.env.filters["excerpt"] = make_excerpt
templates.env.filters["markdown"] = render_markdown

from pathlib import Path

_STATIC = Path(__file__).parent / "static"

def static_v(name: str) -> int:
    return int((_STATIC / name).stat().st_mtime)

from app.antibot import new_challenge
templates.env.globals["new_challenge"] = new_challenge

templates.env.globals["static_v"] = static_v

oauth = OAuth()
oauth.register(
    name="github",
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "user:email"},
)
