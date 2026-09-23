"""App wiring only: app object, middleware, static files, routers, startup."""
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.sessions import SessionMiddleware

from .auth import SECRET_KEY
from .config import CORS_ORIGINS
from .core import limiter
from .database import engine
from .middleware import security_headers_and_csrf
from .models import Base
from .routers import all_routers


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    os.makedirs("app/static/avatars", exist_ok=True)
    os.makedirs("app/static/uploads", exist_ok=True)
    yield


app = FastAPI(
    title="askpc.cc",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Order matters: the last one added is the outermost.
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
app.middleware("http")(security_headers_and_csrf)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

for router in all_routers:
    app.include_router(router)
