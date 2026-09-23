from . import (
    admin,
    auth,
    community,
    forum,
    github_auth,
    kb,
    pages,
    tags,
    users,
    webhooks,
    wiki,
)

all_routers = [
    pages.router,
    kb.router,
    forum.router,
    tags.router,
    community.router,
    users.router,
    auth.router,
    github_auth.router,
    webhooks.router,
    admin.router,
    wiki.router,
]
