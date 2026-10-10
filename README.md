# askpc.cc

A technical knowledge base, wiki and forum about computers and software.
Beginners and pros, Windows, Linux and FreeBSD, iPhone and GrapheneOS: everyone is welcome, as long as the topic is tech.

**Live site:** <https://askpc.cc>

## Features

- **Knowledge Base:** community-written articles in Markdown, organised by category, searchable by tags and titles.
- **Wiki:** a glossary of terms with A-Z navigation. Terms linked anywhere on the site show a hover/tap popover, so you can read a definition without leaving the page.
- **Forum:** threads, replies, voting and tags, with an anti-toxicity moderation policy (warnings first, escalating mutes).
- **Accounts:** email + password sign-up with email verification, "Remember me", password reset, logout-everywhere.
- **Two languages:** English and Russian.
- **Light and dark theme:** strictly monochrome, follows the system preference and can be switched manually.
- **Mobile friendly:** responsive layout with a hamburger menu.
- **Ad-free:** funded by optional sponsorship (colored nickname).

## Tech stack

| Part | Technology |
| --- | --- |
| Backend | Python, FastAPI |
| Database | PostgreSQL (SQLAlchemy) |
| Templates | Jinja2, plain HTML/CSS |
| Frontend JS | Vanilla JS, no frameworks (CSP: `script-src 'self'`) |
| Auth | bcrypt password hashes, signed session cookies (`itsdangerous`) |
| Markdown | Server-side rendering, sanitised with `nh3` |
| Email | [Resend](https://resend.com) |
| Chat | Matrix (Conduit) |
| Deployment | Docker Compose, Caddy, Cloudflare |

## Project layout

```text
app/
├── routers/      # HTTP routes (pages, auth, forum, ...)
├── services/     # email, tokens, sponsors, ...
├── templates/    # Jinja2 templates
├── static/       # CSS and JS
├── antibot.py    # sign-up protection (honeypot, proof-of-work, email budget)
├── auth.py       # password hashing, session tokens
├── config.py     # settings read from the environment
├── deps.py       # current user, cookies, shared request helpers
├── database.py   # engine and session
└── models.py     # SQLAlchemy models
```

Documentation articles live in a **separate repository**: [askpc-kb](https://github.com/Sapo534/askpc-kb).
A GitHub webhook syncs them to the site on every push.

## Running locally

Requirements: Docker with the Compose plugin.

```bash
git clone https://github.com/Sapo534/askpc.cc
cd askpc.cc
cp .env.example .env     # then edit .env, see "Configuration" below
docker compose up -d --build
```

Useful commands:

```bash
docker compose logs -f web      # application logs
docker compose up -d --build web  # rebuild after code changes
docker compose down             # stop (add -v to also delete volumes and data!)
```

Check `docker-compose.yml` for the exposed ports in your setup.

## Configuration

All settings come from environment variables (`.env`). Never commit `.env`.

| Variable | Description |
| --- | --- |
| `SECRET_KEY` | Key used to sign session cookies. Use a long random value, for example `python -c "import secrets; print(secrets.token_urlsafe(64))"`. If unset, a key is generated into `.secret_key` on first start. |
| `REGISTRATION_OPEN` | `1` to allow new sign-ups, `0` (default) to close registration. |

Database, email (Resend), webhook and other settings are listed in `.env.example`.

## Security

Passwords are stored as bcrypt hashes. Sessions are signed cookies tied to a per-user `session_version`, so changing the password or using logout-everywhere invalidates old sessions. Email and reset tokens are stored hashed. Sign-up is protected by a honeypot, a small proof-of-work challenge and a daily email budget, and sensitive endpoints are rate limited.

**Found a vulnerability?** Please do not open a public issue. Use GitHub's private vulnerability reporting (the **Security** tab of this repository) instead.

## Contributing

Contributions are welcome: fixing articles, reporting bugs, suggesting features or sending code.
See the [Participate in Development](https://askpc.cc/contribute) page for the details.

Short version:

1. Open an issue before starting a large change.
2. Fork the repository and create a branch from `main`.
3. Keep pull requests focused: one topic per PR.
4. Describe what changed and why.

By contributing you agree that your contribution is licensed under AGPL-3.0.

## Community

Off-topic chat and questions happen in our Matrix Space, linked on the [Community](https://askpc.cc/community) page.

## License

Copyright (C) 2026 askpc.cc contributors.

This project is free software, licensed under the **GNU Affero General Public License v3.0**. See [LICENSE](LICENSE) for the full text. Third-party dependency licenses are listed at <https://askpc.cc/licenses>.
