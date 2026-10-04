#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose exec -T db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"' <<'SQL'
delete from users
where not is_email_verified
  and github_username is null
  and created_at < (now() at time zone 'utc') - interval '48 hours';
SQL
