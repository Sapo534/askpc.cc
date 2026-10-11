#!/usr/bin/env bash
# Nightly backup: Postgres dump + uploads + .env -> restic repos, email alert on failure.
set -euo pipefail
umask 077
export PATH=/usr/local/bin:/usr/bin:/bin

PROJECT="$(cd "$(dirname "$0")/.." && pwd)"
STATE="$HOME/.cache/askpc-backup"
STAGING="$STATE/staging"
mkdir -p "$STAGING"

# shellcheck disable=SC1091
source "$HOME/.config/askpc-backup/config"
export RESTIC_PASSWORD_FILE
: "${REPOS:?REPOS not set}"

exec 9>"$STATE/lock"
flock -n 9 || { echo "another backup is running"; exit 0; }

notify() {
  local subject="$1" body="${2//$'\n'/ }" line key
  body="${body//\"/\'}"
  if [ -z "${ALERT_EMAIL:-}" ] || [ "$ALERT_EMAIL" = "you@example.com" ]; then
    echo "ALERT (ALERT_EMAIL not set): $subject - $body" >&2
    return 0
  fi
  line="$(grep -E '^RESEND_API_KEY=' "$PROJECT/.env" | head -1 || true)"
  key="${line#RESEND_API_KEY=}"; key="${key%[\"\']}"; key="${key#[\"\']}"
  curl -fsS -m 20 -A "askpc-backup/1.0" https://api.resend.com/emails \
    -H "Authorization: Bearer $key" -H "Content-Type: application/json" \
    -d "{\"from\":\"askpc.cc <noreply@askpc.cc>\",\"to\":[\"$ALERT_EMAIL\"],\"subject\":\"$subject\",\"text\":\"$body\"}" \
    >/dev/null || echo "could not send alert email" >&2
}

CONDUIT_STOPPED=0
cleanup() {
  if [ "$CONDUIT_STOPPED" = 1 ]; then
    docker compose -f "$PROJECT/docker-compose.yml" start conduit >/dev/null 2>&1 || true
  fi
  rm -rf "$STAGING"/*
}
trap cleanup EXIT

trap 'notify "askpc backup FAILED" "Backup failed on $(hostname) near line $LINENO. See ~/backup.log"' ERR

cd "$PROJECT"
rm -rf "$STAGING"/*

echo "[$(date -Is)] dumping database"
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom' > "$STAGING/db.dump"
[ -s "$STAGING/db.dump" ]
docker compose exec -T db pg_restore --list < "$STAGING/db.dump" > /dev/null

echo "[$(date -Is)] backing up Matrix (conduit stops for a few seconds)"
docker compose stop conduit
CONDUIT_STOPPED=1
docker run --rm -v askpccc_conduit_data:/data:ro -v "$STAGING":/out alpine \
  tar cf /out/conduit.tar -C /data .
docker compose start conduit
CONDUIT_STOPPED=0
tar tf "$STAGING/conduit.tar" > /dev/null

PATHS=("$STAGING" "$PROJECT/.env")
for d in app/static/uploads app/static/avatars; do
  if [ -d "$PROJECT/$d" ]; then PATHS+=("$PROJECT/$d"); fi
done

for repo in $REPOS; do
  export RESTIC_REPOSITORY="$repo"
  echo "[$(date -Is)] backing up to $repo"
  restic cat config >/dev/null 2>&1 || restic init
  restic backup --tag askpc --exclude-caches "${PATHS[@]}"
  restic forget --tag askpc --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune
  if [ "$(date +%u)" = 7 ]; then
    restic check --read-data-subset=10%
  fi
done

# Sunday "all fine" mail doubles as a dead man's switch: no mail = something is wrong.
if [ "$(date +%u)" = 7 ]; then
  notify "askpc weekly backup OK" "Repos: $REPOS. Database dump: $(du -h "$STAGING/db.dump" | cut -f1)."
fi
echo "[$(date -Is)] done"
