#!/bin/sh
# Mirror the transparency log to a public git repo so Signet cannot quietly rewrite it.
# Run from cron on the host (needs a deploy key with push access to the public log repo).
#   PUBLIC_LOG_REPO=git@github.com:prithsk/signet-transparency.git \
#   SIGNET_URL=https://sign.example.com ./scripts/publish_transparency.sh
set -eu
: "${PUBLIC_LOG_REPO:?}" "${SIGNET_URL:?}"
work=$(mktemp -d)
git clone -q "$PUBLIC_LOG_REPO" "$work"
curl -fsS "$SIGNET_URL/transparency.log" > "$work/transparency.log"
curl -fsS "$SIGNET_URL/.well-known/signet-key" > "$work/signet-key.json"
cd "$work"
# refuse to publish if the new log is not a strict extension of the old one
if git show HEAD:transparency.log >/tmp/old.log 2>/dev/null; then
  head -c "$(wc -c </tmp/old.log)" transparency.log | cmp -s - /tmp/old.log || { echo "LOG REWRITTEN, REFUSING TO PUBLISH" >&2; exit 1; }
fi
git add transparency.log signet-key.json
git -c user.name=signet-bot -c user.email=bot@signet commit -qm "log $(date -u +%FT%TZ) $(wc -l <transparency.log) entries" || exit 0
git push -q
