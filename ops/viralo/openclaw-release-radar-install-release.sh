#!/usr/bin/env bash
set -euo pipefail

tarball="${1:?tarball path required}"
release_name="${2:?release name required}"

base=/opt/openclaw-release-radar
shared="$base/shared"
releases="$base/releases"
current="$base/current"
release_dir="$releases/$release_name"

case "$release_dir" in
  "$releases"/*) ;;
  *) echo "invalid release path" >&2; exit 1 ;;
esac

[ -f "$tarball" ] || { echo "tarball not found: $tarball" >&2; exit 1; }
[ -f "$shared/.env" ] || { echo "missing shared env: $shared/.env" >&2; exit 1; }

rm -rf "$release_dir"
install -d -m 755 -o www-data -g www-data "$release_dir"
tar -xzf "$tarball" -C "$release_dir"
chown -R www-data:www-data "$release_dir"
ln -sfn "$shared/.env" "$release_dir/.env"
chown -h www-data:www-data "$release_dir/.env" || true

install -d -m 755 -o www-data -g www-data "$shared/.npm-cache"
runuser -u www-data -- env \
  HOME="$shared" \
  NPM_CONFIG_CACHE="$shared/.npm-cache" \
  PATH="/opt/node-v24/bin:$PATH" \
  npm ci --omit=dev --prefix "$release_dir"

rm -f "$current"
ln -s "$release_dir" "$current"
chown -h www-data:www-data "$current"

systemctl restart openclaw-release-radar.service

for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8787/api/health >/dev/null 2>&1; then
    rm -f "$tarball"
    exit 0
  fi
  sleep 1
done

systemctl --no-pager --full status openclaw-release-radar.service || true
journalctl -u openclaw-release-radar.service -n 100 --no-pager || true
exit 1
