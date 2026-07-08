#!/bin/sh
set -eu

script_dir="$(
  CDPATH= cd -P -- "$(dirname "$0")" &&
    pwd -P
)"
runtime_root="$(dirname "$script_dir")"
node_bin="${npm_node_execpath:-}"
tsx_cli="$runtime_root/node_modules/tsx/dist/cli.mjs"
entrypoint="$script_dir/promote-quality-db.mjs"

[ -n "$node_bin" ] && [ -x "$node_bin" ] || {
  echo "promotion lifecycle requires npm_node_execpath" >&2
  exit 1
}
[ -f "$tsx_cli" ] && [ ! -L "$tsx_cli" ] || {
  echo "promotion lifecycle tsx CLI is missing or unsafe: $tsx_cli" >&2
  exit 1
}
[ -f "$entrypoint" ] && [ ! -L "$entrypoint" ] || {
  echo "promotion lifecycle entrypoint is missing or unsafe: $entrypoint" >&2
  exit 1
}

if [ "${RADAR_PROMOTION_LOCK_STDIN:-0}" = "1" ]; then
  exec 9<&0
  unset RADAR_PROMOTION_LOCK_STDIN
fi

cd "$runtime_root"
exec "$node_bin" "$tsx_cli" "$entrypoint" "$@"
