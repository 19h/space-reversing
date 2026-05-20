#!/usr/bin/env bash
# Mint a game JWT and subscribe to push topics on the game's services endpoint.
#
# Usage:
#   SESSION_TOKEN=... DEVICE_TOKEN=... ./listen.sh [--topic t1,t2,...] [refresh.js flags]
#
# Defaults to subscribing to address:account_id:<id> derived from the JWT's claim.
# Any extra args are forwarded to refresh.js (e.g. --budget 60, --keep, -v, --out f.json).

set -euo pipefail

: "${SESSION_TOKEN:?SESSION_TOKEN env var required}"
: "${DEVICE_TOKEN:?DEVICE_TOKEN env var required}"

cd "$(dirname "$0")"

# Pull through gametoken flags up front; everything else falls through to refresh.js.
GT_ARGS=()
RF_ARGS=()
HAS_TOPIC=0
HAS_BUDGET=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env|--game|--channel)
      GT_ARGS+=("$1" "$2"); shift 2 ;;
    --topic)
      HAS_TOPIC=1; RF_ARGS+=("$1" "$2"); shift 2 ;;
    --budget)
      HAS_BUDGET=1; RF_ARGS+=("$1" "$2"); shift 2 ;;
    *)
      RF_ARGS+=("$1"); shift ;;
  esac
done

read -r HP JWT < <(node gametoken.js --pipe "${GT_ARGS[@]}")
[[ -n "${HP:-}" && -n "${JWT:-}" ]] || { echo "gametoken.js produced no output" >&2; exit 1; }

# Default topic: address:account_id:<id> from the JWT payload.
if [[ $HAS_TOPIC -eq 0 ]]; then
  ACCT=$(J="$JWT" node -e '
    const j = process.env.J.split(".")[1];
    const p = JSON.parse(Buffer.from(j, "base64url").toString("utf8"));
    process.stdout.write(p.account_id || "");
  ')
  if [[ -n "$ACCT" ]]; then
    RF_ARGS+=(--topic "address:account_id:$ACCT")
  else
    echo "warning: no account_id claim in JWT, subscribing to no topic" >&2
  fi
fi
[[ $HAS_BUDGET -eq 0 ]] && RF_ARGS+=(--budget 60)

echo "target: $HP"
echo "jwt:    ${JWT:0:24}... (${#JWT}B)"
echo

exec env RSI_JWT="$JWT" node refresh.js --dry-run-grpc --host "$HP" "${RF_ARGS[@]}"
