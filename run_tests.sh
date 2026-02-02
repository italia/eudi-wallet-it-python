#!/usr/bin/env bash
# Load local env (e.g. .env) then run pytest on pyeudiw.
# For MongoDB with auth, set in .env: PYEUDIW_MONGO_TEST_AUTH_INLINE="user:password@"
# (empty = no auth, e.g. CI). See README.md and integration_test/.env.example.
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
if [ -f .env ]; then
  set -a
  # shellcheck source=/dev/null
  . ./.env
  set +a
fi
if [ -f integration_test/.env ]; then
  set -a
  # shellcheck source=/dev/null
  . ./integration_test/.env
  set +a
fi
exec python3 -m pytest pyeudiw "$@"
