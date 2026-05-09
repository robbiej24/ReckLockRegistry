#!/bin/sh
set -e

if [ "${SKIP_INIT_DB:-}" != "1" ]; then
  recklock-registry init-db
fi

exec recklock-registry serve "$@"
