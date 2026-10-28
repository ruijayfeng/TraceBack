#!/usr/bin/env bash
# F23: run the backend suite with the repository import path, matching CI.
set -euo pipefail
cd "$(dirname "$0")/.."
PYTHON_BIN="${PYTHON:-python3}"
PYTHONPATH="$PWD/backend:$PWD${PYTHONPATH:+:$PYTHONPATH}" exec "$PYTHON_BIN" -m pytest backend/tests "$@"
