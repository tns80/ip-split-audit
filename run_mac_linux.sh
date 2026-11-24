#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "[Error] Python 3.8+ is required."
  exit 1
fi

"$PY" "$SCRIPT_DIR/ip_split_audit.py" --open "$@"
