#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

run_buf() {
  if command -v buf >/dev/null 2>&1; then
    buf "$@"
    return
  fi

  go run github.com/bufbuild/buf/cmd/buf@v1.59.0 "$@"
}

run_buf generate
