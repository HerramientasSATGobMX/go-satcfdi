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

rm -rf examples/python/generated examples/php/generated
mkdir -p examples/python/generated examples/php/generated

run_buf generate --template buf.gen.examples.yaml

mkdir -p \
  examples/python/generated/satcfdi \
  examples/python/generated/satcfdi/v1

touch \
  examples/python/generated/__init__.py \
  examples/python/generated/satcfdi/__init__.py \
  examples/python/generated/satcfdi/v1/__init__.py

