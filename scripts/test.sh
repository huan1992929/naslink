#!/bin/sh
set -eu

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
GO_BIN="${GO_BIN:-}"
if [ -z "${GO_BIN}" ]; then
    GO_BIN="$(command -v go 2>/dev/null || true)"
fi
if [ -z "${GO_BIN}" ] && [ -x /tmp/codex-go-1.26.5/go/bin/go ]; then
    GO_BIN=/tmp/codex-go-1.26.5/go/bin/go
fi
if [ ! -x "${GO_BIN}" ]; then
    echo "Go toolchain not found. Set GO_BIN=/path/to/go" >&2
    exit 1
fi

cd "${PROJECT_DIR}"
"${GO_BIN}" fmt ./...
"${GO_BIN}" vet ./...
"${GO_BIN}" test -race ./...

