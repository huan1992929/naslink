#!/bin/sh
set -eu
PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
GO_BIN="${GO_BIN:-$(command -v go 2>/dev/null || true)}"
if [ -z "${GO_BIN}" ] && [ -x /tmp/codex-go-1.26.5/go/bin/go ]; then GO_BIN=/tmp/codex-go-1.26.5/go/bin/go; fi
if [ ! -x "${GO_BIN}" ]; then echo "Go toolchain not found" >&2; exit 1; fi
DIST="${PROJECT_DIR}/dist/license-center"
mkdir -p "${DIST}"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "${GO_BIN}" build -trimpath -ldflags="-s -w -buildid=" -o "${DIST}/naslink-license-center" "${PROJECT_DIR}/cmd/license-center"
cp "${PROJECT_DIR}/packaging/license-center/README.md" "${DIST}/README.md"
(cd "${PROJECT_DIR}/dist" && tar -czf NASLink-LicenseCenter-0.3.0-linux-amd64.tar.gz license-center)
shasum -a 256 "${PROJECT_DIR}/dist/NASLink-LicenseCenter-0.3.0-linux-amd64.tar.gz"
