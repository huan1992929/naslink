#!/bin/sh
set -eu

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
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

STAGE="${PROJECT_DIR}/build/spk-stage"
PACKAGE_ROOT="${STAGE}/package"
DIST="${PROJECT_DIR}/dist"
OUTPUT="${DIST}/NASLink-0.3.0-0019-x86_64.spk"

case "${STAGE}" in
    "${PROJECT_DIR}"/build/spk-stage) ;;
    *) echo "Unsafe stage path: ${STAGE}" >&2; exit 1 ;;
esac

rm -rf "${STAGE}"
mkdir -p "${PACKAGE_ROOT}/bin" "${STAGE}/conf" "${STAGE}/scripts" "${DIST}"

cd "${PROJECT_DIR}"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 "${GO_BIN}" build \
    -trimpath -ldflags="-s -w -buildid=" \
    -o "${PACKAGE_ROOT}/bin/naslink" ./cmd/naslink

"${GO_BIN}" run ./tools/icon --size 64 --out "${STAGE}/PACKAGE_ICON.PNG"
"${GO_BIN}" run ./tools/icon --size 256 --out "${STAGE}/PACKAGE_ICON_256.PNG"

cp packaging/spk/INFO "${STAGE}/INFO"
cp packaging/spk/conf/privilege "${STAGE}/conf/privilege"
cp packaging/spk/scripts/* "${STAGE}/scripts/"
chmod 755 "${STAGE}/scripts/"*

(cd "${PACKAGE_ROOT}" && tar -czf "${STAGE}/package.tgz" .)
(cd "${STAGE}" && tar -cf "${OUTPUT}" INFO PACKAGE_ICON.PNG PACKAGE_ICON_256.PNG conf scripts package.tgz)

echo "Built ${OUTPUT}"
shasum -a 256 "${OUTPUT}"
