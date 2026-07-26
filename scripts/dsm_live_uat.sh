#!/bin/sh
set -eu

DSM_BASE_URL="${1:-https://127.0.0.1:5001}"
DSM_ACCOUNT="${2:-}"
GO_BIN="${NASLINK_GO_BIN:-go}"

if [ -z "${DSM_ACCOUNT}" ] || [ -z "${NASLINK_DSM_PASSWORD:-}" ]; then
    echo "usage: NASLINK_DSM_PASSWORD=... $0 https://nas:5001 admin" >&2
    exit 2
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
cd "${PROJECT_DIR}"
exec "${GO_BIN}" run ./cmd/dsm-uat --url "${DSM_BASE_URL}" --account "${DSM_ACCOUNT}" --insecure
