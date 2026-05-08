#!/usr/bin/env bash
#
# build.sh -- one-step build for the Node.js / TypeScript binding:
# libitb.so + npm install + TypeScript compile. Prerequisites (Go,
# Node.js >= 22, npm) must be installed separately; see README.md
# "Prerequisites" section.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

cd "$REPO_ROOT"
echo "==> building libitb.so${TAGS:+ (with ${TAGS[*]})}"
go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared

cd "$REPO_ROOT/bindings/nodejs"
if [ ! -d node_modules ]; then
    echo "==> installing npm dependencies"
    npm install
fi
echo "==> cleaning previous Node.js binding build artefacts (dist*/)"
rm -rf dist dist-test 2>/dev/null || true
echo "==> building Node.js binding (TypeScript)"
npm run build

echo "==> ready: npm test"
