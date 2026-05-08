#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Node.js / TypeScript
# binding. Verifies libitb.so is present, sets LD_LIBRARY_PATH, then
# invokes `npm test`. Forwards any positional arguments through to
# the npm test script (e.g. a single test file path).
#
# Usage:
#   ./run_tests.sh                                       # full suite
#   ./run_tests.sh dist-test/test/easy/test_blake3.test.js  # one file
#
# Prerequisites: node_modules must exist; run ./build.sh first if not.

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

if [[ ! -f "$DIST_DIR/libitb.so" ]]; then
    echo "error: libitb.so not found at $DIST_DIR" >&2
    echo "       run ./build.sh first" >&2
    exit 1
fi

if [[ ! -d node_modules ]]; then
    echo "error: node_modules missing; run ./build.sh first" >&2
    exit 1
fi

export LD_LIBRARY_PATH="$DIST_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

if [[ $# -gt 0 ]]; then
    exec npm test -- "$@"
fi

exec npm test
