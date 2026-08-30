#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Node.js / TypeScript
# binding. Builds libitb.so + the binding via build.sh, points
# ITB_LIBITB_PATH at the freshly-built shared library, then invokes
# `npm test`. Positional arguments are forwarded through to the npm
# test script (e.g. a single compiled test file path).
#
# Usage:
#   ./run_tests.sh                                        # full suite
#   ./run_tests.sh dist-test/tests/smoke.test.js          # one file

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export ITB_LIBITB_PATH="$DIST_DIR/libitb.so"

if [[ $# -gt 0 ]]; then
    exec npm test -- "$@"
fi

exec npm test
