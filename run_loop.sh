#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the Node.js
# binding: compiles the utility on first use (or after a clean) and
# execs it with every argument passed through. libitb3.so and the
# binding's own TypeScript output are assumed built by build.sh.
#
# The compiler's own output is held back and printed only when it
# fails, so neither stream carries anything the utility did not write.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

if [[ ! -f dist-loop/loop/main.js ]]; then
    if ! build_log="$(npm run --silent loop:build 2>&1)"; then
        printf '%s\n' "$build_log" >&2
        exit 1
    fi
fi

exec node dist-loop/loop/main.js "$@"
