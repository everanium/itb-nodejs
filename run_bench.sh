#!/usr/bin/env bash
#
# run_bench.sh -- bench runner for the Node.js / TypeScript binding.
# Builds libitb.so + the binding via build.sh, points ITB_LIBITB_PATH
# at the freshly-built shared library, then runs every bench script
# (bench_message + bench_stream + bench_stream_one_shot) at
# 1 / 16 / 64 MiB.

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export ITB_LIBITB_PATH="$DIST_DIR/libitb.so"

# Bench-hostile Go runtime defaults are capped at libitb load time
# via env vars so a bench crash before the benches' own
# setMemoryLimit / setGCPercent calls still runs under a bounded
# heap. The benches themselves reassert these via the API for
# self-contained reproducibility.
export ITB_GOMEMLIMIT="${ITB_GOMEMLIMIT:-512MiB}"
export ITB_GOGC="${ITB_GOGC:-20}"

# Bench-shape defaults — match the root Go BENCH3.md pin so the
# throughput numbers are directly comparable to the shipped Go
# baseline. Override any of these before calling the script to
# change the shape. ITB_PROFILE stays unset by default: each bench
# script applies its own shape default (Message:
# singlemsg-triple-nomac-v1 / Stream: streaming-noaead-triple-v1).
export ITB_NONCE_BITS="${ITB_NONCE_BITS:-512}"
export ITB_KEY_BITS="${ITB_KEY_BITS:-1024}"
export ITB_WITH_PARALLAX="${ITB_WITH_PARALLAX:-false}"
export ITB_WITH_WRAPPER="${ITB_WITH_WRAPPER:-false}"
export ITB_INNER_HASH="${ITB_INNER_HASH:-areion512}"
export ITB_BENCH_MIN_SEC="${ITB_BENCH_MIN_SEC:-5}"

# ITB_WITH_MAC=true derives MAC/AEAD profile counterparts. When
# ITB_PROFILE is set explicitly by the caller, it wins over the
# derivation and applies to both shapes (expert override).
: "${ITB_WITH_MAC:=false}"
if [ -n "${ITB_PROFILE:-}" ]; then
    ITB_MSG_PROFILE_DEFAULT="${ITB_PROFILE}"
    ITB_STREAM_PROFILE_DEFAULT="${ITB_PROFILE}"
elif [ "${ITB_WITH_MAC}" = "true" ]; then
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-mac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-aead-triple-mac-v1"
else
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-nomac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-noaead-triple-v1"
fi

npm run bench:build
export ITB_PROFILE="${ITB_MSG_PROFILE_DEFAULT}"
node dist-bench/benches/bench_message.js
export ITB_PROFILE="${ITB_STREAM_PROFILE_DEFAULT}"
node dist-bench/benches/bench_stream.js
node dist-bench/benches/bench_stream_one_shot.js
