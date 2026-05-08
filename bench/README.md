# ITB Node.js / TypeScript Binding - Easy Mode Benchmark

Two scripts cover the Easy Mode encryption / decryption surface
exposed by the Node.js binding:

* `bench-single.ts` — Single Ouroboros (mode=1, 3 seeds + optional
  dedicated lockSeed). Walks the nine PRF-grade primitives plus
  one mixed-primitive variant.
* `bench-triple.ts` — Triple Ouroboros (mode=3, 7 seeds + optional
  dedicated lockSeed). Same nine + one mixed grid as the Single
  script.

Both scripts pin **1024-bit ITB key width** and **16 MiB
CSPRNG-filled payload**, run four ops per case (`encrypt`,
`decrypt`, `encryptAuth`, `decryptAuth`), and emit a Go-bench-style
line per case (`name iters ns/op MB/s`).

The harness is a custom Go-bench-style runner in `bench/common.ts`
(no third-party bench framework — Node's built-in `node:crypto`
+ `process.hrtime.bigint` cover the random-fill and timing
surfaces). Three `npm` scripts in `package.json` drive the
build + run cycle: `bench:build` (TypeScript build only),
`bench:single`, `bench:triple` (build + run the matching pass).

## Prerequisites

Build the shared library once and install the Node.js dependencies
(see the binding [README](../README.md)):

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/nodejs && npm install
```

A project-private opt-out tag is available when the 4-lane
chain-absorb wrapper is dead weight (hosts without AVX-512+VL).
The tag disables only the chain-absorb asm; upstream stdlib asm
stays engaged so the per-pixel single Func runs at upstream-asm
speed via `process_cgo`'s nil-`BatchHash` fallback:

```bash
go build -trimpath -tags=noitbasm -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
```

The Node.js binding loads `libitb.so` / `.dll` / `.dylib` at
runtime through `koffi`, picking it up from `ITB_LIBRARY_PATH`,
`<repo>/dist/<os>-<arch>/`, or the system loader path; see
`bindings/nodejs/src/library-loader.ts` for the full search list.

## Run

From the binding root (`bindings/nodejs/`):

```bash
npm run bench:single
npm run bench:triple
```

The `bench:single` and `bench:triple` scripts compile the bench
harness into `dist-bench/` and dispatch through `dist-bench/bench/main.js
{single,triple}`. To compile without running, use `npm run bench:build`.

## Environment variables

| Variable             | Default | Purpose |
|----------------------|---------|---------|
| `ITB_NONCE_BITS`     | `128`   | Process-wide nonce width — `128`, `256`, or `512`. Mirrors `ITB_NONCE_BITS` from `bitbyte_test.go`. |
| `ITB_LOCKSEED`       | unset   | When set to a non-empty / non-`0` value, every encryptor in the run calls `setLockSeed(1)`. Easy Mode auto-couples `setBitSoup(1)` + `setLockSoup(1)`, so no separate flags are needed. The mixed-primitive cases attach a dedicated lockSeed primitive (via `primL`) only under this flag; otherwise `primL` is `null` so the no-LockSeed bench arm measures the plain mixed-primitive cost. |
| `ITB_BENCH_FILTER`   | unset   | Substring filter on bench-function names — only cases whose name contains the filter are run. Useful when iterating on one primitive / op. |
| `ITB_BENCH_MIN_SEC`  | `5.0`   | Minimum measured wall-clock seconds per case. The runner keeps doubling iteration count until the measured batch reaches the threshold, mirroring Go's `-benchtime=Ns`. The 5-second default absorbs the cold-cache / warm-up transient that distorts shorter measurement windows on the 16 MiB encrypt / decrypt path. |

Worker count is fixed at `setMaxWorkers(0)` (auto-detect),
matching the Go bench default.

## Examples

Whole grid, default settings (128-bit nonces, no lockSeed):

```bash
npm run bench:single
```

512-bit nonces with the dedicated lockSeed channel + auto-coupled
overlay:

```bash
ITB_NONCE_BITS=512 ITB_LOCKSEED=1 npm run bench:triple
```

Just the BLAKE3 row of the Single grid:

```bash
ITB_BENCH_FILTER=blake3_1024bit npm run bench:single
```

Only the encrypt-with-MAC ops across every primitive in the Triple
grid, with a longer 10-second per-case budget for tighter
confidence intervals:

```bash
ITB_BENCH_FILTER=encrypt_auth_16mb ITB_BENCH_MIN_SEC=10 \
    npm run bench:triple
```

Just the mixed-primitive cases on the Single side:

```bash
ITB_BENCH_FILTER=mixed npm run bench:single
```

## Output format

```
# easy_single primitives=9 key_bits=1024 mac=hmac-blake3 nonce_bits=128 lockseed=off workers=auto
# benchmarks=40 payload_bytes=16777216 min_seconds=5
bench_single_aescmac_1024bit_encrypt_16mb               4    493210110.0 ns/op    32.44 MB/s
bench_single_aescmac_1024bit_decrypt_16mb               4    488104225.0 ns/op    32.78 MB/s
...
```

The four columns are:

1. Bench-function name (matches the `BenchmarkSingle*` /
   `BenchmarkTriple*` Go cohort, snake-cased and without the `Ext`
   infix that the Go side carries for namespace reasons).
2. Iteration count chosen to reach `ITB_BENCH_MIN_SEC`.
3. Per-iter wall-clock cost in nanoseconds.
4. Throughput in MiB/s, derived from `payload_bytes / ns_per_op`.

Comparison with the Go bench cohort goes via `(MB/s ratio)` —
the throughput column is the most direct cross-language signal for
how much overhead the Node.js binding adds on top of the underlying
libitb call path.

## Expected runtime

At the default `ITB_BENCH_MIN_SEC=5`, each pass walks 40 cases (9
single-primitive + 1 mixed × 4 ops) and converges per case in 5–15
wall-clock seconds depending on the primitive's per-byte cost. A
full pass therefore lands at 5–10 minutes; the four canonical
passes (Single ±LockSeed, Triple ±LockSeed) fill BENCH.md in
~30 minutes of total wall-clock time. Filter to a single primitive
(`ITB_BENCH_FILTER=blake3_1024bit`) for ~1-minute spot-check runs.

## Recorded results

A snapshot of the four canonical pass results (Single + Triple,
each with and without `ITB_LOCKSEED=1`) on Intel Core i7-11700K is
collected in [BENCH.md](BENCH.md). The same file briefly discusses
the FFI overhead the binding leaves on top of the native Go path.
