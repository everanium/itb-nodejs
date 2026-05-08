// Shared scaffolding for the Node.js Easy Mode benchmark scripts.
//
// The harness mirrors the Go ``testing.B`` benchmark style on the
// itb_ext_test.go / itb3_ext_test.go side: each bench case runs a
// short warm-up batch to reach steady state, then a measured batch
// whose total wall-clock time is divided by the iteration count to
// produce the canonical ``ns/op`` throughput line. The output line
// also carries an MB/s figure derived from the configured payload
// size, matching the Go reporter's ``-benchmem``-less default.
//
// Environment variables (mirrored from itb's bitbyte_test.go +
// extended for Easy Mode):
//
// * ``ITB_NONCE_BITS`` — process-wide nonce width override; valid
//   values 128 / 256 / 512. Maps to `setNonceBits` before any
//   encryptor is constructed. Default 128.
// * ``ITB_LOCKSEED`` — when set to a non-empty / non-``0`` value,
//   every Easy Mode encryptor in this run calls
//   `Encryptor.setLockSeed(1)`. The Go side's auto-couple invariant
//   then engages BitSoup + LockSoup automatically; no separate flags
//   required for Easy Mode. Default off.
// * ``ITB_BENCH_FILTER`` — substring filter on bench-case names; only
//   cases whose name contains the substring run.
// * ``ITB_BENCH_MIN_SEC`` — minimum measured wall-clock seconds per
//   case (default 5.0). The runner doubles iteration count until the
//   measured batch reaches the threshold, mirroring Go's
//   ``-benchtime=Ns``. The 5-second default absorbs the cold-cache /
//   warm-up transient that distorts shorter measurement windows on
//   the 16 MiB encrypt / decrypt path.
//
// Worker count defaults to `setMaxWorkers(0)` (auto-detect), matching
// the Go bench default.

/* eslint-disable no-console */

/** Per-iter callable; accepts an iteration count and runs the
 * per-iter body that many times. The harness measures wall-clock
 * time outside the callable. Returning a `Promise` is supported and
 * awaited end-to-end, so async streaming benchmarks integrate
 * cleanly with the canonical 5-second convergence loop. */
export type BenchFn = (iters: number) => void | Promise<void>;

/** One bench case: name + per-iter callable + payload byte count
 * (used to compute the MB/s column). */
export interface BenchCase {
  readonly name: string;
  readonly run: BenchFn;
  readonly payloadBytes: number;
}

/** Default 16 MiB CSPRNG-filled payload, matching the Go bench /
 *  Python bench / Rust bench / C# bench surface. */
export const PAYLOAD_16MB = 16 << 20;

/** Canonical ITB key width pinned across every bench case
 *  (1024 bits = 128 bytes). */
export const KEY_BITS = 1024;

/** Bench MAC slot. Hard-coded to ``hmac-blake3`` — never
 *  ``kmac256``. KMAC-256 adds ~44% overhead on encrypt_auth via
 *  cSHAKE-256 / Keccak; HMAC-BLAKE3 adds ~9%. KMAC-256 in benches
 *  would shift the encrypt_auth row 4-5× higher than expected. */
export const MAC_NAME = 'hmac-blake3';

/** Mixed-primitive composition for bench_single / bench_triple's
 *  Mixed cases. The four user-facing slots (noise / data / start /
 *  optional dedicated lockSeed) all share the 256-bit native hash
 *  width so the `Encryptor.mixedSingle` / `mixedTriple` width-check
 *  passes. */
export const MIXED_NOISE = 'blake3';
export const MIXED_DATA = 'blake2s';
export const MIXED_START = 'blake2b256';
export const MIXED_LOCK = 'areion256';

/** Triple Ouroboros mixed-primitive seed slot composition. The seven
 *  middle slots (noise + 3 data + 3 start) cycle the same BLAKE
 *  family used by the Single mixed case. */
export const MIXED_NOISE_T = 'blake3';
export const MIXED_DATA1 = 'blake2s';
export const MIXED_DATA2 = 'blake2b256';
export const MIXED_DATA3 = 'blake3';
export const MIXED_START1 = 'blake2s';
export const MIXED_START2 = 'blake2b256';
export const MIXED_START3 = 'blake3';
export const MIXED_LOCK_T = 'areion256';

/** Canonical 9-primitive PRF-grade order, mirroring bench_single.py
 *  / bench_single.rs. The three below-spec lab primitives (CRC128,
 *  FNV-1a, MD5) are not exposed through the libitb registry and are
 *  therefore absent here by construction. */
export const PRIMITIVES_CANONICAL: readonly string[] = [
  'areion256',
  'areion512',
  'blake2b256',
  'blake2b512',
  'blake2s',
  'blake3',
  'aescmac',
  'siphash24',
  'chacha20',
];

/**
 * Reads `ITB_NONCE_BITS` from the environment with the same
 * 128 / 256 / 512 validation as bitbyte_test.go's TestMain. Falls
 * back to `defaultBits` on missing / invalid input (with a stderr
 * diagnostic for the invalid case).
 */
export function envNonceBits(defaultBits = 128): number {
  const v = process.env['ITB_NONCE_BITS'];
  if (v === undefined || v === '') {
    return defaultBits;
  }
  if (v === '128' || v === '256' || v === '512') {
    return Number(v);
  }
  console.error(
    `ITB_NONCE_BITS="${v}" invalid (expected 128/256/512); using ${defaultBits}`,
  );
  return defaultBits;
}

/**
 * `true` when `ITB_LOCKSEED` is set to a non-empty / non-`0` value.
 * Triggers `Encryptor.setLockSeed(1)` on every encryptor; Easy Mode
 * auto-couples BitSoup + LockSoup as a side effect.
 */
export function envLockSeed(): boolean {
  const v = process.env['ITB_LOCKSEED'];
  if (v === undefined || v === '' || v === '0') {
    return false;
  }
  return true;
}

/**
 * Optional substring filter for bench-case names, read from
 * `ITB_BENCH_FILTER`. Cases whose name does not contain the filter
 * substring are skipped; used to scope a run down to a single
 * primitive or operation during development.
 */
export function envBenchFilter(): string | null {
  const v = process.env['ITB_BENCH_FILTER'];
  if (v === undefined || v === '') {
    return null;
  }
  return v;
}

/**
 * Minimum wall-clock seconds the measured iter loop should take,
 * read from `ITB_BENCH_MIN_SEC` (default 5.0). The runner keeps
 * doubling iteration count until the measured run reaches this
 * threshold, mirroring Go's `-benchtime=Ns` semantics. The 5-second
 * default is wide enough to absorb the cold-cache / warm-up
 * transient that distorts shorter measurement windows on the 16 MiB
 * encrypt / decrypt path.
 */
export function envBenchMinSec(): number {
  const v = process.env['ITB_BENCH_MIN_SEC'];
  if (v === undefined || v === '') {
    return 5.0;
  }
  const f = Number(v);
  if (!Number.isFinite(f) || f <= 0) {
    console.error(
      `ITB_BENCH_MIN_SEC="${v}" invalid (expected positive float); using 5.0`,
    );
    return 5.0;
  }
  return f;
}

/**
 * Run a benchmark case to convergence and emit a single
 * Go-bench-style report line.
 *
 * Convergence policy: warm up with one iteration, then double the
 * iteration count until the measured wall-clock duration meets
 * `minSeconds`. The final `ns/op` figure is the measured duration
 * of that final batch divided by its iteration count.
 */
async function measure(bench: BenchCase, minSeconds: number): Promise<void> {
  // Warm-up — one iteration to hit cache / cold-start transients
  // before the measured loop.
  try {
    await bench.run(1);
  } catch (e) {
    console.log(`${bench.name}\tFAIL: ${(e as Error).message}`);
    return;
  }

  const minNs = BigInt(Math.floor(minSeconds * 1e9));
  let iters = 1;
  let elapsed: bigint = 0n;
  while (true) {
    const t0 = process.hrtime.bigint();
    await bench.run(iters);
    elapsed = process.hrtime.bigint() - t0;
    if (elapsed >= minNs) {
      break;
    }
    // Double up; cap growth so a very fast op doesn't escalate
    // past 1 << 24 iters for one batch.
    if (iters >= 1 << 24) {
      break;
    }
    iters *= 2;
  }

  const nsPerOp = Number(elapsed) / iters;
  const mbPerS =
    nsPerOp > 0 ? bench.payloadBytes / (nsPerOp / 1e9) / (1 << 20) : 0.0;
  // Mirrors `BenchmarkX-8     N    ns/op    MB/s` Go format,
  // column-aligned for human reading.
  console.log(
    `${padRight(bench.name, 60)}\t${padLeft(String(iters), 10)}\t${padLeft(nsPerOp.toFixed(1), 14)} ns/op\t${padLeft(mbPerS.toFixed(2), 9)} MB/s`,
  );
}

/**
 * Run every case in `cases` and print one Go-bench-style line per
 * case to stdout. Honours `ITB_BENCH_FILTER` for substring scoping
 * and `ITB_BENCH_MIN_SEC` for the per-case wall-clock budget.
 */
export async function runAll(cases: BenchCase[]): Promise<void> {
  const flt = envBenchFilter();
  const minSeconds = envBenchMinSec();

  const allNames = cases.map((c) => c.name);
  const selected =
    flt === null ? cases : cases.filter((c) => c.name.includes(flt));
  if (selected.length === 0) {
    console.error(
      `no bench cases match filter "${flt}"; available: ${JSON.stringify(allNames)}`,
    );
    return;
  }

  const first = selected[0]!;
  console.log(
    `# benchmarks=${selected.length} payload_bytes=${first.payloadBytes} min_seconds=${minSeconds}`,
  );
  for (const bench of selected) {
    await measure(bench, minSeconds);
  }
}

function padRight(s: string, width: number): string {
  if (s.length >= width) return s;
  return s + ' '.repeat(width - s.length);
}

function padLeft(s: string, width: number): string {
  if (s.length >= width) return s;
  return ' '.repeat(width - s.length) + s;
}
