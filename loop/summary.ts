// The final summary in both renderings, and the two measurements it
// folds in that are not per-worker counters: the process resident set
// and the shared library's pool counters.

import { readFileSync } from 'node:fs';
import { ItbError, drbgAutoTier, poolStats, setGCPercent } from '../src/index.js';
import { payloadModeName } from './payload.js';
import {
  humanBytes,
  humanBytesSigned,
  humanDuration,
  humanRate,
  mbPerSec,
  roundNs,
  u64Dec,
} from './size.js';
import {
  CONCURRENCY,
  logLine,
  onOff,
  outRaw,
  policyLabel,
  shapeName,
  type Config,
  type WorkerReport,
} from './state.js';

// ─── Resident set ──────────────────────────────────────────────────

/**
 * Parses one "Vm...:   1234 kB" line of /proc/self/status into bytes;
 * zero on any parse failure.
 */
function statusKb(line: string): number {
  const fields = line.trim().split(/\s+/);
  if (fields.length < 2 || !/^[0-9]+$/.test(fields[1]!)) {
    return 0;
  }
  return Number(fields[1]) * 1024;
}

/**
 * The process's current resident set and its high-water mark in bytes,
 * from /proc/self/status (VmRSS and VmHWM, reported in kB). Both are
 * zero on a platform without that file; the figures are informational
 * and never enter the verdict.
 */
export function readRss(): [number, number] {
  let text: string;
  try {
    text = readFileSync('/proc/self/status', 'latin1');
  } catch {
    return [0, 0];
  }
  let current = 0;
  let peak = 0;
  for (const line of text.split('\n')) {
    if (line.startsWith('VmRSS:')) {
      current = statusKb(line);
    } else if (line.startsWith('VmHWM:')) {
      peak = statusKb(line);
    }
  }
  return [current, peak];
}

// ─── Pool counters ─────────────────────────────────────────────────

/**
 * Pool counters. The shared library keeps process-wide monotonic
 * totals at every pool checkout of its cipher core: per hash-array
 * tier the starter width, checkouts, constructor misses, regrow
 * replacements and bytes allocated; for the scratch byte pool and the
 * parallax chunk pool the checkouts, constructor misses, regrows and
 * regrow bytes. Two snapshots bracketing the main loop are differenced
 * into per-run hit / miss figures that tell whether a pool keeps its
 * items warm between calls or evicts them across GC cycles. The slot
 * layout is read from the library: slot 0 carries the tier count T,
 * tier i occupies the five slots at 1 + 5*i, and the two byte pools
 * occupy the eight slots at 1 + 5*T; the vector is sized from the
 * binding's length query, never from a constant.
 */
export function poolSnapshot(): bigint[] {
  try {
    return poolStats();
  } catch (e) {
    if (e instanceof ItbError) {
      return [];
    }
    throw e;
  }
}

/** The differenced pool figures of one run. */
export class PoolDelta {
  tiers = 0;
  starter: bigint[] = [];
  get: bigint[] = [];
  new: bigint[] = [];
  regrow: bigint[] = [];
  newBytes: bigint[] = [];
  buf: bigint[] = [0n, 0n, 0n, 0n];
  chunk: bigint[] = [0n, 0n, 0n, 0n];

  constructor(warmup: bigint[], steady: bigint[]) {
    if (
      warmup.length === 0 ||
      steady.length < 9 ||
      warmup.length !== steady.length
    ) {
      return;
    }
    const tiers = Number(steady[0]!);
    if (tiers < 0 || 1 + 5 * tiers + 8 > steady.length) {
      return;
    }
    this.tiers = tiers;
    for (let i = 0; i < tiers; i++) {
      const base = 1 + 5 * i;
      this.starter.push(steady[base]!);
      this.get.push(steady[base + 1]! - warmup[base + 1]!);
      this.new.push(steady[base + 2]! - warmup[base + 2]!);
      this.regrow.push(steady[base + 3]! - warmup[base + 3]!);
      this.newBytes.push(steady[base + 4]! - warmup[base + 4]!);
    }
    const tail = 1 + 5 * tiers;
    for (let i = 0; i < 4; i++) {
      this.buf[i] = steady[tail + i]! - warmup[tail + i]!;
      this.chunk[i] = steady[tail + 4 + i]! - warmup[tail + 4 + i]!;
    }
  }
}

/**
 * Misses over checkouts as a percentage; zero when nothing was checked
 * out.
 */
function missPercent(miss: bigint, get: bigint): number {
  if (get <= 0n) {
    return 0;
  }
  return (100 * Number(miss)) / Number(get);
}

/**
 * The effective GC percentage as the runtime reports it: the query form
 * of the setter (a set-and-restore round trip inside the library) so
 * the field is the same whether the value came from the flag, the
 * environment, or the runtime default.
 */
function effectiveGogc(flag: number): number {
  if (flag > 0) {
    return flag;
  }
  return setGCPercent(-1);
}

/** Renders s as a JSON string literal with the escapes JSON requires. */
function jsonString(s: string): string {
  return JSON.stringify(s);
}

/** Everything the summary reads that is not a per-worker counter. */
export interface SummaryInput {
  cfg: Config;
  /** One report per effective worker, in worker order. */
  reports: WorkerReport[];
  rekeys: number;
  blobCycles: number;
  /** The streaming Pipeline's profile, "" when not built. */
  streamProfile: string;
  /** The Single Message Pipeline's profile, "" when not built. */
  msgProfile: string;
  rssWarmup: number;
  rssPeak: number;
  rssFinal: number;
  poolWarmup: bigint[];
  poolSteady: bigint[];
  gomaxprocs: number;
  elapsedNs: bigint;
}

/**
 * Output contract. Both renderings are shared with the Go harness and
 * every other binding's loop utility field for field: the same lines in
 * the same order, the same keys in the same order, floats with a fixed
 * number of decimals so the JSON is byte-identical across
 * implementations. The Go harness alone adds its runtime-internal lines
 * after rss: and its runtime-internal keys after parallax_chunk_pool;
 * nothing here reproduces them because nothing they read is reachable
 * through the C ABI.
 */
export function finalSummary(s: SummaryInput): number {
  const cfg = s.cfg;
  const reports = s.reports;
  let totalIters = 0;
  let totalEnc = 0;
  let totalDec = 0;
  let nanosEnc = 0n;
  let nanosDec = 0n;
  const errors: string[] = [];
  for (const r of reports) {
    totalIters += r.iters;
    totalEnc += r.bytesEnc;
    totalDec += r.bytesDec;
    nanosEnc += r.nanosEnc;
    nanosDec += r.nanosDec;
    if (r.failed) {
      errors.push(r.error);
    }
  }

  // Throughput. Per-direction throughput divides the sum of every
  // worker's wall time in that direction by the worker count — the
  // equivalent single-stream wall time under N-way concurrency — so
  // each direction reports the aggregate rate it sustained rather than
  // collapsing to combined/2 (every iteration moves equal encrypt and
  // decrypt bytes, so a total-elapsed denominator would give both
  // directions the same figure). The combined rate keeps total elapsed
  // as the one-glance overall figure.
  const workers = BigInt(cfg.workers);
  const avgEnc = nanosEnc > 0n ? nanosEnc / workers : 0n;
  const avgDec = nanosDec > 0n ? nanosDec / workers : 0n;

  const rssDelta = s.rssFinal - s.rssWarmup;
  const rssGrowth = s.rssWarmup > 0 ? (100 * rssDelta) / s.rssWarmup : 0;

  const pd = new PoolDelta(s.poolWarmup, s.poolSteady);
  const passed = errors.length === 0;

  if (cfg.jsonOutput) {
    emitJson(s, pd, errors, passed, totalIters, totalEnc, totalDec, avgEnc, avgDec, rssGrowth);
    return passed ? 0 : 1;
  }

  logLine('=== FINAL ===');
  logLine(`  duration: ${humanDuration(roundNs(s.elapsedNs, 1000000n))}`);
  logLine(
    `  iterations: ${reports.map((r) => r.iters).join(' + ')} = ${totalIters} total`,
  );
  logLine(
    `  throughput: encrypt ${humanRate(totalEnc, avgEnc)}, ` +
      `decrypt ${humanRate(totalDec, avgDec)}, ` +
      `combined ${humanRate(totalEnc + totalDec, s.elapsedNs)}`,
  );
  logLine(`  bytes: ${humanBytes(totalEnc)} encrypted, ${humanBytes(totalDec)} decrypted`);
  logLine(`  data integrity: ${totalIters}/${totalIters} PASS`);
  logLine(
    `  concurrency: ${CONCURRENCY}, workers ${cfg.workers} ` +
      `(requested ${cfg.workersRequested})`,
  );
  logLine(
    `  rss: warmup ${humanBytes(s.rssWarmup)}, peak ${humanBytes(s.rssPeak)}, ` +
      `final ${humanBytes(s.rssFinal)} ` +
      `(delta ${humanBytesSigned(rssDelta)}, ${rssGrowth.toFixed(1)}% growth)`,
  );
  for (let i = 0; i < pd.tiers; i++) {
    if (pd.starter[i] === 0n) {
      continue;
    }
    const miss = pd.new[i]! + pd.regrow[i]!;
    logLine(
      `  hash pool tier ${i} (starter ${pd.starter[i]}): get ${pd.get[i]}, ` +
        `miss ${miss} (new ${pd.new[i]} + regrow ${pd.regrow[i]}), ` +
        `miss ${missPercent(miss, pd.get[i]!).toFixed(2)}%, ` +
        `${humanBytes(Number(pd.newBytes[i]))} allocated`,
    );
  }
  logLine(
    `  buf pool: get ${pd.buf[0]}, regrow ${pd.buf[2]} (of which fresh ${pd.buf[1]}), ` +
      `miss ${missPercent(pd.buf[2]!, pd.buf[0]!).toFixed(2)}%, ` +
      `${humanBytes(Number(pd.buf[3]))} regrown`,
  );
  logLine(
    `  parallax chunk pool: get ${pd.chunk[0]}, regrow ${pd.chunk[2]} ` +
      `(of which fresh ${pd.chunk[1]}), ` +
      `miss ${missPercent(pd.chunk[2]!, pd.chunk[0]!).toFixed(2)}%, ` +
      `${humanBytes(Number(pd.chunk[3]))} regrown`,
  );
  if (s.rekeys > 0) {
    logLine(`  rekeys: ${s.rekeys}`);
  }
  if (s.blobCycles > 0) {
    logLine(`  blob cycles: ${s.blobCycles}`);
  }
  for (const text of errors) {
    logLine(`  ERROR: ${text}`);
  }
  if (passed) {
    logLine('  verdict: PASS');
    return 0;
  }
  logLine(`  verdict: FAIL (errors=${errors.length})`);
  return 1;
}

/**
 * One compact object on one line, keys in the contract's order, floats
 * with the contract's decimal counts and never in exponent form.
 */
function emitJson(
  s: SummaryInput,
  pd: PoolDelta,
  errors: string[],
  passed: boolean,
  totalIters: number,
  totalEnc: number,
  totalDec: number,
  avgEnc: bigint,
  avgDec: bigint,
  rssGrowth: number,
): void {
  const cfg = s.cfg;
  const tiers: string[] = [];
  for (let i = 0; i < pd.tiers; i++) {
    if (pd.starter[i] === 0n) {
      continue;
    }
    const miss = pd.new[i]! + pd.regrow[i]!;
    tiers.push(
      `{"tier":${i},"starter":${pd.starter[i]},"get":${pd.get[i]},` +
        `"new":${pd.new[i]},"regrow":${pd.regrow[i]},"new_bytes":${pd.newBytes[i]},` +
        `"miss_percent":${missPercent(miss, pd.get[i]!).toFixed(2)}}`,
    );
  }
  const out =
    `{"duration_seconds":${(Number(s.elapsedNs) / 1e9).toFixed(3)}` +
    `,"iterations":${totalIters}` +
    `,"per_worker_iterations":[${s.reports.map((r) => r.iters).join(',')}]` +
    `,"bytes_encrypted":${totalEnc}` +
    `,"bytes_decrypted":${totalDec}` +
    `,"encrypt_mb_per_sec":${mbPerSec(totalEnc, avgEnc).toFixed(1)}` +
    `,"decrypt_mb_per_sec":${mbPerSec(totalDec, avgDec).toFixed(1)}` +
    `,"combined_mb_per_sec":${mbPerSec(totalEnc + totalDec, s.elapsedNs).toFixed(1)}` +
    `,"rekeys":${s.rekeys}` +
    `,"blob_cycles":${s.blobCycles}` +
    `,"worker_errors":[${errors.map(jsonString).join(',')}]` +
    `,"verdict":"${passed ? 'PASS' : 'FAIL'}"` +
    `,"shape":"${shapeName(cfg.shape)}"` +
    `,"stream_profile":${jsonString(s.streamProfile)}` +
    `,"message_profile":${jsonString(s.msgProfile)}` +
    `,"hash":${jsonString(cfg.hash)}` +
    `,"mac":${jsonString(cfg.mac)}` +
    `,"payload_bytes":${cfg.payload}` +
    `,"payload_mode":"${payloadModeName(cfg.payloadMode)}"` +
    `,"seed":${u64Dec(cfg.seed)}` +
    `,"key_bits":${cfg.keyBits}` +
    `,"nonce_bits":${cfg.nonceBits}` +
    `,"blob_mode":${cfg.blobMode}` +
    `,"drbg":${jsonString(cfg.drbg)}` +
    `,"drbg_auto_tier":${jsonString(drbgAutoTier())}` +
    `,"chunk_size_bytes":${cfg.chunkSize}` +
    `,"barrier_fill":${cfg.barrierFill}` +
    `,"parallax":"${onOff(cfg.parallax)}"` +
    `,"wrapper":"${onOff(cfg.wrapper)}"` +
    `,"goroutines_requested":${cfg.workersRequested}` +
    `,"goroutines":${cfg.workers}` +
    `,"concurrency":"${CONCURRENCY}"` +
    `,"gogc":"${effectiveGogc(cfg.gogc)}"` +
    `,"memlimit_bytes":${cfg.memlimit}` +
    `,"gomaxprocs":${s.gomaxprocs}` +
    `,"microbatch_tiers":${jsonString(policyLabel(process.env['ITB_MICROBATCH_TIERS']))}` +
    `,"hashpool_starters":${jsonString(policyLabel(process.env['ITB_HASHPOOL_STARTERS']))}` +
    `,"rss_warmup_bytes":${s.rssWarmup}` +
    `,"rss_peak_bytes":${s.rssPeak}` +
    `,"rss_final_bytes":${s.rssFinal}` +
    `,"rss_growth_percent":${rssGrowth.toFixed(2)}` +
    `,"hash_pool_tiers":[${tiers.join(',')}]` +
    `,"buf_pool":{"get":${pd.buf[0]},"new":${pd.buf[1]},"regrow":${pd.buf[2]},` +
    `"regrow_bytes":${pd.buf[3]},` +
    `"miss_percent":${missPercent(pd.buf[2]!, pd.buf[0]!).toFixed(2)}}` +
    `,"parallax_chunk_pool":{"get":${pd.chunk[0]},"new":${pd.chunk[1]},` +
    `"regrow":${pd.chunk[2]},"regrow_bytes":${pd.chunk[3]},` +
    `"miss_percent":${missPercent(pd.chunk[2]!, pd.chunk[0]!).toFixed(2)}}` +
    '}\n';
  outRaw(out);
}
