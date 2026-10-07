// Size and duration parsing, the monotonic clock, and the human
// renderings of sizes, rates and durations. Every rendering here is
// part of the output contract shared with the Go harness and the other
// bindings' loop utilities, so the formats are fixed to the character,
// not to taste.

// Byte-size suffixes, longest first so "KIB" is matched before "K" and
// "B" never swallows the tail of another suffix. Every multiple is
// binary.
const SIZE_SUFFIXES: ReadonlyArray<readonly [string, number]> = [
  ['KIB', 1024],
  ['KB', 1024],
  ['K', 1024],
  ['MIB', 1048576],
  ['MB', 1048576],
  ['M', 1048576],
  ['GIB', 1073741824],
  ['GB', 1073741824],
  ['G', 1073741824],
  ['B', 1],
];

// Duration units in the order the grammar probes them, so "ms" is
// taken before "m" and "s", and "ns" / "us" before "s".
const DURATION_UNITS: ReadonlyArray<readonly [string, number]> = [
  ['ns', 1],
  ['us', 1e3],
  ['ms', 1e6],
  ['s', 1e9],
  ['m', 60e9],
  ['h', 3600e9],
];

const INT64_MAX = 9223372036854775807n;

function isDigits(s: string): boolean {
  return s.length > 0 && /^[0-9]+$/.test(s);
}

/**
 * Parses a human byte-size string ("16MB", "1MiB", "512K",
 * "1073741824") into a byte count. Every suffix is a binary multiple:
 * K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B or none =
 * bytes; matching is case-insensitive and surrounding whitespace is
 * trimmed. Returns null on a malformed or negative value.
 */
export function parseSize(s: string): number | null {
  const upper = s.trim().toUpperCase();
  if (upper === '') {
    return null;
  }
  let mult = 1;
  let digits = upper;
  for (const [suffix, m] of SIZE_SUFFIXES) {
    if (upper.endsWith(suffix)) {
      mult = m;
      digits = upper.slice(0, upper.length - suffix.length);
      break;
    }
  }
  digits = digits.replace(/\s+$/, '');
  if (!isDigits(digits)) {
    return null;
  }
  // The product is taken in BigInt so a value that cannot be a byte
  // count is rejected rather than silently losing precision in a
  // double.
  const n = BigInt(digits) * BigInt(mult);
  if (n > INT64_MAX || n > BigInt(Number.MAX_SAFE_INTEGER)) {
    return null;
  }
  return Number(n);
}

/**
 * Parses the Go duration grammar — a sequence of decimal numbers each
 * followed by a unit (h, m, s, ms, us, ns), such as "30s", "5m",
 * "1h30m", "3s500ms", "1.5s" — into nanoseconds. Returns null on a
 * malformed string.
 */
export function parseDuration(s: string): number | null {
  if (s === '') {
    return null;
  }
  let total = 0;
  let pos = 0;
  while (pos < s.length) {
    const start = pos;
    while (pos < s.length && /[0-9.]/.test(s[pos]!)) {
      pos++;
    }
    if (pos === start) {
      return null;
    }
    const digits = s.slice(start, pos);
    const value = Number(digits);
    if (!Number.isFinite(value) || value < 0) {
      return null;
    }
    let mult = 0;
    for (const [unit, ns] of DURATION_UNITS) {
      if (!s.startsWith(unit, pos)) {
        continue;
      }
      const after = pos + unit.length;
      if (after < s.length && /[A-Za-z]/.test(s[after]!)) {
        continue;
      }
      mult = ns;
      pos = after;
      break;
    }
    if (mult === 0) {
      return null;
    }
    total += value * mult;
  }
  if (total > 9.2e18) {
    return null;
  }
  return Math.trunc(total);
}

/** Monotonic wall clock in nanoseconds. */
export function nowNs(): bigint {
  return process.hrtime.bigint();
}

/**
 * Renders a byte count with a binary-unit suffix: "1.0GiB", "16.0MiB",
 * "4.0KiB", "512B".
 */
export function humanBytes(n: number): string {
  if (n >= 1073741824) {
    return `${(n / 1073741824).toFixed(1)}GiB`;
  }
  if (n >= 1048576) {
    return `${(n / 1048576).toFixed(1)}MiB`;
  }
  if (n >= 1024) {
    return `${(n / 1024).toFixed(1)}KiB`;
  }
  return `${n}B`;
}

/** Renders a possibly-negative byte delta with an explicit sign. */
export function humanBytesSigned(n: number): string {
  return n < 0 ? `-${humanBytes(-n)}` : `+${humanBytes(n)}`;
}

/**
 * Binary MiB per second over a nanosecond window; 0 when the window is
 * unmeasured.
 */
export function mbPerSec(byteCount: number, ns: bigint): number {
  if (ns <= 0n) {
    return 0;
  }
  return byteCount / 1048576 / (Number(ns) / 1e9);
}

/**
 * Renders a throughput as "123.4MB/s" (binary MiB per second) or "n/a"
 * for an unmeasured window.
 */
export function humanRate(byteCount: number, ns: bigint): string {
  if (ns <= 0n) {
    return 'n/a';
  }
  return `${mbPerSec(byteCount, ns).toFixed(1)}MB/s`;
}

/**
 * The fractional part of a nanosecond remainder (0 .. 1e9) as ".ddd"
 * with trailing zeros removed; empty for zero.
 */
function durationFraction(fracNs: bigint): string {
  if (fracNs === 0n) {
    return '';
  }
  return '.' + fracNs.toString().padStart(9, '0').replace(/0+$/, '');
}

/**
 * Renders a duration the way Go's time.Duration prints: below one
 * second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
 * where the hour part appears when non-zero, the minute part when the
 * hour part appears or the minutes are non-zero, and the seconds carry
 * their fraction with trailing zeros removed ("5s", "5.003s", "1m0s",
 * "1m5.25s", "1h0m0s"). The caller rounds first.
 */
export function humanDuration(ns: bigint): string {
  let v = ns < 0n ? -ns : ns;
  if (v === 0n) {
    return '0s';
  }
  if (v < 1000000000n) {
    // Scale the sub-millisecond remainder to nine digits so the
    // fraction renderer sees the same shape it does for seconds.
    return `${v / 1000000n}${durationFraction((v % 1000000n) * 1000n)}ms`;
  }
  const hours = v / 3600000000000n;
  v %= 3600000000000n;
  const minutes = v / 60000000000n;
  v %= 60000000000n;
  const seconds = v / 1000000000n;
  const frac = v % 1000000000n;
  let out = hours > 0n ? `${hours}h` : '';
  if (hours > 0n || minutes > 0n) {
    out += `${minutes}m`;
  }
  return `${out}${seconds}${durationFraction(frac)}s`;
}

/** Rounds a nanosecond count to the nearest multiple of unitNs. */
export function roundNs(ns: bigint, unitNs: bigint): bigint {
  return ((ns + unitNs / 2n) / unitNs) * unitNs;
}

/**
 * Renders a 64-bit value as unsigned decimal. The seed crosses the
 * command line as an unsigned 64-bit quantity, which is wider than a
 * double carries exactly, so it is held and printed as a BigInt.
 */
export function u64Dec(v: bigint): string {
  return (v < 0n ? v + (1n << 64n) : v).toString();
}
