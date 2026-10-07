// Process-wide Go runtime knobs plus the library version strings.

import {
  ITB_DRBGAutoTier,
  ITB_PoolStats,
  ITB_PoolStatsLen,
  ITB_SetGCPercent,
  ITB_SetGOMAXPROCS,
  ITB_SetMemoryLimit,
  ITB_Version,
  ITB_WriteHeapProfile,
} from './ffi.js';
import { ItbError, check } from './error.js';
import { Status } from './status.js';

/** Binding package version, reported by the eitb CLI. */
export const bindingVersion = '0.5.1';

const decoder = new TextDecoder('utf-8');

/**
 * Sets the Go runtime's soft heap limit in bytes and returns the
 * previous limit. A negative value queries without changing. BigInt
 * in / out — the limit is a full int64.
 */
export function setMemoryLimit(bytes: number | bigint): bigint {
  return BigInt(ITB_SetMemoryLimit(bytes));
}

/**
 * Sets the Go GC trigger percentage and returns the previous value.
 * A negative value queries without changing.
 */
export function setGCPercent(pct: number): number {
  return ITB_SetGCPercent(pct | 0);
}

/**
 * Sets the Go runtime's GOMAXPROCS — the number of OS threads
 * executing Go code simultaneously inside the library — and returns
 * the previous value. `n <= 0` queries without changing.
 */
export function setGOMAXPROCS(n: number): number {
  return ITB_SetGOMAXPROCS(n | 0);
}

/**
 * Writes a Go runtime heap profile (pprof format, readable with
 * `go tool pprof`) to `path` after one forced garbage collection. An
 * empty path falls back to the `ITB_MEMPROFILE` environment variable;
 * a file-system failure throws [ItbError] carrying the os diagnostic.
 */
export function writeHeapProfile(path: string): void {
  check(ITB_WriteHeapProfile(path));
}

/**
 * The number of `int64` slots [poolStats] fills. A caller sizes its
 * buffer from this value rather than a constant: the slot count grows
 * if the library adds a pool.
 */
export function poolStatsLen(): number {
  return ITB_PoolStatsLen();
}

/**
 * The library's pool hit / miss counters, every one a monotonically
 * increasing total since library load (a consumer differences two
 * snapshots).
 *
 * Slot layout, with `T` the hash-array pool tier count in slot 0: for
 * tier `i` the five slots at `1 + 5*i` hold the starter width (`0` for
 * an unused tier), checkouts, constructor misses, regrow replacements
 * and bytes allocated by misses + regrows; the four slots at `1 + 5*T`
 * hold the scratch byte pool's get / new / regrow / regrow-bytes and
 * the four after them the parallax chunk pool's, in the same order.
 */
export function poolStats(): bigint[] {
  // The capacity this entry takes is counted in int64 slots, not in
  // bytes, so the array is allocated by element count and the same
  // count is handed over.
  const cap = ITB_PoolStatsLen();
  if (cap <= 0) {
    return [];
  }
  const buf = new BigInt64Array(cap);
  const len: [number | bigint] = [0];
  check(ITB_PoolStats(buf, cap, len));
  const n = Math.min(Number(len[0]), cap);
  return Array.from(buf.subarray(0, n));
}

/** Returns the libitb3 library version string. */
export function version(): string {
  const need: [number | bigint] = [0];
  const rc1 = ITB_Version(null, 0, need);
  const cap = Number(need[0]);
  if (rc1 !== Status.Ok && rc1 !== Status.BufferTooSmall) {
    throw new ItbError(rc1);
  }
  if (cap <= 1) {
    return '';
  }
  const buf = new Uint8Array(cap);
  const len: [number | bigint] = [0];
  const rc2 = ITB_Version(buf, buf.length, len);
  if (rc2 !== Status.Ok) {
    throw new ItbError(rc2);
  }
  const written = Number(len[0]);
  return decoder.decode(buf.subarray(0, written > 0 ? written - 1 : 0));
}

/**
 * Returns the fill cipher the auto DRBG tier selected on this host
 * ("aes-256-ctr" or "chacha20"): the tier a Pipeline uses when its
 * drbg option is empty, resolved per host and recorded in no blob.
 */
export function drbgAutoTier(): string {
  const need: [number | bigint] = [0];
  const rc1 = ITB_DRBGAutoTier(null, 0, need);
  const cap = Number(need[0]);
  if (rc1 !== Status.Ok && rc1 !== Status.BufferTooSmall) {
    throw new ItbError(rc1);
  }
  if (cap <= 1) {
    return '';
  }
  const buf = new Uint8Array(cap);
  const len: [number | bigint] = [0];
  const rc2 = ITB_DRBGAutoTier(buf, buf.length, len);
  if (rc2 !== Status.Ok) {
    throw new ItbError(rc2);
  }
  const written = Number(len[0]);
  return decoder.decode(buf.subarray(0, written > 0 ? written - 1 : 0));
}
