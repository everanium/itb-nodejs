// Process-wide Go runtime knobs plus the library version strings.

import { ITB_SetGCPercent, ITB_SetMemoryLimit, ITB_Version } from './ffi.js';
import { ItbError } from './error.js';
import { Status } from './status.js';

/** Binding package version, reported by the eitb CLI. */
export const bindingVersion = '0.4.1';

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

/** Returns the libitb library version string. */
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
