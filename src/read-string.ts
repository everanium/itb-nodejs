// Common idiom for size-out-param string accessors.
//
// libitb's string getters follow a probe-then-read protocol: the
// first call with `cap=0` returns the required buffer size in
// `outLen` (including the trailing NUL byte) and `Status.BufferTooSmall`;
// the second call with the allocated buffer fills it.
//
// `outLen` reports the byte count INCLUDING the terminator, so the
// caller decodes UTF-8 over `[0, outLen-1)` to strip the trailing
// 0x00. Empty strings are represented as `outLen == 0`; the special
// case is handled here.

import { Status } from './status.js';

const decoder = new TextDecoder('utf-8');

export type SizeProbeFn = (
  out: Uint8Array | null,
  capBytes: number | bigint,
  outLen: [number | bigint],
) => number;

export function readString(call: SizeProbeFn): { rc: number; value: string } {
  const probeLen: [number | bigint] = [0];
  const rc1 = call(null, 0, probeLen);
  if (rc1 !== Status.Ok && rc1 !== Status.BufferTooSmall) {
    return { rc: rc1, value: '' };
  }
  const cap = Number(probeLen[0]);
  if (cap <= 1) {
    return { rc: Status.Ok, value: '' };
  }
  const buf = new Uint8Array(cap);
  const filledLen: [number | bigint] = [0];
  const rc2 = call(buf, cap, filledLen);
  if (rc2 !== Status.Ok) {
    return { rc: rc2, value: '' };
  }
  const written = Number(filledLen[0]);
  const usable = written > 0 ? written - 1 : 0;
  return { rc: Status.Ok, value: decoder.decode(buf.subarray(0, usable)) };
}
