// Error type shared by every fallible call in the binding.

import { ITB_LastError } from './ffi.js';
import { Status, statusLabel } from './status.js';

const decoder = new TextDecoder('utf-8');

/**
 * Raised whenever libitb returns a non-OK status. `status` carries
 * the numeric code; the message appends the `ITB_LastError`
 * diagnostic captured immediately after the failing call
 * (process-global last-write-wins — under concurrent FFI use the
 * text may belong to a different call; the status code is always
 * attributable).
 */
export class ItbError extends Error {
  readonly status: number;

  constructor(status: number, detail?: string) {
    const diag = detail ?? readLastError();
    super(
      diag.length > 0
        ? `itb: status=${status} (${statusLabel(status)}): ${diag}`
        : `itb: status=${status} (${statusLabel(status)})`,
    );
    this.status = status;
    this.name = 'ItbError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Maps a raw FFI return code onto void / thrown [ItbError]. */
export function check(rc: number): void {
  if (rc !== Status.Ok) {
    throw new ItbError(rc);
  }
}

/**
 * Reads the `ITB_LastError` diagnostic (NUL-stripped). Returns the
 * empty string when no diagnostic is recorded.
 */
export function readLastError(): string {
  const need: [number | bigint] = [0];
  const rc = ITB_LastError(null, 0, need);
  const cap = Number(need[0]);
  if ((rc !== Status.Ok && rc !== Status.BufferTooSmall) || cap <= 1) {
    return '';
  }
  const buf = new Uint8Array(cap);
  const len: [number | bigint] = [0];
  if (ITB_LastError(buf, buf.length, len) !== Status.Ok) {
    return '';
  }
  const written = Number(len[0]);
  return decoder.decode(buf.subarray(0, written > 0 ? written - 1 : 0));
}
