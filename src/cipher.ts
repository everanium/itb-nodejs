// Low-level encrypt / decrypt entry points (Single + Triple, plain +
// authenticated). Exposes the libitb encrypt / decrypt surface as
// free functions: `encrypt`, `decrypt`, `encryptTriple`,
// `decryptTriple`, plus the four authenticated `*Auth` variants.
//
// Output sizing uses the formula+retry-once pattern shared with
// `Encryptor._cipherCall`: pre-allocate
// `Math.max(131072, Math.floor(payloadLen * 5 / 4) + 131072)` (1.25×
// upper bound + 128 KiB headroom that absorbs barrier-fill expansion
// up to bf=32 plus the small-payload Triple+auth-MAC fixed overhead),
// invoke the C ABI once, and retry exactly once on
// `Status.BufferTooSmall` using the returned `outLen` as the next
// allocation size. The retry-once branch is the safety net for any
// future barrier-fill / nonce-bits combination outside the measured
// matrix.
//
// All seeds passed to one call must share the same native hash
// width. Mixing widths raises `ITBError(SeedWidthMix)`.
//
// Empty plaintext / ciphertext is rejected by libitb itself with
// `Status.EncryptFailed` (the Go-side `Encrypt128` / `Decrypt128`
// family returns `"itb: empty data"` before any work). The binding
// propagates the rejection verbatim — pass at least one byte.

function preallocCap(payloadLen: number): number {
  return Math.max(131072, Math.floor((payloadLen * 5) / 4) + 131072);
}

import { errorFromStatus } from './errors.js';
import type { MAC } from './mac.js';
import {
  ITB_Decrypt,
  ITB_Decrypt3,
  ITB_DecryptAuth,
  ITB_DecryptAuth3,
  ITB_Encrypt,
  ITB_Encrypt3,
  ITB_EncryptAuth,
  ITB_EncryptAuth3,
} from './native.js';
import type { Seed } from './seed.js';
import { Status } from './status.js';

type Handle = bigint | number;

type SingleFn = (
  noise: Handle,
  data: Handle,
  start: Handle,
  payload: Uint8Array,
  ptlen: number,
  out: Uint8Array | null,
  outCap: number,
  outLen: [number | bigint],
) => number;

type TripleFn = (
  noise: Handle,
  data1: Handle,
  data2: Handle,
  data3: Handle,
  start1: Handle,
  start2: Handle,
  start3: Handle,
  payload: Uint8Array,
  ptlen: number,
  out: Uint8Array | null,
  outCap: number,
  outLen: [number | bigint],
) => number;

type AuthSingleFn = (
  noise: Handle,
  data: Handle,
  start: Handle,
  mac: Handle,
  payload: Uint8Array,
  ptlen: number,
  out: Uint8Array | null,
  outCap: number,
  outLen: [number | bigint],
) => number;

type AuthTripleFn = (
  noise: Handle,
  data1: Handle,
  data2: Handle,
  data3: Handle,
  start1: Handle,
  start2: Handle,
  start3: Handle,
  mac: Handle,
  payload: Uint8Array,
  ptlen: number,
  out: Uint8Array | null,
  outCap: number,
  outLen: [number | bigint],
) => number;

function ensureBytes(payload: Uint8Array, label: string): void {
  if (!(payload instanceof Uint8Array)) {
    throw new TypeError(`${label} must be a Uint8Array`);
  }
}

function runSingle(
  fn: SingleFn,
  noise: Seed,
  data: Seed,
  start: Seed,
  payload: Uint8Array,
): Uint8Array {
  const cap = preallocCap(payload.length);
  let out = new Uint8Array(cap);
  const outLen: [number | bigint] = [0];
  let rc = fn(
    noise.handle, data.handle, start.handle,
    payload, payload.length,
    out, out.length, outLen,
  );
  if (rc === Status.BufferTooSmall) {
    const need = Number(outLen[0]);
    out = new Uint8Array(need);
    rc = fn(
      noise.handle, data.handle, start.handle,
      payload, payload.length,
      out, out.length, outLen,
    );
  }
  if (rc !== Status.Ok) {
    throw errorFromStatus(rc);
  }
  return out.subarray(0, Number(outLen[0]));
}

function runTriple(
  fn: TripleFn,
  noise: Seed,
  data1: Seed,
  data2: Seed,
  data3: Seed,
  start1: Seed,
  start2: Seed,
  start3: Seed,
  payload: Uint8Array,
): Uint8Array {
  const cap = preallocCap(payload.length);
  let out = new Uint8Array(cap);
  const outLen: [number | bigint] = [0];
  let rc = fn(
    noise.handle,
    data1.handle, data2.handle, data3.handle,
    start1.handle, start2.handle, start3.handle,
    payload, payload.length,
    out, out.length, outLen,
  );
  if (rc === Status.BufferTooSmall) {
    const need = Number(outLen[0]);
    out = new Uint8Array(need);
    rc = fn(
      noise.handle,
      data1.handle, data2.handle, data3.handle,
      start1.handle, start2.handle, start3.handle,
      payload, payload.length,
      out, out.length, outLen,
    );
  }
  if (rc !== Status.Ok) {
    throw errorFromStatus(rc);
  }
  return out.subarray(0, Number(outLen[0]));
}

function runAuthSingle(
  fn: AuthSingleFn,
  noise: Seed,
  data: Seed,
  start: Seed,
  mac: MAC,
  payload: Uint8Array,
): Uint8Array {
  const cap = preallocCap(payload.length);
  let out = new Uint8Array(cap);
  const outLen: [number | bigint] = [0];
  let rc = fn(
    noise.handle, data.handle, start.handle,
    mac.handle,
    payload, payload.length,
    out, out.length, outLen,
  );
  if (rc === Status.BufferTooSmall) {
    const need = Number(outLen[0]);
    out = new Uint8Array(need);
    rc = fn(
      noise.handle, data.handle, start.handle,
      mac.handle,
      payload, payload.length,
      out, out.length, outLen,
    );
  }
  if (rc !== Status.Ok) {
    throw errorFromStatus(rc);
  }
  return out.subarray(0, Number(outLen[0]));
}

function runAuthTriple(
  fn: AuthTripleFn,
  noise: Seed,
  data1: Seed,
  data2: Seed,
  data3: Seed,
  start1: Seed,
  start2: Seed,
  start3: Seed,
  mac: MAC,
  payload: Uint8Array,
): Uint8Array {
  const cap = preallocCap(payload.length);
  let out = new Uint8Array(cap);
  const outLen: [number | bigint] = [0];
  let rc = fn(
    noise.handle,
    data1.handle, data2.handle, data3.handle,
    start1.handle, start2.handle, start3.handle,
    mac.handle,
    payload, payload.length,
    out, out.length, outLen,
  );
  if (rc === Status.BufferTooSmall) {
    const need = Number(outLen[0]);
    out = new Uint8Array(need);
    rc = fn(
      noise.handle,
      data1.handle, data2.handle, data3.handle,
      start1.handle, start2.handle, start3.handle,
      mac.handle,
      payload, payload.length,
      out, out.length, outLen,
    );
  }
  if (rc !== Status.Ok) {
    throw errorFromStatus(rc);
  }
  return out.subarray(0, Number(outLen[0]));
}

/** Encrypts plaintext under the (noise, data, start) seed trio. */
export function encrypt(
  noise: Seed,
  data: Seed,
  start: Seed,
  plaintext: Uint8Array,
): Uint8Array {
  ensureBytes(plaintext, 'plaintext');
  return runSingle(ITB_Encrypt, noise, data, start, plaintext);
}

/** Decrypts ciphertext produced by `encrypt` under the same seed trio. */
export function decrypt(
  noise: Seed,
  data: Seed,
  start: Seed,
  ciphertext: Uint8Array,
): Uint8Array {
  ensureBytes(ciphertext, 'ciphertext');
  return runSingle(ITB_Decrypt, noise, data, start, ciphertext);
}

/**
 * Triple-Ouroboros encrypt over seven seeds.
 *
 * Splits plaintext across three interleaved snake payloads. The
 * on-wire ciphertext format is the same shape as `encrypt` — only
 * the internal split / interleave differs. All seven seeds must
 * share the same native hash width and be pairwise distinct
 * handles.
 */
export function encryptTriple(
  noise: Seed,
  data1: Seed, data2: Seed, data3: Seed,
  start1: Seed, start2: Seed, start3: Seed,
  plaintext: Uint8Array,
): Uint8Array {
  ensureBytes(plaintext, 'plaintext');
  return runTriple(ITB_Encrypt3, noise, data1, data2, data3, start1, start2, start3, plaintext);
}

/** Inverse of `encryptTriple`. */
export function decryptTriple(
  noise: Seed,
  data1: Seed, data2: Seed, data3: Seed,
  start1: Seed, start2: Seed, start3: Seed,
  ciphertext: Uint8Array,
): Uint8Array {
  ensureBytes(ciphertext, 'ciphertext');
  return runTriple(ITB_Decrypt3, noise, data1, data2, data3, start1, start2, start3, ciphertext);
}

/** Authenticated single-Ouroboros encrypt with MAC-Inside-Encrypt. */
export function encryptAuth(
  noise: Seed,
  data: Seed,
  start: Seed,
  mac: MAC,
  plaintext: Uint8Array,
): Uint8Array {
  ensureBytes(plaintext, 'plaintext');
  return runAuthSingle(ITB_EncryptAuth, noise, data, start, mac, plaintext);
}

/**
 * Authenticated single-Ouroboros decrypt. Raises `ITBError` with
 * code `Status.MacFailure` on tampered ciphertext / wrong MAC key.
 */
export function decryptAuth(
  noise: Seed,
  data: Seed,
  start: Seed,
  mac: MAC,
  ciphertext: Uint8Array,
): Uint8Array {
  ensureBytes(ciphertext, 'ciphertext');
  return runAuthSingle(ITB_DecryptAuth, noise, data, start, mac, ciphertext);
}

/** Authenticated Triple-Ouroboros encrypt (7 seeds + MAC). */
export function encryptAuthTriple(
  noise: Seed,
  data1: Seed, data2: Seed, data3: Seed,
  start1: Seed, start2: Seed, start3: Seed,
  mac: MAC,
  plaintext: Uint8Array,
): Uint8Array {
  ensureBytes(plaintext, 'plaintext');
  return runAuthTriple(
    ITB_EncryptAuth3,
    noise, data1, data2, data3, start1, start2, start3, mac, plaintext,
  );
}

/** Authenticated Triple-Ouroboros decrypt. */
export function decryptAuthTriple(
  noise: Seed,
  data1: Seed, data2: Seed, data3: Seed,
  start1: Seed, start2: Seed, start3: Seed,
  mac: MAC,
  ciphertext: Uint8Array,
): Uint8Array {
  ensureBytes(ciphertext, 'ciphertext');
  return runAuthTriple(
    ITB_DecryptAuth3,
    noise, data1, data2, data3, start1, start2, start3, mac, ciphertext,
  );
}
