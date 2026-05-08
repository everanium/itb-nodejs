// Streaming-style use of the high-level Encryptor surface.
//
// Streaming over the Encryptor surface lives entirely on the binding
// side (no separate StreamEncryptor / StreamDecryptor classes for
// the Easy API): the consumer slices the plaintext into chunks of
// the desired size and calls `Encryptor.encrypt` per chunk; the
// decrypt side walks the concatenated chunk stream by reading
// `Encryptor.headerSize` bytes, calling `Encryptor.parseChunkLen`,
// reading the remaining body, and feeding the full chunk to
// `Encryptor.decrypt`.
//
// Triple-Ouroboros (mode=3) and non-default nonce-bits configurations
// are covered explicitly so a regression in the per-instance
// `headerSize` / `parseChunkLen` path or in the seed plumbing
// surfaces here.

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';

import {
  Encryptor,
  ITBError,
  Status,
} from '../../src/index.js';

const SMALL_CHUNK = 4096;

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function asU8(buf: Uint8Array | Buffer): Uint8Array {
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength).slice();
}

/**
 * Encrypts `plaintext` chunk-by-chunk through `enc.encrypt` and
 * returns the concatenated ciphertext stream. Mirrors the Python
 * `_stream_encrypt` helper.
 */
function streamEncrypt(
  enc: Encryptor,
  plaintext: Uint8Array,
  chunkSize: number,
): Uint8Array {
  const parts: Uint8Array[] = [];
  let total = 0;
  let i = 0;
  while (i < plaintext.length) {
    const end = Math.min(i + chunkSize, plaintext.length);
    const ct = enc.encrypt(plaintext.subarray(i, end));
    parts.push(ct);
    total += ct.length;
    i = end;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * Drains the concatenated ciphertext stream chunk-by-chunk and
 * returns the recovered plaintext. Throws on a trailing incomplete
 * chunk so the test harness can assert the plausible-failure
 * contract.
 */
function streamDecrypt(enc: Encryptor, ciphertext: Uint8Array): Uint8Array {
  const out: Uint8Array[] = [];
  let outTotal = 0;
  let accumulator = new Uint8Array(0);
  const headerSize = enc.headerSize;
  let feedOff = 0;

  while (feedOff < ciphertext.length) {
    const end = Math.min(feedOff + SMALL_CHUNK, ciphertext.length);
    const slice = ciphertext.subarray(feedOff, end);
    const merged = new Uint8Array(accumulator.length + slice.length);
    merged.set(accumulator, 0);
    merged.set(slice, accumulator.length);
    accumulator = merged;
    feedOff = end;
    // Drain any complete chunks already in the accumulator.
    for (;;) {
      if (accumulator.length < headerSize) break;
      const chunkLen = enc.parseChunkLen(accumulator.subarray(0, headerSize));
      if (accumulator.length < chunkLen) break;
      const chunk = accumulator.subarray(0, chunkLen);
      const pt = enc.decrypt(chunk);
      out.push(pt);
      outTotal += pt.length;
      accumulator = accumulator.subarray(chunkLen);
    }
  }
  if (accumulator.length > 0) {
    throw new Error(
      `trailing ${accumulator.length} bytes do not form a complete chunk`,
    );
  }
  const result = new Uint8Array(outTotal);
  let off = 0;
  for (const p of out) {
    result.set(p, off);
    off += p.length;
  }
  return result;
}

describe('test_easy_streams', () => {
  // ─── TestEasyStreamRoundtripDefaultNonce ──────────────────────────

  test('class roundtrip default nonce single', () => {
    const plaintext = asU8(randomBytes(SMALL_CHUNK * 5 + 17));
    using enc = new Encryptor('blake3', 1024, 'kmac256', 1);
    const ct = streamEncrypt(enc, plaintext, SMALL_CHUNK);
    const pt = streamDecrypt(enc, ct);
    assert.ok(bytesEqual(pt, plaintext));
  });

  // ─── TestEasyStreamRoundtripNonDefaultNonce ───────────────────────

  test('class roundtrip non default nonce single', () => {
    const plaintext = asU8(randomBytes(SMALL_CHUNK * 3 + 100));
    for (const n of [256, 512]) {
      using enc = new Encryptor('blake3', 1024, 'kmac256', 1);
      enc.setNonceBits(n);
      const ct = streamEncrypt(enc, plaintext, SMALL_CHUNK);
      const pt = streamDecrypt(enc, ct);
      assert.ok(bytesEqual(pt, plaintext), `nonce=${n}`);
    }
  });

  // ─── TestEasyStreamTripleRoundtripDefaultNonce ────────────────────

  test('class roundtrip default nonce triple', () => {
    const plaintext = asU8(randomBytes(SMALL_CHUNK * 4 + 33));
    using enc = new Encryptor('blake3', 1024, 'kmac256', 3);
    const ct = streamEncrypt(enc, plaintext, SMALL_CHUNK);
    const pt = streamDecrypt(enc, ct);
    assert.ok(bytesEqual(pt, plaintext));
  });

  // ─── TestEasyStreamTripleRoundtripNonDefaultNonce ─────────────────

  test('class roundtrip non default nonce triple', () => {
    const plaintext = asU8(randomBytes(SMALL_CHUNK * 3));
    for (const n of [256, 512]) {
      using enc = new Encryptor('blake3', 1024, 'kmac256', 3);
      enc.setNonceBits(n);
      const ct = streamEncrypt(enc, plaintext, SMALL_CHUNK);
      const pt = streamDecrypt(enc, ct);
      assert.ok(bytesEqual(pt, plaintext), `nonce=${n}`);
    }
  });

  // ─── TestEasyStreamErrors ─────────────────────────────────────────

  test('partial chunk raises', () => {
    // Feeding only a partial chunk to the streaming decoder
    // surfaces an Error on close — same plausible-failure contract
    // as the lower-level StreamDecryptor.
    const plaintext = new Uint8Array(100).fill(0x78); // 'x'
    using enc = new Encryptor('blake3', 1024, 'kmac256', 1);
    const ct = streamEncrypt(enc, plaintext, SMALL_CHUNK);
    // Feed only 30 bytes — header complete (>= 20) but body
    // truncated. The drain loop must reject the trailing
    // incomplete chunk on close.
    assert.throws(
      () => streamDecrypt(enc, ct.subarray(0, 30)),
      (err: unknown) => err instanceof Error && /trailing/.test(err.message),
    );
  });

  test('parse chunk len short buffer', () => {
    using enc = new Encryptor('blake3', 1024, 'kmac256');
    const buf = new Uint8Array(enc.headerSize - 1);
    assert.throws(
      () => enc.parseChunkLen(buf),
      (err: unknown) =>
        err instanceof ITBError && err.code === Status.BadInput,
    );
  });

  test('parse chunk len zero dim', () => {
    using enc = new Encryptor('blake3', 1024, 'kmac256');
    // headerSize bytes, but width === 0.
    const hdr = new Uint8Array(enc.headerSize);
    assert.throws(
      () => enc.parseChunkLen(hdr),
      (err: unknown) => err instanceof ITBError,
    );
  });
});
