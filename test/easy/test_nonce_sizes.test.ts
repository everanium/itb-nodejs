// Round-trip tests across all per-instance nonce-size configurations.
//
// Symmetric counterpart to bindings/python/tests/easy/test_nonce_sizes.py.
// The Encryptor surface exposes nonceBits as a per-instance setter
// (`Encryptor.setNonceBits`) rather than a process-wide config; each
// encryptor's `headerSize` and `parseChunkLen` track its own
// nonceBits state without touching the global setNonceBits /
// getNonceBits accessors. Per-instance setter — no cross-test race
// (NEXTBIND.md §11.a / §11.k pattern).

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';

import {
  Encryptor,
  ITBError,
  Status,
} from '../../src/index.js';

const NONCE_SIZES: readonly number[] = [128, 256, 512];

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

describe('test_easy_nonce_sizes', () => {
  // ─── TestEasyHeaderSizeTracksNonceBits ────────────────────────────

  test('default is 20', () => {
    using enc = new Encryptor('blake3', 1024, 'kmac256');
    assert.equal(enc.headerSize, 20);
    assert.equal(enc.nonceBits, 128);
  });

  test('dynamic header size tracks nonce bits', () => {
    for (const n of NONCE_SIZES) {
      using enc = new Encryptor('blake3', 1024, 'kmac256');
      enc.setNonceBits(n);
      assert.equal(enc.nonceBits, n, `nonce=${n}`);
      assert.equal(enc.headerSize, n / 8 + 4, `nonce=${n}`);
    }
  });

  // ─── TestEasyEncryptDecryptAcrossNonceSizes ───────────────────────

  test('single roundtrip across nonce sizes', () => {
    const plaintext = asU8(randomBytes(1024));
    for (const n of NONCE_SIZES) {
      for (const hashName of ['siphash24', 'blake3', 'blake2b512']) {
        using enc = new Encryptor(hashName, 1024, 'kmac256', 1);
        enc.setNonceBits(n);
        const ct = enc.encrypt(plaintext);
        const pt = enc.decrypt(ct);
        assert.ok(bytesEqual(pt, plaintext), `nonce=${n} hash=${hashName}`);
        // parseChunkLen must report the full chunk.
        assert.equal(
          enc.parseChunkLen(ct.subarray(0, enc.headerSize)),
          ct.length,
          `nonce=${n} hash=${hashName} parseChunkLen`,
        );
      }
    }
  });

  // ─── TestEasyTripleEncryptDecryptAcrossNonceSizes ─────────────────

  test('triple roundtrip across nonce sizes', () => {
    const plaintext = asU8(randomBytes(1024));
    for (const n of NONCE_SIZES) {
      for (const hashName of ['siphash24', 'blake3', 'blake2b512']) {
        using enc = new Encryptor(hashName, 1024, 'kmac256', 3);
        enc.setNonceBits(n);
        const ct = enc.encrypt(plaintext);
        const pt = enc.decrypt(ct);
        assert.ok(bytesEqual(pt, plaintext), `nonce=${n} hash=${hashName}`);
        assert.equal(
          enc.parseChunkLen(ct.subarray(0, enc.headerSize)),
          ct.length,
          `nonce=${n} hash=${hashName} parseChunkLen`,
        );
      }
    }
  });

  // ─── TestEasyAuthAcrossNonceSizes ─────────────────────────────────

  test('single auth across nonce sizes', () => {
    const plaintext = asU8(randomBytes(1024));
    for (const n of NONCE_SIZES) {
      for (const macName of ['kmac256', 'hmac-sha256', 'hmac-blake3']) {
        using enc = new Encryptor('blake3', 1024, macName, 1);
        enc.setNonceBits(n);
        const ct = enc.encryptAuth(plaintext);
        const pt = enc.decryptAuth(ct);
        assert.ok(bytesEqual(pt, plaintext), `nonce=${n} mac=${macName}`);

        const tampered = new Uint8Array(ct);
        const h = enc.headerSize;
        const end = Math.min(h + 256, tampered.length);
        for (let i = h; i < end; i++) tampered[i]! ^= 0x01;
        assert.throws(
          () => enc.decryptAuth(tampered),
          (err: unknown) =>
            err instanceof ITBError && err.code === Status.MacFailure,
          `nonce=${n} mac=${macName} tamper`,
        );
      }
    }
  });

  // ─── TestEasyTripleAuthAcrossNonceSizes ───────────────────────────

  test('triple auth across nonce sizes', () => {
    const plaintext = asU8(randomBytes(1024));
    for (const n of NONCE_SIZES) {
      for (const macName of ['kmac256', 'hmac-sha256', 'hmac-blake3']) {
        using enc = new Encryptor('blake3', 1024, macName, 3);
        enc.setNonceBits(n);
        const ct = enc.encryptAuth(plaintext);
        const pt = enc.decryptAuth(ct);
        assert.ok(bytesEqual(pt, plaintext), `nonce=${n} mac=${macName}`);

        const tampered = new Uint8Array(ct);
        const h = enc.headerSize;
        const end = Math.min(h + 256, tampered.length);
        for (let i = h; i < end; i++) tampered[i]! ^= 0x01;
        assert.throws(
          () => enc.decryptAuth(tampered),
          (err: unknown) =>
            err instanceof ITBError && err.code === Status.MacFailure,
          `nonce=${n} mac=${macName} tamper`,
        );
      }
    }
  });

  // ─── TestEasyTwoEncryptorsIndependentNonceBits ────────────────────

  test('two encryptors independent nonce bits', () => {
    // Per-instance nonceBits are isolated: one encryptor's
    // setNonceBits(512) does not affect another encryptor that uses
    // the default.
    const plaintext = new TextEncoder().encode('isolation test');
    using a = new Encryptor('blake3', 1024, 'kmac256');
    using b = new Encryptor('blake3', 1024, 'kmac256');
    a.setNonceBits(512);
    assert.equal(a.nonceBits, 512);
    assert.equal(a.headerSize, 68);
    assert.equal(b.nonceBits, 128);
    assert.equal(b.headerSize, 20);
    // Round-trip works on both with their own nonce sizes.
    assert.ok(bytesEqual(a.decrypt(a.encrypt(plaintext)), plaintext));
    assert.ok(bytesEqual(b.decrypt(b.encrypt(plaintext)), plaintext));
  });
});
