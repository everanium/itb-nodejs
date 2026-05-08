// Round-trip tests across all nonce-size configurations.
//
// Mirrors bindings/python/tests/test_nonce_sizes.py. ITB exposes a
// runtime-configurable nonce size (`setNonceBits`) that takes one of
// {128, 256, 512}. The on-the-wire chunk header therefore varies
// between 20, 36, and 68 bytes; every consumer that walks ciphertext
// on the byte level (chunk parsers, tampering tests, streaming
// decoders) must use `headerSize()` rather than a hardcoded constant.
//
// This file mutates `setNonceBits`, a process-global libitb atomic.
// node:test runs each test file in its own child process, so
// cross-file races against other test binaries do not occur. Each
// test wraps its mutation in save/restore so subsequent tests in
// this file run unaffected.

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';

import {
  decrypt,
  decryptAuth,
  decryptAuthTriple,
  decryptTriple,
  encrypt,
  encryptAuth,
  encryptAuthTriple,
  encryptTriple,
  getNonceBits,
  headerSize,
  ITBError,
  MAC,
  parseChunkLen,
  Seed,
  setNonceBits,
  Status,
} from '../src/index.js';

const NONCE_SIZES: readonly number[] = [128, 256, 512];
const HASHES: readonly string[] = ['siphash24', 'blake3', 'blake2b512'];
const MAC_NAMES: readonly string[] = ['kmac256', 'hmac-sha256', 'hmac-blake3'];

function withNonceBits<T>(n: number, fn: () => T): T {
  const orig = getNonceBits();
  setNonceBits(n);
  try {
    return fn();
  } finally {
    setNonceBits(orig);
  }
}

function tokenBytes(n: number): Uint8Array {
  return new Uint8Array(randomBytes(n));
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

describe('test_nonce_sizes', () => {
  test('default header size is 20', () => {
    const orig = getNonceBits();
    try {
      setNonceBits(128);
      assert.equal(headerSize(), 20);
      assert.equal(getNonceBits(), 128);
    } finally {
      setNonceBits(orig);
    }
  });

  test('header size dynamic', () => {
    for (const n of NONCE_SIZES) {
      withNonceBits(n, () => {
        assert.equal(headerSize(), n / 8 + 4, `nonce=${n}`);
      });
    }
  });

  test('encrypt decrypt across nonce sizes', () => {
    const plaintext = tokenBytes(1024);
    for (const n of NONCE_SIZES) {
      for (const hashName of HASHES) {
        withNonceBits(n, () => {
          const seeds: Seed[] = [];
          try {
            for (let i = 0; i < 3; i++) seeds.push(new Seed(hashName, 1024));
            const [s0, s1, s2] = seeds as [Seed, Seed, Seed];
            const ct = encrypt(s0, s1, s2, plaintext);
            const pt = decrypt(s0, s1, s2, ct);
            assert.ok(
              bytesEqual(pt, plaintext),
              `nonce=${n} hash=${hashName}`,
            );
            assert.equal(
              parseChunkLen(ct.subarray(0, headerSize())),
              ct.length,
              `nonce=${n} hash=${hashName} chunk-len`,
            );
          } finally {
            for (const s of seeds) s.free();
          }
        });
      }
    }
  });

  test('triple encrypt decrypt across nonce sizes', () => {
    const plaintext = tokenBytes(1024);
    for (const n of NONCE_SIZES) {
      for (const hashName of HASHES) {
        withNonceBits(n, () => {
          const seeds: Seed[] = [];
          try {
            for (let i = 0; i < 7; i++) seeds.push(new Seed(hashName, 1024));
            const [s0, s1, s2, s3, s4, s5, s6] = seeds as [
              Seed, Seed, Seed, Seed, Seed, Seed, Seed,
            ];
            const ct = encryptTriple(s0, s1, s2, s3, s4, s5, s6, plaintext);
            const pt = decryptTriple(s0, s1, s2, s3, s4, s5, s6, ct);
            assert.ok(
              bytesEqual(pt, plaintext),
              `nonce=${n} hash=${hashName}`,
            );
          } finally {
            for (const s of seeds) s.free();
          }
        });
      }
    }
  });

  test('auth across nonce sizes', () => {
    const plaintext = tokenBytes(1024);
    for (const n of NONCE_SIZES) {
      for (const macName of MAC_NAMES) {
        withNonceBits(n, () => {
          using mac = new MAC(macName, tokenBytes(32));
          const seeds: Seed[] = [];
          try {
            for (let i = 0; i < 3; i++) seeds.push(new Seed('blake3', 1024));
            const [s0, s1, s2] = seeds as [Seed, Seed, Seed];
            const ct = encryptAuth(s0, s1, s2, mac, plaintext);
            const pt = decryptAuth(s0, s1, s2, mac, ct);
            assert.ok(
              bytesEqual(pt, plaintext),
              `nonce=${n} mac=${macName}`,
            );

            const tampered = new Uint8Array(ct);
            const h = headerSize();
            const end = Math.min(h + 256, tampered.length);
            for (let i = h; i < end; i++) tampered[i]! ^= 0x01;
            assert.throws(
              () => decryptAuth(s0, s1, s2, mac, tampered),
              (err: unknown) =>
                err instanceof ITBError && err.code === Status.MacFailure,
              `nonce=${n} mac=${macName} tamper`,
            );
          } finally {
            for (const s of seeds) s.free();
          }
        });
      }
    }
  });

  test('triple auth across nonce sizes', () => {
    const plaintext = tokenBytes(1024);
    for (const n of NONCE_SIZES) {
      for (const macName of MAC_NAMES) {
        withNonceBits(n, () => {
          using mac = new MAC(macName, tokenBytes(32));
          const seeds: Seed[] = [];
          try {
            for (let i = 0; i < 7; i++) seeds.push(new Seed('blake3', 1024));
            const [s0, s1, s2, s3, s4, s5, s6] = seeds as [
              Seed, Seed, Seed, Seed, Seed, Seed, Seed,
            ];
            const ct = encryptAuthTriple(s0, s1, s2, s3, s4, s5, s6, mac, plaintext);
            const pt = decryptAuthTriple(s0, s1, s2, s3, s4, s5, s6, mac, ct);
            assert.ok(
              bytesEqual(pt, plaintext),
              `nonce=${n} mac=${macName}`,
            );

            const tampered = new Uint8Array(ct);
            const h = headerSize();
            const end = Math.min(h + 256, tampered.length);
            for (let i = h; i < end; i++) tampered[i]! ^= 0x01;
            assert.throws(
              () => decryptAuthTriple(s0, s1, s2, s3, s4, s5, s6, mac, tampered),
              (err: unknown) =>
                err instanceof ITBError && err.code === Status.MacFailure,
              `nonce=${n} mac=${macName} tamper`,
            );
          } finally {
            for (const s of seeds) s.free();
          }
        });
      }
    }
  });
});
