// End-to-end Encryptor tests for Authenticated Encryption.
//
// Symmetric counterpart to bindings/python/tests/easy/test_auth.py.
// Same matrix (3 MACs x 3 hash widths x {Single, Triple} round trip
// plus tamper rejection) applied to the high-level Encryptor surface.
//
// The cross-MAC rejection cases (different MAC primitive on encrypt
// vs decrypt) are realised here by Export-ing the sender's state and
// Import-ing it into a receiver constructed with the wrong MAC
// primitive — but Import enforces matching primitive / keyBits /
// mode / mac and refuses the swap with ITBEasyMismatchError carrying
// `field === "mac"`, so the cross-MAC case becomes a structural-
// rejection test instead of a runtime MAC verification miss. The
// same security guarantee is covered by tampering the MAC bytes
// inside the ciphertext (header-adjacent flip).

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';

import {
  Encryptor,
  ITBEasyMismatchError,
  ITBError,
  Status,
} from '../../src/index.js';

const CANONICAL_MACS: readonly string[] = [
  'kmac256',
  'hmac-sha256',
  'hmac-blake3',
];

const HASH_BY_WIDTH: ReadonlyArray<readonly [string, number]> = [
  ['siphash24', 128],
  ['blake3', 256],
  ['blake2b512', 512],
];

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

describe('test_easy_auth', () => {
  // ─── TestAuthEasyRoundtrip ────────────────────────────────────────

  test('all macs all widths single', () => {
    const plaintext = asU8(randomBytes(4096));
    for (const macName of CANONICAL_MACS) {
      for (const [hashName] of HASH_BY_WIDTH) {
        using enc = new Encryptor(hashName, 1024, macName, 1);
        const ct = enc.encryptAuth(plaintext);
        const pt = enc.decryptAuth(ct);
        assert.ok(
          bytesEqual(pt, plaintext),
          `mac=${macName} hash=${hashName}`,
        );

        // Tamper: flip 256 bytes past the dynamic header.
        const tampered = new Uint8Array(ct);
        const h = enc.headerSize;
        const end = Math.min(h + 256, tampered.length);
        for (let i = h; i < end; i++) tampered[i]! ^= 0x01;
        assert.throws(
          () => enc.decryptAuth(tampered),
          (err: unknown) =>
            err instanceof ITBError && err.code === Status.MacFailure,
          `mac=${macName} hash=${hashName} tamper`,
        );
      }
    }
  });

  // ─── TestAuthEasyTripleRoundtrip ──────────────────────────────────

  test('all macs all widths triple', () => {
    const plaintext = asU8(randomBytes(4096));
    for (const macName of CANONICAL_MACS) {
      for (const [hashName] of HASH_BY_WIDTH) {
        using enc = new Encryptor(hashName, 1024, macName, 3);
        const ct = enc.encryptAuth(plaintext);
        const pt = enc.decryptAuth(ct);
        assert.ok(
          bytesEqual(pt, plaintext),
          `mac=${macName} hash=${hashName}`,
        );

        const tampered = new Uint8Array(ct);
        const h = enc.headerSize;
        const end = Math.min(h + 256, tampered.length);
        for (let i = h; i < end; i++) tampered[i]! ^= 0x01;
        assert.throws(
          () => enc.decryptAuth(tampered),
          (err: unknown) =>
            err instanceof ITBError && err.code === Status.MacFailure,
          `mac=${macName} hash=${hashName} tamper`,
        );
      }
    }
  });

  // ─── TestAuthEasyCrossMACRejection ────────────────────────────────

  test('cross mac different primitive', () => {
    // Cross-MAC rejection at the structural level: an exported state
    // blob carries the encryptor's MAC primitive name; Import on a
    // receiver constructed with a different MAC primitive surfaces
    // ITBEasyMismatchError with field='mac' rather than a runtime
    // MAC verification miss.
    let blob: Uint8Array;
    {
      using src = new Encryptor('blake3', 1024, 'kmac256', 1);
      blob = src.exportState();
    }
    using dst = new Encryptor('blake3', 1024, 'hmac-sha256', 1);
    assert.throws(
      () => dst.importState(blob),
      (err: unknown) =>
        err instanceof ITBEasyMismatchError &&
        err.code === Status.EasyMismatch &&
        err.field === 'mac',
    );
  });

  // ─── TestAuthEasyDifferentKeyRejection ────────────────────────────

  test('same primitive different key mac failure', () => {
    // Same-primitive different-key MAC failure at the runtime level.
    // Encrypt with one encryptor, attempt decrypt with a separately
    // constructed encryptor (same primitive / keyBits / mode / mac
    // but with its own random MAC key) — STATUS_MAC_FAILURE rather
    // than a corrupted plaintext.
    const plaintext = new TextEncoder().encode('authenticated payload');
    using enc1 = new Encryptor('blake3', 1024, 'hmac-sha256', 1);
    using enc2 = new Encryptor('blake3', 1024, 'hmac-sha256', 1);
    // Day 1: encrypt with enc1's seeds and MAC key.
    enc1.exportState();
    const ct = enc1.encryptAuth(plaintext);
    // Day 2: enc2 has its own (different) seed / MAC keys.
    assert.throws(
      () => enc2.decryptAuth(ct),
      (err: unknown) =>
        err instanceof ITBError && err.code === Status.MacFailure,
    );
  });
});
