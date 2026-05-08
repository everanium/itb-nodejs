// SipHash-2-4-focused Encryptor coverage.
//
// Symmetric counterpart to bindings/python/tests/easy/test_siphash24.py
// applied to the high-level Encryptor surface. SipHash ships only at
// -128 and is the unique primitive with no fixed PRF key —
// Encryptor.hasPRFKeys is false, prfKey() raises
// ITBError(Status.BadInput). The persistence path therefore exports
// / imports without prfKeys carried in the JSON blob; the seed
// components alone reconstruct the SipHash keying material.

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';

import { Encryptor, ITBError, Status } from '../../src/index.js';

const SIPHASH_HASHES: ReadonlyArray<readonly [string, number]> = [
  ['siphash24', 128],
];

const NONCE_SIZES: readonly number[] = [128, 256, 512];

const MAC_NAMES: readonly string[] = ['kmac256', 'hmac-sha256', 'hmac-blake3'];

function keyBitsFor(width: number): number[] {
  return [512, 1024, 2048].filter((k) => k % width === 0);
}

function rng(n: number): Uint8Array {
  return new Uint8Array(randomBytes(n));
}

describe('test_easy_siphash24', () => {
  // SipHash is the lone primitive with hasPRFKeys === false; the PRF
  // key getter rejects indexed access with Status.BadInput.
  test('no prf keys', () => {
    using enc = new Encryptor('siphash24', 1024, 'kmac256');
    assert.equal(enc.hasPRFKeys, false);
    assert.throws(
      () => enc.prfKey(0),
      (err: unknown) =>
        err instanceof ITBError && err.code === Status.BadInput,
      'siphash24 prfKey rejects with BadInput',
    );
  });

  test('roundtrip across nonce sizes', () => {
    const plaintext = rng(1024);
    for (const n of NONCE_SIZES) {
      for (const [hashName] of SIPHASH_HASHES) {
        using enc = new Encryptor(hashName, 1024, 'kmac256', 1);
        enc.setNonceBits(n);
        const ct = enc.encrypt(plaintext);
        const pt = enc.decrypt(ct);
        assert.deepEqual(pt, plaintext, `nonce=${n} hash=${hashName}`);
      }
    }
  });

  test('triple roundtrip across nonce sizes', () => {
    const plaintext = rng(1024);
    for (const n of NONCE_SIZES) {
      for (const [hashName] of SIPHASH_HASHES) {
        using enc = new Encryptor(hashName, 1024, 'kmac256', 3);
        enc.setNonceBits(n);
        const ct = enc.encrypt(plaintext);
        const pt = enc.decrypt(ct);
        assert.deepEqual(pt, plaintext, `nonce=${n} hash=${hashName}`);
      }
    }
  });

  test('auth across nonce sizes', () => {
    const plaintext = rng(1024);
    for (const n of NONCE_SIZES) {
      for (const macName of MAC_NAMES) {
        for (const [hashName] of SIPHASH_HASHES) {
          using enc = new Encryptor(hashName, 1024, macName, 1);
          enc.setNonceBits(n);
          const ct = enc.encryptAuth(plaintext);
          const pt = enc.decryptAuth(ct);
          assert.deepEqual(
            pt, plaintext,
            `nonce=${n} mac=${macName} hash=${hashName}`,
          );

          const tampered = new Uint8Array(ct);
          const h = enc.headerSize;
          const end = Math.min(h + 256, tampered.length);
          for (let i = h; i < end; i++) tampered[i]! ^= 0x01;
          assert.throws(
            () => enc.decryptAuth(tampered),
            (err: unknown) =>
              err instanceof ITBError && err.code === Status.MacFailure,
            `nonce=${n} mac=${macName} hash=${hashName} tamper`,
          );
        }
      }
    }
  });

  test('triple auth across nonce sizes', () => {
    const plaintext = rng(1024);
    for (const n of NONCE_SIZES) {
      for (const macName of MAC_NAMES) {
        for (const [hashName] of SIPHASH_HASHES) {
          using enc = new Encryptor(hashName, 1024, macName, 3);
          enc.setNonceBits(n);
          const ct = enc.encryptAuth(plaintext);
          const pt = enc.decryptAuth(ct);
          assert.deepEqual(
            pt, plaintext,
            `nonce=${n} mac=${macName} hash=${hashName}`,
          );

          const tampered = new Uint8Array(ct);
          const h = enc.headerSize;
          const end = Math.min(h + 256, tampered.length);
          for (let i = h; i < end; i++) tampered[i]! ^= 0x01;
          assert.throws(
            () => enc.decryptAuth(tampered),
            (err: unknown) =>
              err instanceof ITBError && err.code === Status.MacFailure,
            `nonce=${n} mac=${macName} hash=${hashName} tamper`,
          );
        }
      }
    }
  });

  // Persistence sweep without prfKeys: SipHash's seed components alone
  // reconstruct the keying material. The exported blob omits prfKeys,
  // and importState on a fresh encryptor restores the seeds without
  // consulting them.
  test('persistence across nonce sizes', () => {
    const tail = rng(1024);
    const head = new TextEncoder().encode('persistence payload ');
    const plaintext = new Uint8Array(head.length + tail.length);
    plaintext.set(head, 0);
    plaintext.set(tail, head.length);

    for (const [hashName, width] of SIPHASH_HASHES) {
      for (const keyBits of keyBitsFor(width)) {
        for (const n of NONCE_SIZES) {
          const src = new Encryptor(hashName, keyBits, 'kmac256', 1);
          let blob: Uint8Array;
          let ct: Uint8Array;
          try {
            src.setNonceBits(n);
            assert.equal(src.hasPRFKeys, false);
            assert.equal(
              src.seedComponents(0).length * 64,
              keyBits,
              `hash=${hashName} key_bits=${keyBits} nonce=${n} comps`,
            );
            blob = src.exportState();
            ct = src.encrypt(plaintext);
          } finally {
            src.free();
          }

          const dst = new Encryptor(hashName, keyBits, 'kmac256', 1);
          try {
            dst.setNonceBits(n);
            dst.importState(blob);
            const pt = dst.decrypt(ct);
            assert.deepEqual(
              pt, plaintext,
              `hash=${hashName} key_bits=${keyBits} nonce=${n} day2`,
            );
          } finally {
            dst.free();
          }
        }
      }
    }
  });

  test('roundtrip sizes', () => {
    const SIZES: readonly number[] = [1, 17, 4096, 65536, 1 << 20];
    for (const [hashName] of SIPHASH_HASHES) {
      for (const n of NONCE_SIZES) {
        for (const sz of SIZES) {
          const plaintext = rng(sz);
          using enc = new Encryptor(hashName, 1024, 'kmac256');
          enc.setNonceBits(n);
          const ct = enc.encrypt(plaintext);
          const pt = enc.decrypt(ct);
          assert.deepEqual(
            pt, plaintext,
            `hash=${hashName} nonce=${n} size=${sz}`,
          );
        }
      }
    }
  });
});
