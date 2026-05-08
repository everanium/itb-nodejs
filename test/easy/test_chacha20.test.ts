// ChaCha20-focused Encryptor coverage.
//
// Symmetric counterpart to bindings/python/tests/easy/test_chacha20.py
// applied to the high-level Encryptor surface. ChaCha20 ships only at
// -256.

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';

import { Encryptor, ITBError, Status } from '../../src/index.js';

const CHACHA20_HASHES: ReadonlyArray<readonly [string, number]> = [
  ['chacha20', 256],
];

const EXPECTED_KEY_LEN: Record<string, number> = {
  chacha20: 32,
};

const NONCE_SIZES: readonly number[] = [128, 256, 512];

const MAC_NAMES: readonly string[] = ['kmac256', 'hmac-sha256', 'hmac-blake3'];

function keyBitsFor(width: number): number[] {
  return [512, 1024, 2048].filter((k) => k % width === 0);
}

function rng(n: number): Uint8Array {
  return new Uint8Array(randomBytes(n));
}

describe('test_easy_chacha20', () => {
  test('roundtrip across nonce sizes', () => {
    const plaintext = rng(1024);
    for (const n of NONCE_SIZES) {
      for (const [hashName] of CHACHA20_HASHES) {
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
      for (const [hashName] of CHACHA20_HASHES) {
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
        for (const [hashName] of CHACHA20_HASHES) {
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
        for (const [hashName] of CHACHA20_HASHES) {
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

  test('persistence across nonce sizes', () => {
    const tail = rng(1024);
    const head = new TextEncoder().encode('persistence payload ');
    const plaintext = new Uint8Array(head.length + tail.length);
    plaintext.set(head, 0);
    plaintext.set(tail, head.length);

    for (const [hashName, width] of CHACHA20_HASHES) {
      for (const keyBits of keyBitsFor(width)) {
        for (const n of NONCE_SIZES) {
          const src = new Encryptor(hashName, keyBits, 'kmac256', 1);
          let blob: Uint8Array;
          let ct: Uint8Array;
          try {
            src.setNonceBits(n);
            assert.equal(
              src.prfKey(0).length,
              EXPECTED_KEY_LEN[hashName],
              `hash=${hashName} key_bits=${keyBits} nonce=${n} prf-key-len`,
            );
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
    for (const [hashName] of CHACHA20_HASHES) {
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
