// BLAKE3-focused Encryptor coverage.
//
// Symmetric counterpart to bindings/python/tests/easy/test_blake3.py
// applied to the high-level Encryptor surface. BLAKE3 ships at a
// single width (-256) — there is no -512 BLAKE3 in the registry — so
// this file iterates the single primitive across the same axes
// test_blake2{b,s} cover.
//
// Persistence rides on Encryptor.exportState / Encryptor.importState
// (JSON blob, single round-trip). The blob captures the full
// encryptor state (PRF keys for every slot, MAC key, optional
// dedicated lockSeed material) so the day-2 decrypt path exercises
// the full restore.

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';

import { Encryptor, ITBError, Status } from '../../src/index.js';

// (hash, ITB_seed_width) — BLAKE3 ships only at -256.
const BLAKE3_HASHES: ReadonlyArray<readonly [string, number]> = [
  ['blake3', 256],
];

const EXPECTED_KEY_LEN: Record<string, number> = {
  blake3: 32,
};

const NONCE_SIZES: readonly number[] = [128, 256, 512];

const MAC_NAMES: readonly string[] = ['kmac256', 'hmac-sha256', 'hmac-blake3'];

function keyBitsFor(width: number): number[] {
  return [512, 1024, 2048].filter((k) => k % width === 0);
}

function rng(n: number): Uint8Array {
  return new Uint8Array(randomBytes(n));
}

describe('test_easy_blake3', () => {
  // Single Ouroboros round-trip via Encryptor over blake3 × all three
  // nonce sizes. setNonceBits is per-instance on the Encryptor surface,
  // so the brackets that bracket the legacy process-wide setter become
  // a single setter call on the encryptor after construction.
  test('roundtrip across nonce sizes', () => {
    const plaintext = rng(1024);
    for (const n of NONCE_SIZES) {
      for (const [hashName] of BLAKE3_HASHES) {
        using enc = new Encryptor(hashName, 1024, 'kmac256', 1);
        enc.setNonceBits(n);
        const ct = enc.encrypt(plaintext);
        const pt = enc.decrypt(ct);
        assert.deepEqual(pt, plaintext, `nonce=${n} hash=${hashName}`);
      }
    }
  });

  // Triple Ouroboros (mode=3) round-trip via Encryptor.
  test('triple roundtrip across nonce sizes', () => {
    const plaintext = rng(1024);
    for (const n of NONCE_SIZES) {
      for (const [hashName] of BLAKE3_HASHES) {
        using enc = new Encryptor(hashName, 1024, 'kmac256', 3);
        enc.setNonceBits(n);
        const ct = enc.encrypt(plaintext);
        const pt = enc.decrypt(ct);
        assert.deepEqual(pt, plaintext, `nonce=${n} hash=${hashName}`);
      }
    }
  });

  // Single Ouroboros + Auth + tamper rejection via Encryptor. Tamper
  // region starts past the chunk header (nonce + 2-byte width + 2-byte
  // height) so the body bytes get bit-flipped, not the header
  // dimensions. Encryptor.headerSize is per-instance and tracks this
  // encryptor's nonceBits, so the header offset reflects the
  // setNonceBits override automatically.
  test('auth across nonce sizes', () => {
    const plaintext = rng(1024);
    for (const n of NONCE_SIZES) {
      for (const macName of MAC_NAMES) {
        for (const [hashName] of BLAKE3_HASHES) {
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

  // Triple Ouroboros (mode=3) + Auth + tamper rejection. Header size
  // computed per-instance from the encryptor's nonceBits.
  test('triple auth across nonce sizes', () => {
    const plaintext = rng(1024);
    for (const n of NONCE_SIZES) {
      for (const macName of MAC_NAMES) {
        for (const [hashName] of BLAKE3_HASHES) {
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

  // Encrypt → export blob → free encryptor → fresh encryptor → import
  // blob → decrypt → verify plaintext bit-identical. The encryptor's
  // setNonceBits state is per-instance and not carried in the blob
  // (deployment config), so the receiver mirrors it via a matching
  // setNonceBits call.
  test('persistence across nonce sizes', () => {
    const tail = rng(1024);
    const head = new TextEncoder().encode('persistence payload ');
    const plaintext = new Uint8Array(head.length + tail.length);
    plaintext.set(head, 0);
    plaintext.set(tail, head.length);

    for (const [hashName, width] of BLAKE3_HASHES) {
      for (const keyBits of keyBitsFor(width)) {
        for (const n of NONCE_SIZES) {
          // Day 1.
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

          // Day 2.
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

  // Round-trip across plaintext sizes that span multiple chunk
  // boundaries. ITB's processChunk batches 4 pixels per BatchHash
  // call; trailing partial batches must dispatch via the per-lane
  // fallback.
  test('roundtrip sizes', () => {
    const SIZES: readonly number[] = [1, 17, 4096, 65536, 1 << 20];
    for (const [hashName] of BLAKE3_HASHES) {
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
