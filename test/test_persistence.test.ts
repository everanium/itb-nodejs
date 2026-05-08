// Cross-process persistence round-trip tests for the Node.js binding.
//
// Mirrors bindings/python/tests/test_persistence.py — exercises the
// `Seed.components` / `Seed.hashKey` / `Seed.fromComponents` surface
// across every primitive in the registry × the three ITB key-bit
// widths (512 / 1024 / 2048) that are valid for each native hash
// width.
//
// Without both `components` and `hashKey` captured at encrypt-side
// and re-supplied at decrypt-side, the seed state cannot be
// reconstructed and the ciphertext is unreadable.

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';

import {
  decrypt,
  encrypt,
  ITBError,
  Seed,
} from '../src/index.js';

const CANONICAL_HASHES: ReadonlyArray<readonly [string, number]> = [
  ['areion256', 256],
  ['areion512', 512],
  ['siphash24', 128],
  ['aescmac', 128],
  ['blake2b256', 256],
  ['blake2b512', 512],
  ['blake2s', 256],
  ['blake3', 256],
  ['chacha20', 256],
];

const EXPECTED_HASH_KEY_LEN: Record<string, number> = {
  areion256: 32,
  areion512: 64,
  siphash24: 0, // no internal fixed key — keyed by seed components
  aescmac: 16,
  blake2b256: 32,
  blake2b512: 64,
  blake2s: 32,
  blake3: 32,
  chacha20: 32,
};

function keyBitsFor(width: number): number[] {
  return [512, 1024, 2048].filter((k) => k % width === 0);
}

function buildPlaintext(): Uint8Array {
  const head = new TextEncoder().encode(
    'any binary data, including 0x00 bytes -- ',
  );
  const tail = new Uint8Array(256);
  for (let i = 0; i < 256; i++) tail[i] = i;
  const out = new Uint8Array(head.length + tail.length);
  out.set(head, 0);
  out.set(tail, head.length);
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function bigintArrEqual(a: readonly bigint[], b: readonly bigint[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

describe('test_persistence', () => {
  test('roundtrip all hashes', () => {
    const plaintext = buildPlaintext();
    for (const [name, width] of CANONICAL_HASHES) {
      for (const keyBits of keyBitsFor(width)) {
        // Day 1 — random seeds.
        const ns = new Seed(name, keyBits);
        const ds = new Seed(name, keyBits);
        const ss = new Seed(name, keyBits);

        const nsComps = ns.components;
        const dsComps = ds.components;
        const ssComps = ss.components;
        const nsKey = ns.hashKey;
        const dsKey = ds.hashKey;
        const ssKey = ss.hashKey;

        assert.equal(
          nsComps.length * 64, keyBits,
          `hash=${name} keyBits=${keyBits} components count`,
        );
        assert.equal(
          nsKey.length, EXPECTED_HASH_KEY_LEN[name],
          `hash=${name} hashKey length`,
        );

        const ciphertext = encrypt(ns, ds, ss, plaintext);
        ns.free();
        ds.free();
        ss.free();

        // Day 2 — restore from saved material.
        const ns2 = Seed.fromComponents(name, nsComps, nsKey);
        const ds2 = Seed.fromComponents(name, dsComps, dsKey);
        const ss2 = Seed.fromComponents(name, ssComps, ssKey);
        try {
          const decrypted = decrypt(ns2, ds2, ss2, ciphertext);
          assert.ok(
            bytesEqual(decrypted, plaintext),
            `hash=${name} keyBits=${keyBits} day2`,
          );

          // Restored seeds report the same key + components.
          assert.ok(
            bigintArrEqual(ns2.components, nsComps),
            `hash=${name} keyBits=${keyBits} restored components`,
          );
          assert.ok(
            bytesEqual(ns2.hashKey, nsKey),
            `hash=${name} keyBits=${keyBits} restored hashKey`,
          );
        } finally {
          ns2.free();
          ds2.free();
          ss2.free();
        }
      }
    }
  });

  test('random key path', () => {
    // 512-bit zero components — sufficient for non-SipHash primitives.
    const components: bigint[] = Array.from({ length: 8 }, () => 0n);
    for (const [name] of CANONICAL_HASHES) {
      const seed = Seed.fromComponents(name, components, new Uint8Array(0));
      try {
        const key = seed.hashKey;
        if (name === 'siphash24') {
          assert.equal(key.length, 0, 'siphash24 must report empty key');
        } else {
          assert.equal(
            key.length, EXPECTED_HASH_KEY_LEN[name],
            `primitive=${name}`,
          );
        }
      } finally {
        seed.free();
      }
    }
  });

  test('explicit key preserved', () => {
    // BLAKE3 has a 32-byte symmetric key.
    const explicit = new Uint8Array(32);
    for (let i = 0; i < 32; i++) explicit[i] = i;
    const components: bigint[] = Array.from({ length: 8 }, () => 0xCAFEBABEDEADBEEFn);
    const seed = Seed.fromComponents('blake3', components, explicit);
    try {
      assert.ok(bytesEqual(seed.hashKey, explicit));
    } finally {
      seed.free();
    }
  });

  test('bad key size', () => {
    // A non-empty hashKey whose length does not match the primitive's
    // expected length must surface a clean ITBError. Seven bytes is
    // wrong for blake3 (expects 32).
    const components: bigint[] = Array.from({ length: 16 }, () => 0n);
    const badKey = new Uint8Array(7);
    assert.throws(
      () => Seed.fromComponents('blake3', components, badKey),
      (err: unknown) => err instanceof ITBError,
    );
  });

  test('siphash rejects hash key', () => {
    // SipHash-2-4 takes no internal fixed key; passing one must be
    // rejected (not silently ignored).
    const components: bigint[] = Array.from({ length: 8 }, () => 0n);
    const nonempty = new Uint8Array(16);
    assert.throws(
      () => Seed.fromComponents('siphash24', components, nonempty),
      (err: unknown) => err instanceof ITBError,
    );
  });
});
