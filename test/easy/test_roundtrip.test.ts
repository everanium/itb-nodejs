// End-to-end Node.js / TypeScript binding tests for the high-level
// `Encryptor` surface (the github.com/everanium/itb/easy sub-package
// wrapper).
//
// Mirrors bindings/python/tests/easy/test_roundtrip.py one-to-one.
// Each Python TestCase.test_* becomes a single test() here; the
// per-class subTest loops are inlined since node:test has no
// equivalent of unittest subTest..
//
// Skipped (canonical skip set):
//   - test_double_free_idempotent — `using` / Symbol.dispose covers
//     idempotent disposal at the language level.
//   - test_context_manager — `using` declaration is the equivalent.
//   - test_bytearray_input / test_memoryview_input — Uint8Array is
//     the single byte-buffer surface in TypeScript; no separate
//     bytearray / memoryview type exists.

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';

import {
  Encryptor,
  ITBError,
  Status,
} from '../../src/index.js';

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

function keyBitsFor(width: number): number[] {
  return [512, 1024, 2048].filter((k) => k % width === 0);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function asU8(buf: Uint8Array | Buffer): Uint8Array {
  // Buffer is a Uint8Array subclass; copy the bytes into a plain
  // Uint8Array so deepEqual (which checks the prototype chain) and
  // bytesEqual both behave consistently across Buffer / Uint8Array
  // origins.
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength).slice();
}

describe('test_easy_roundtrip', () => {
  // ─── TestEncryptorLifecycle ───────────────────────────────────────

  test('new and free', () => {
    const enc = new Encryptor('blake3', 1024, 'kmac256');
    assert.notEqual(enc.handle, 0);
    assert.notEqual(enc.handle, 0n);
    assert.equal(enc.primitive, 'blake3');
    assert.equal(enc.keyBits, 1024);
    assert.equal(enc.mode, 1);
    assert.equal(enc.macName, 'kmac256');
    enc.free();
    assert.ok(enc.handle === 0 || enc.handle === 0n);
  });

  test('close then method raises', () => {
    const enc = new Encryptor('blake3', 1024, 'kmac256');
    enc.close();
    assert.throws(
      () => enc.encrypt(new TextEncoder().encode('after close')),
      (err: unknown) => err instanceof ITBError && err.code === Status.EasyClosed,
    );
    enc.free();
  });

  test('defaults', () => {
    // Empty primitive / 0 keyBits / null mac select package defaults
    // (areion512 / 1024 / hmac-blake3). The latter via the
    // binding-side override that maps macName === null to the
    // lightest-overhead MAC available in the Easy Mode surface.
    using enc = new Encryptor('', 0, null);
    assert.equal(enc.primitive, 'areion512');
    assert.equal(enc.keyBits, 1024);
    assert.equal(enc.mode, 1);
    assert.equal(enc.macName, 'hmac-blake3');
  });

  test('bad primitive', () => {
    assert.throws(() => new Encryptor('nonsense-hash', 1024, 'kmac256'),
      (err: unknown) => err instanceof ITBError);
  });

  test('bad mac', () => {
    assert.throws(() => new Encryptor('blake3', 1024, 'nonsense-mac'),
      (err: unknown) => err instanceof ITBError);
  });

  test('bad key bits', () => {
    for (const bits of [256, 511, 999, 2049]) {
      assert.throws(() => new Encryptor('blake3', bits, 'kmac256'),
        (err: unknown) => err instanceof ITBError, `bits=${bits}`);
    }
  });

  test('bad mode', () => {
    assert.throws(() => new Encryptor('blake3', 1024, 'kmac256', 2),
      (err: unknown) => err instanceof ITBError);
  });

  // ─── TestRoundtripSingle ──────────────────────────────────────────

  test('all hashes all widths single', () => {
    const plaintext = asU8(randomBytes(4096));
    for (const [name, width] of CANONICAL_HASHES) {
      for (const keyBits of keyBitsFor(width)) {
        using enc = new Encryptor(name, keyBits, 'kmac256', 1);
        const ct = enc.encrypt(plaintext);
        assert.ok(ct.length > plaintext.length, `hash=${name} bits=${keyBits} ct should be larger`);
        const pt = enc.decrypt(ct);
        assert.ok(bytesEqual(pt, plaintext), `hash=${name} bits=${keyBits}`);
      }
    }
  });

  test('all hashes all widths single auth', () => {
    const plaintext = asU8(randomBytes(4096));
    for (const [name, width] of CANONICAL_HASHES) {
      for (const keyBits of keyBitsFor(width)) {
        using enc = new Encryptor(name, keyBits, 'kmac256', 1);
        const ct = enc.encryptAuth(plaintext);
        const pt = enc.decryptAuth(ct);
        assert.ok(bytesEqual(pt, plaintext), `hash=${name} bits=${keyBits}`);
      }
    }
  });

  // ─── TestRoundtripTriple ──────────────────────────────────────────

  test('all hashes all widths triple', () => {
    const plaintext = asU8(randomBytes(4096));
    for (const [name, width] of CANONICAL_HASHES) {
      for (const keyBits of keyBitsFor(width)) {
        using enc = new Encryptor(name, keyBits, 'kmac256', 3);
        const ct = enc.encrypt(plaintext);
        assert.ok(ct.length > plaintext.length, `hash=${name} bits=${keyBits}`);
        const pt = enc.decrypt(ct);
        assert.ok(bytesEqual(pt, plaintext), `hash=${name} bits=${keyBits}`);
      }
    }
  });

  test('all hashes all widths triple auth', () => {
    const plaintext = asU8(randomBytes(4096));
    for (const [name, width] of CANONICAL_HASHES) {
      for (const keyBits of keyBitsFor(width)) {
        using enc = new Encryptor(name, keyBits, 'kmac256', 3);
        const ct = enc.encryptAuth(plaintext);
        const pt = enc.decryptAuth(ct);
        assert.ok(bytesEqual(pt, plaintext), `hash=${name} bits=${keyBits}`);
      }
    }
  });

  test('seed count reflects mode', () => {
    {
      using enc = new Encryptor('blake3', 1024, 'kmac256', 1);
      assert.equal(enc.seedCount, 3);
    }
    {
      using enc = new Encryptor('blake3', 1024, 'kmac256', 3);
      assert.equal(enc.seedCount, 7);
    }
  });

  // ─── TestConfigPerInstance ────────────────────────────────────────

  test('set bit soup', () => {
    using enc = new Encryptor('blake3', 1024, 'kmac256');
    enc.setBitSoup(1);
    const payload = new TextEncoder().encode('bit-soup payload');
    const ct = enc.encrypt(payload);
    const pt = enc.decrypt(ct);
    assert.ok(bytesEqual(pt, payload));
  });

  test('set lock soup couples bit soup', () => {
    // Activating LockSoup auto-couples BitSoup=1 on the same encryptor;
    // verify by round-tripping a known plaintext.
    using enc = new Encryptor('blake3', 1024, 'kmac256');
    enc.setLockSoup(1);
    const payload = new TextEncoder().encode('lock-soup payload');
    const ct = enc.encrypt(payload);
    const pt = enc.decrypt(ct);
    assert.ok(bytesEqual(pt, payload));
  });

  test('set lock seed grows seed count', () => {
    using enc = new Encryptor('blake3', 1024, 'kmac256', 1);
    assert.equal(enc.seedCount, 3);
    enc.setLockSeed(1);
    assert.equal(enc.seedCount, 4);
    const payload = new TextEncoder().encode('lockseed payload');
    const ct = enc.encrypt(payload);
    const pt = enc.decrypt(ct);
    assert.ok(bytesEqual(pt, payload));
  });

  test('set lock seed after encrypt rejected', () => {
    using enc = new Encryptor('blake3', 1024, 'kmac256');
    enc.encrypt(new TextEncoder().encode('first'));
    assert.throws(
      () => enc.setLockSeed(1),
      (err: unknown) =>
        err instanceof ITBError && err.code === Status.EasyLockSeedAfterEncrypt,
    );
  });

  test('set nonce bits validation', () => {
    using enc = new Encryptor('blake3', 1024, 'kmac256');
    for (const valid of [128, 256, 512]) {
      enc.setNonceBits(valid); // must not throw
    }
    for (const bad of [0, 1, 192, 1024]) {
      assert.throws(
        () => enc.setNonceBits(bad),
        (err: unknown) => err instanceof ITBError && err.code === Status.BadInput,
        `bad=${bad}`,
      );
    }
  });

  test('set barrier fill validation', () => {
    using enc = new Encryptor('blake3', 1024, 'kmac256');
    for (const valid of [1, 2, 4, 8, 16, 32]) {
      enc.setBarrierFill(valid); // must not throw
    }
    for (const bad of [0, 3, 5, 7, 64]) {
      assert.throws(
        () => enc.setBarrierFill(bad),
        (err: unknown) => err instanceof ITBError && err.code === Status.BadInput,
        `bad=${bad}`,
      );
    }
  });

  test('set chunk size accepted', () => {
    using enc = new Encryptor('blake3', 1024, 'kmac256');
    enc.setChunkSize(1024); // must not throw
    enc.setChunkSize(0); // auto-detect
  });

  test('two encryptors isolated', () => {
    // Setting LockSoup on one encryptor must not bleed into another;
    // per-instance Config snapshots are independent.
    using a = new Encryptor('blake3', 1024, 'kmac256');
    using b = new Encryptor('blake3', 1024, 'kmac256');
    a.setLockSoup(1);
    const pa = new TextEncoder().encode('a');
    const pb = new TextEncoder().encode('b');
    assert.ok(bytesEqual(a.decrypt(a.encrypt(pa)), pa));
    assert.ok(bytesEqual(b.decrypt(b.encrypt(pb)), pb));
  });
});
