// End-to-end Node.js / TypeScript binding tests over libitb.
//
// Mirrors bindings/python/tests/test_roundtrip.py — exercises the
// cross-primitive matrix at 512 / 1024 / 2048 keyBits for both Single
// Ouroboros and Triple Ouroboros, plus introspection of `version` /
// `listHashes` / `maxKeyBits` / `channels` and the SeedWidthMix
// rejection on mismatched seed widths.
//
// The TestConfig section mutates process-global libitb state
// (`setBitSoup`, `setLockSoup`, `setMaxWorkers`, `setNonceBits`,
// `setBarrierFill`). Every such test body saves the prior value at
// entry and restores it on exit; node:test runs each test file in its
// own child process, so cross-file races against other test binaries
// do not occur. Within this file `test()` calls run serially by
// default, which combined with the per-test save/restore prevents
// intra-file races.

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';

import {
  channels,
  decrypt,
  decryptTriple,
  encrypt,
  encryptTriple,
  getBarrierFill,
  getBitSoup,
  getLockSoup,
  getMaxWorkers,
  getNonceBits,
  ITBError,
  listHashes,
  maxKeyBits,
  Seed,
  setBarrierFill,
  setBitSoup,
  setLockSoup,
  setMaxWorkers,
  setNonceBits,
  Status,
  version,
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

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

describe('test_roundtrip', () => {
  // ────────────────────────────────────────────────────────────────
  // Introspection.
  // ────────────────────────────────────────────────────────────────

  test('version', () => {
    const v = version();
    assert.equal(typeof v, 'string');
    assert.ok(v.length > 0, 'version must be non-empty');
    assert.match(v, /^\d+\.\d+\.\d+/, 'version pattern');
  });

  test('listHashes', () => {
    const got = listHashes();
    assert.equal(got.length, CANONICAL_HASHES.length);
    for (let i = 0; i < CANONICAL_HASHES.length; i++) {
      assert.equal(got[i]!.name, CANONICAL_HASHES[i]![0]);
      assert.equal(got[i]!.width, CANONICAL_HASHES[i]![1]);
    }
  });

  test('constants', () => {
    assert.equal(maxKeyBits(), 2048);
    assert.equal(channels(), 8);
  });

  // ────────────────────────────────────────────────────────────────
  // Seed lifecycle.
  // ────────────────────────────────────────────────────────────────

  test('seed new and free', () => {
    const s = new Seed('blake3', 1024);
    assert.notEqual(Number(s.handle), 0);
    assert.equal(s.hashName, 'blake3');
    assert.equal(s.width, 256);
    s.free();
    assert.equal(Number(s.handle), 0);
  });

  test('seed using-disposal', () => {
    let captured: Seed | null = null;
    {
      using s = new Seed('areion256', 1024);
      assert.notEqual(Number(s.handle), 0);
      captured = s;
    }
    assert.notEqual(captured, null);
    assert.equal(Number(captured!.handle), 0);
  });

  test('seed bad hash', () => {
    assert.throws(
      () => new Seed('nonsense-hash', 1024),
      (err: unknown) =>
        err instanceof ITBError && err.code === Status.BadHash,
    );
  });

  test('seed bad key bits', () => {
    for (const bits of [0, 256, 511, 2049]) {
      assert.throws(
        () => new Seed('blake3', bits),
        (err: unknown) =>
          err instanceof ITBError && err.code === Status.BadKeyBits,
        `bits=${bits}`,
      );
    }
  });

  // Skipped — Python `test_double_free_idempotent` and
  // `test_context_manager` on Seed: covered by `using`/`Disposable`
  // contract in TypeScript and the wrapper's idempotent `.free()`
  // pattern.

  // ────────────────────────────────────────────────────────────────
  // Single round-trip — full cross-primitive matrix.
  // ────────────────────────────────────────────────────────────────

  test('single all hashes all widths', () => {
    const plaintext = new Uint8Array(randomBytes(4096));
    for (const [name] of CANONICAL_HASHES) {
      for (const keyBits of [512, 1024, 2048]) {
        using ns = new Seed(name, keyBits);
        using ds = new Seed(name, keyBits);
        using ss = new Seed(name, keyBits);
        const ct = encrypt(ns, ds, ss, plaintext);
        assert.ok(
          ct.length > plaintext.length,
          `hash=${name} keyBits=${keyBits} ct ${ct.length} not > pt ${plaintext.length}`,
        );
        const pt = decrypt(ns, ds, ss, ct);
        assert.ok(bytesEqual(pt, plaintext), `hash=${name} keyBits=${keyBits}`);
      }
    }
  });

  // Skipped — Python `test_bytearray_input` / `test_memoryview_input`:
  // TypeScript's `Uint8Array` parameter type accepts any underlying
  // ArrayBuffer view (Buffer, subarray, fromHex, etc.) by construction;
  // there is no separate bytearray / memoryview type to discriminate.

  test('single seed width mismatch', () => {
    using ns = new Seed('siphash24', 1024); // width 128
    using ds = new Seed('blake3', 1024);    // width 256
    using ss = new Seed('blake3', 1024);    // width 256
    assert.throws(
      () => encrypt(ns, ds, ss, new Uint8Array([0x68, 0x69])),
      (err: unknown) =>
        err instanceof ITBError && err.code === Status.SeedWidthMix,
    );
  });

  // ────────────────────────────────────────────────────────────────
  // Triple round-trip.
  // ────────────────────────────────────────────────────────────────

  test('triple all hashes all widths', () => {
    const plaintext = new Uint8Array(randomBytes(4096));
    for (const [name] of CANONICAL_HASHES) {
      for (const keyBits of [512, 1024, 2048]) {
        const seeds: Seed[] = [];
        try {
          for (let i = 0; i < 7; i++) seeds.push(new Seed(name, keyBits));
          const [s0, s1, s2, s3, s4, s5, s6] = seeds as [
            Seed, Seed, Seed, Seed, Seed, Seed, Seed,
          ];
          const ct = encryptTriple(s0, s1, s2, s3, s4, s5, s6, plaintext);
          assert.ok(
            ct.length > plaintext.length,
            `hash=${name} keyBits=${keyBits} ct ${ct.length} not > pt ${plaintext.length}`,
          );
          const pt = decryptTriple(s0, s1, s2, s3, s4, s5, s6, ct);
          assert.ok(bytesEqual(pt, plaintext), `hash=${name} keyBits=${keyBits}`);
        } finally {
          for (const s of seeds) s.free();
        }
      }
    }
  });

  test('triple seed width mismatch', () => {
    using odd = new Seed('siphash24', 1024); // width 128
    const rest: Seed[] = [];
    try {
      for (let i = 0; i < 6; i++) rest.push(new Seed('blake3', 1024));
      const [r0, r1, r2, r3, r4, r5] = rest as [Seed, Seed, Seed, Seed, Seed, Seed];
      assert.throws(
        () => encryptTriple(odd, r0, r1, r2, r3, r4, r5, new Uint8Array([0x68, 0x69])),
        (err: unknown) =>
          err instanceof ITBError && err.code === Status.SeedWidthMix,
      );
    } finally {
      for (const s of rest) s.free();
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Process-global configuration round-trip + validation.
  //
  // Each test wraps its mutation in save/restore. node:test runs the
  // tests in this file serially, and the file itself runs in its own
  // child process — so neither intra-file nor cross-file races touch
  // the libitb global atomics through these tests.
  // ────────────────────────────────────────────────────────────────

  test('bit soup roundtrip', () => {
    const orig = getBitSoup();
    try {
      setBitSoup(1);
      assert.equal(getBitSoup(), 1);
      setBitSoup(0);
      assert.equal(getBitSoup(), 0);
    } finally {
      setBitSoup(orig);
    }
  });

  test('lock soup roundtrip', () => {
    const orig = getLockSoup();
    try {
      setLockSoup(1);
      assert.equal(getLockSoup(), 1);
    } finally {
      setLockSoup(orig);
    }
  });

  test('max workers roundtrip', () => {
    const orig = getMaxWorkers();
    try {
      setMaxWorkers(4);
      assert.equal(getMaxWorkers(), 4);
    } finally {
      setMaxWorkers(orig);
    }
  });

  test('nonce bits validation', () => {
    const orig = getNonceBits();
    try {
      for (const valid of [128, 256, 512]) {
        setNonceBits(valid);
        assert.equal(getNonceBits(), valid);
      }
      for (const bad of [0, 1, 192, 1024]) {
        assert.throws(
          () => setNonceBits(bad),
          (err: unknown) =>
            err instanceof ITBError && err.code === Status.BadInput,
          `bad=${bad}`,
        );
      }
    } finally {
      setNonceBits(orig);
    }
  });

  test('barrier fill validation', () => {
    const orig = getBarrierFill();
    try {
      for (const valid of [1, 2, 4, 8, 16, 32]) {
        setBarrierFill(valid);
        assert.equal(getBarrierFill(), valid);
      }
      for (const bad of [0, 3, 5, 7, 64]) {
        assert.throws(
          () => setBarrierFill(bad),
          (err: unknown) =>
            err instanceof ITBError && err.code === Status.BadInput,
          `bad=${bad}`,
        );
      }
    } finally {
      setBarrierFill(orig);
    }
  });
});
