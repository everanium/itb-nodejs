// Tests for the low-level `Seed.attachLockSeed` mutator.
//
// Mirrors bindings/python/tests/test_attach_lock_seed.py — covers the
// happy-path round trip with the bit-permutation overlay engaged, the
// cross-process persistence path (export components + hashKey,
// rebuild via `Seed.fromComponents`, reattach a fresh lockSeed), and
// the misuse-rejection paths (self-attach, post-encrypt switch, width
// mismatch) plus the overlay-off panic guard.
//
// Tests in this file mutate `setBitSoup` / `setLockSoup`, both
// process-global libitb atomics. Each test that mutates wraps its
// mutation in save/restore. node:test runs each test file in its own
// child process, so cross-file races against other test binaries do
// not occur. Within this file `test()` calls run serially by default,
// which combined with the per-test save/restore prevents intra-file
// races.

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';

import {
  decrypt,
  encrypt,
  getBitSoup,
  getLockSoup,
  ITBError,
  Seed,
  setBitSoup,
  setLockSoup,
  Status,
} from '../src/index.js';

/**
 * Engages `setLockSoup(1)` for the duration of the body, then restores
 * the prior values. The `setLockSoup` setter auto-couples `BitSoup=1`
 * inside libitb, so both flags are restored on exit.
 */
function withLockSoupOn(body: () => void): void {
  const prevBs = getBitSoup();
  const prevLs = getLockSoup();
  setLockSoup(1);
  try {
    body();
  } finally {
    setBitSoup(prevBs);
    setLockSoup(prevLs);
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

describe('test_attach_lock_seed', () => {
  test('roundtrip', () => {
    const plaintext = new TextEncoder().encode('attach_lock_seed roundtrip payload');
    withLockSoupOn(() => {
      using ns = new Seed('blake3', 1024);
      using ds = new Seed('blake3', 1024);
      using ss = new Seed('blake3', 1024);
      using ls = new Seed('blake3', 1024);
      ns.attachLockSeed(ls);
      const ct = encrypt(ns, ds, ss, plaintext);
      const pt = decrypt(ns, ds, ss, ct);
      assert.ok(bytesEqual(pt, plaintext));
    });
  });

  test('persistence', () => {
    const plaintext = new TextEncoder().encode('cross-process attach lockseed roundtrip');
    withLockSoupOn(() => {
      // Day 1 — sender.
      const ns = new Seed('blake3', 1024);
      const ds = new Seed('blake3', 1024);
      const ss = new Seed('blake3', 1024);
      const ls = new Seed('blake3', 1024);
      ns.attachLockSeed(ls);

      const nsComps = ns.components;
      const dsComps = ds.components;
      const ssComps = ss.components;
      const lsComps = ls.components;
      const nsKey = ns.hashKey;
      const dsKey = ds.hashKey;
      const ssKey = ss.hashKey;
      const lsKey = ls.hashKey;

      const ct = encrypt(ns, ds, ss, plaintext);
      ns.free();
      ds.free();
      ss.free();
      ls.free();

      // Day 2 — receiver.
      using ns2 = Seed.fromComponents('blake3', nsComps, nsKey);
      using ds2 = Seed.fromComponents('blake3', dsComps, dsKey);
      using ss2 = Seed.fromComponents('blake3', ssComps, ssKey);
      using ls2 = Seed.fromComponents('blake3', lsComps, lsKey);
      ns2.attachLockSeed(ls2);
      const pt = decrypt(ns2, ds2, ss2, ct);
      assert.ok(bytesEqual(pt, plaintext));
    });
  });

  test('self attach rejected', () => {
    using ns = new Seed('blake3', 1024);
    assert.throws(
      () => ns.attachLockSeed(ns),
      (err: unknown) =>
        err instanceof ITBError && err.code === Status.BadInput,
    );
  });

  test('width mismatch rejected', () => {
    using ns256 = new Seed('blake3', 1024);    // width 256
    using ls128 = new Seed('siphash24', 1024); // width 128
    assert.throws(
      () => ns256.attachLockSeed(ls128),
      (err: unknown) =>
        err instanceof ITBError && err.code === Status.SeedWidthMix,
    );
  });

  test('post encrypt attach rejected', () => {
    withLockSoupOn(() => {
      using ns = new Seed('blake3', 1024);
      using ds = new Seed('blake3', 1024);
      using ss = new Seed('blake3', 1024);
      using ls = new Seed('blake3', 1024);
      ns.attachLockSeed(ls);
      // Encrypt once — locks future attachLockSeed calls on ns.
      encrypt(ns, ds, ss, new TextEncoder().encode('pre-switch'));
      using ls2 = new Seed('blake3', 1024);
      assert.throws(
        () => ns.attachLockSeed(ls2),
        (err: unknown) =>
          err instanceof ITBError && err.code === Status.BadInput,
      );
    });
  });

  // Skipped — the Python `test_type_check` covers TypeError when a
  // non-Seed value is passed. TypeScript rejects this at compile time
  // via the typed `lockSeed: Seed` parameter; the runtime guard
  // (`instanceof Seed`) is unreachable on type-checked call sites.

  test('overlay off panics on encrypt', () => {
    // Without either BitSoup or LockSoup engaged, the build-PRF guard
    // inside the Go-side dispatch panics on encrypt-time, surfacing
    // as ITBError. Regression-pin for the overlay-off
    // action-at-a-distance bug — silent no-op replaced by a loud
    // failure.
    const prevBs = getBitSoup();
    const prevLs = getLockSoup();
    setBitSoup(0);
    setLockSoup(0);
    try {
      using ns = new Seed('blake3', 1024);
      using ds = new Seed('blake3', 1024);
      using ss = new Seed('blake3', 1024);
      using ls = new Seed('blake3', 1024);
      ns.attachLockSeed(ls);
      assert.throws(
        () => encrypt(ns, ds, ss, new TextEncoder().encode('overlay off - should panic')),
        (err: unknown) => err instanceof ITBError,
      );
    } finally {
      setBitSoup(prevBs);
      setLockSoup(prevLs);
    }
  });
});
