// Native-Blob round-trip tests for the Node.js binding.
//
// Mirrors bindings/python/tests/test_blob.py — exercises the Single /
// Triple × LockSeed × MAC × non-default globals matrix through
// `Blob128` / `Blob256` / `Blob512` plus the three typed error paths
// (mode mismatch, malformed JSON, version too new).
//
// The blob captures the sender's process-wide configuration
// (NonceBits / BarrierFill / BitSoup / LockSoup) at export time and
// applies it unconditionally on import, so each test case toggles the
// four globals to non-default values, exports, resets to defaults,
// imports, and verifies the restored state.
//
// Tests in this file mutate process-global libitb configuration
// (NonceBits / BarrierFill / BitSoup / LockSoup). node:test runs
// each test file in its own child process, so cross-file races
// against other test binaries do not occur. Each test wraps its
// mutation in save/restore so subsequent tests in this file run
// unaffected.

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';

import {
  Blob128,
  Blob256,
  Blob512,
  BlobExportOpts,
  decrypt,
  decryptAuth,
  decryptAuthTriple,
  decryptTriple,
  encrypt,
  encryptAuth,
  encryptAuthTriple,
  encryptTriple,
  getBarrierFill,
  getBitSoup,
  getLockSoup,
  getNonceBits,
  ITBBlobMalformedError,
  ITBBlobModeMismatchError,
  ITBBlobVersionTooNewError,
  MAC,
  Seed,
  setBarrierFill,
  setBitSoup,
  setLockSoup,
  setNonceBits,
} from '../src/index.js';

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function tokenBytes(n: number): Uint8Array {
  return new Uint8Array(randomBytes(n));
}

/**
 * Sets the four globals to non-default values for the body and
 * restores them on exit. Mirrors `_with_globals` from `test_blob.py`.
 */
function withGlobals(body: () => void): void {
  const prev = [
    getNonceBits(),
    getBarrierFill(),
    getBitSoup(),
    getLockSoup(),
  ] as const;
  setNonceBits(512);
  setBarrierFill(4);
  setBitSoup(1);
  setLockSoup(1);
  try {
    body();
  } finally {
    setNonceBits(prev[0]);
    setBarrierFill(prev[1]);
    setBitSoup(prev[2]);
    setLockSoup(prev[3]);
  }
}

/**
 * Forces all four globals to defaults so an Import-applied snapshot
 * is detectable via post-Import reads.
 */
function resetGlobals(): void {
  setNonceBits(128);
  setBarrierFill(1);
  setBitSoup(0);
  setLockSoup(0);
}

function assertGlobalsRestored(
  nonce: number,
  barrier: number,
  bitSoup: number,
  lockSoup: number,
): void {
  assert.equal(getNonceBits(), nonce, 'NonceBits not restored');
  assert.equal(getBarrierFill(), barrier, 'BarrierFill not restored');
  assert.equal(getBitSoup(), bitSoup, 'BitSoup not restored');
  assert.equal(getLockSoup(), lockSoup, 'LockSoup not restored');
}

describe('test_blob', () => {
  // ────────────────────────────────────────────────────────────────
  // Smoke tests — construction and properties.
  // ────────────────────────────────────────────────────────────────

  test('construct each width', () => {
    for (const [Cls, expectedWidth] of [
      [Blob128, 128] as const,
      [Blob256, 256] as const,
      [Blob512, 512] as const,
    ]) {
      const b = new Cls();
      try {
        assert.equal(b.width, expectedWidth, `${Cls.name} width`);
        assert.equal(b.mode, 0, `${Cls.name} mode`);
        assert.notEqual(Number(b.handle), 0, `${Cls.name} handle`);
      } finally {
        b.free();
      }
    }
  });

  // Skipped — Python `test_double_free_idempotent` and
  // `test_context_manager` for Blob: covered by `using` /
  // `Disposable` contract in TypeScript and the wrapper's idempotent
  // `.free()` pattern.

  // ────────────────────────────────────────────────────────────────
  // Blob512 — areion512 round-trip, full matrix.
  // ────────────────────────────────────────────────────────────────

  test('blob512 single full matrix', () => {
    const plaintext = new TextEncoder().encode('node blob512 single round-trip payload');
    withGlobals(() => {
      for (const withLs of [false, true]) {
        for (const withMac of [false, true]) {
          blob512SingleRoundtrip('areion512', 2048, plaintext, withLs, withMac);
        }
      }
    });
  });

  test('blob512 triple full matrix', () => {
    const plaintext = new TextEncoder().encode('node blob512 triple round-trip payload');
    withGlobals(() => {
      for (const withLs of [false, true]) {
        for (const withMac of [false, true]) {
          blob512TripleRoundtrip(plaintext, withLs, withMac);
        }
      }
    });
  });

  // ────────────────────────────────────────────────────────────────
  // Blob256 — BLAKE3 round-trip.
  // ────────────────────────────────────────────────────────────────

  test('blob256 single', () => {
    const plaintext = new TextEncoder().encode('node blob256 single round-trip');
    withGlobals(() => {
      using ns = new Seed('blake3', 1024);
      using ds = new Seed('blake3', 1024);
      using ss = new Seed('blake3', 1024);
      const ct = encrypt(ns, ds, ss, plaintext);

      let blob: Uint8Array;
      {
        using src = new Blob256();
        for (const [slot, seed] of [
          ['n', ns] as const,
          ['d', ds] as const,
          ['s', ss] as const,
        ]) {
          src.setKey(slot, seed.hashKey);
          src.setComponents(slot, seed.components);
        }
        blob = src.export();
      }

      resetGlobals();
      using dst = new Blob256();
      dst.import(blob);
      assert.equal(dst.mode, 1);
      using ns2 = Seed.fromComponents('blake3', dst.getComponents('n'), dst.getKey('n'));
      using ds2 = Seed.fromComponents('blake3', dst.getComponents('d'), dst.getKey('d'));
      using ss2 = Seed.fromComponents('blake3', dst.getComponents('s'), dst.getKey('s'));
      const recovered = decrypt(ns2, ds2, ss2, ct);
      assert.ok(bytesEqual(recovered, plaintext));
    });
  });

  test('blob256 triple', () => {
    const plaintext = new TextEncoder().encode('node blob256 triple round-trip');
    withGlobals(() => {
      const seeds: Seed[] = [];
      try {
        for (let i = 0; i < 7; i++) seeds.push(new Seed('blake3', 1024));
        const [s0, s1, s2, s3, s4, s5, s6] = seeds as [
          Seed, Seed, Seed, Seed, Seed, Seed, Seed,
        ];
        const ct = encryptTriple(s0, s1, s2, s3, s4, s5, s6, plaintext);

        const slotNames = ['n', 'd1', 'd2', 'd3', 's1', 's2', 's3'] as const;
        let blob: Uint8Array;
        {
          using src = new Blob256();
          for (let i = 0; i < slotNames.length; i++) {
            const slot = slotNames[i]!;
            const seed = seeds[i]!;
            src.setKey(slot, seed.hashKey);
            src.setComponents(slot, seed.components);
          }
          blob = src.exportTriple();
        }

        resetGlobals();
        using dst = new Blob256();
        dst.importTriple(blob);
        assert.equal(dst.mode, 3);
        const seeds2: Seed[] = [];
        try {
          for (const slot of slotNames) {
            seeds2.push(Seed.fromComponents('blake3', dst.getComponents(slot), dst.getKey(slot)));
          }
          const [t0, t1, t2, t3, t4, t5, t6] = seeds2 as [
            Seed, Seed, Seed, Seed, Seed, Seed, Seed,
          ];
          const recovered = decryptTriple(t0, t1, t2, t3, t4, t5, t6, ct);
          assert.ok(bytesEqual(recovered, plaintext));
        } finally {
          for (const s of seeds2) s.free();
        }
      } finally {
        for (const s of seeds) s.free();
      }
    });
  });

  // ────────────────────────────────────────────────────────────────
  // Blob128 — siphash24 (no key) and aescmac (16-byte key).
  // ────────────────────────────────────────────────────────────────

  test('blob128 siphash single', () => {
    const plaintext = new TextEncoder().encode('node blob128 siphash round-trip');
    withGlobals(() => {
      using ns = new Seed('siphash24', 512);
      using ds = new Seed('siphash24', 512);
      using ss = new Seed('siphash24', 512);
      const ct = encrypt(ns, ds, ss, plaintext);

      let blob: Uint8Array;
      {
        using src = new Blob128();
        for (const [slot, seed] of [
          ['n', ns] as const,
          ['d', ds] as const,
          ['s', ss] as const,
        ]) {
          src.setKey(slot, seed.hashKey); // empty bytes for siphash24
          src.setComponents(slot, seed.components);
        }
        blob = src.export();
      }

      resetGlobals();
      using dst = new Blob128();
      dst.import(blob);
      using ns2 = Seed.fromComponents('siphash24', dst.getComponents('n'));
      using ds2 = Seed.fromComponents('siphash24', dst.getComponents('d'));
      using ss2 = Seed.fromComponents('siphash24', dst.getComponents('s'));
      const recovered = decrypt(ns2, ds2, ss2, ct);
      assert.ok(bytesEqual(recovered, plaintext));
    });
  });

  test('blob128 aescmac single', () => {
    const plaintext = new TextEncoder().encode('node blob128 aescmac round-trip');
    withGlobals(() => {
      using ns = new Seed('aescmac', 512);
      using ds = new Seed('aescmac', 512);
      using ss = new Seed('aescmac', 512);
      const ct = encrypt(ns, ds, ss, plaintext);

      let blob: Uint8Array;
      {
        using src = new Blob128();
        for (const [slot, seed] of [
          ['n', ns] as const,
          ['d', ds] as const,
          ['s', ss] as const,
        ]) {
          src.setKey(slot, seed.hashKey);
          src.setComponents(slot, seed.components);
        }
        blob = src.export();
      }

      resetGlobals();
      using dst = new Blob128();
      dst.import(blob);
      using ns2 = Seed.fromComponents('aescmac', dst.getComponents('n'), dst.getKey('n'));
      using ds2 = Seed.fromComponents('aescmac', dst.getComponents('d'), dst.getKey('d'));
      using ss2 = Seed.fromComponents('aescmac', dst.getComponents('s'), dst.getKey('s'));
      const recovered = decrypt(ns2, ds2, ss2, ct);
      assert.ok(bytesEqual(recovered, plaintext));
    });
  });

  // ────────────────────────────────────────────────────────────────
  // Slot-naming surface — string vs int parity.
  // ────────────────────────────────────────────────────────────────

  test('string and int slots equivalent', () => {
    using b = new Blob512();
    const key = tokenBytes(64);
    const comps: bigint[] = Array.from({ length: 8 }, () => 0xDEADBEEFCAFEBABEn);
    b.setKey('n', key);
    b.setComponents('n', comps);
    assert.ok(bytesEqual(b.getKey(0), key)); // 0 === BlobSlot.N
    const got = b.getComponents(0);
    assert.equal(got.length, comps.length);
    for (let i = 0; i < comps.length; i++) assert.equal(got[i], comps[i]);
  });

  test('invalid slot name', () => {
    using b = new Blob512();
    assert.throws(
      () => b.setKey('nope', new Uint8Array(64)),
      (err: unknown) => err instanceof TypeError,
    );
  });

  // ────────────────────────────────────────────────────────────────
  // Error paths — mode mismatch, malformed, version too new.
  // ────────────────────────────────────────────────────────────────

  test('mode mismatch', () => {
    withGlobals(() => {
      using ns = new Seed('areion512', 1024);
      using ds = new Seed('areion512', 1024);
      using ss = new Seed('areion512', 1024);
      let blob: Uint8Array;
      {
        using src = new Blob512();
        for (const [slot, seed] of [
          ['n', ns] as const,
          ['d', ds] as const,
          ['s', ss] as const,
        ]) {
          src.setKey(slot, seed.hashKey);
          src.setComponents(slot, seed.components);
        }
        blob = src.export();
      }

      using dst = new Blob512();
      assert.throws(
        () => dst.importTriple(blob),
        (err: unknown) => err instanceof ITBBlobModeMismatchError,
      );
    });
  });

  test('malformed', () => {
    using b = new Blob512();
    assert.throws(
      () => b.import(new TextEncoder().encode('{not json')),
      (err: unknown) => err instanceof ITBBlobMalformedError,
    );
  });

  test('version too new', () => {
    const doc = {
      v: 99,
      mode: 1,
      key_bits: 512,
      key_n: '00'.repeat(64),
      key_d: '00'.repeat(64),
      key_s: '00'.repeat(64),
      ns: Array(8).fill('0'),
      ds: Array(8).fill('0'),
      ss: Array(8).fill('0'),
      globals: {
        nonce_bits: 128,
        barrier_fill: 1,
        bit_soup: 0,
        lock_soup: 0,
      },
    };
    const data = new TextEncoder().encode(JSON.stringify(doc));
    using b = new Blob512();
    assert.throws(
      () => b.import(data),
      (err: unknown) => err instanceof ITBBlobVersionTooNewError,
    );
  });
});

// ────────────────────────────────────────────────────────────────
// Helpers — Blob512 single + triple full-matrix bodies.
// ────────────────────────────────────────────────────────────────

function blob512SingleRoundtrip(
  primitive: string,
  keyBits: number,
  plaintext: Uint8Array,
  withLs: boolean,
  withMac: boolean,
): void {
  using ns = new Seed(primitive, keyBits);
  using ds = new Seed(primitive, keyBits);
  using ss = new Seed(primitive, keyBits);

  let ls: Seed | null = null;
  if (withLs) {
    ls = new Seed(primitive, keyBits);
    ns.attachLockSeed(ls);
  }

  const macKey = withMac ? tokenBytes(32) : null;
  let mac: MAC | null = null;
  if (withMac) {
    mac = new MAC('kmac256', macKey!);
  }

  let ct: Uint8Array;
  try {
    ct = withMac
      ? encryptAuth(ns, ds, ss, mac!, plaintext)
      : encrypt(ns, ds, ss, plaintext);

    let blob: Uint8Array;
    let opts = BlobExportOpts.None;
    if (withLs) opts |= BlobExportOpts.LockSeed;
    if (withMac) opts |= BlobExportOpts.Mac;
    {
      using src = new Blob512();
      src.setKey('n', ns.hashKey);
      src.setKey('d', ds.hashKey);
      src.setKey('s', ss.hashKey);
      src.setComponents('n', ns.components);
      src.setComponents('d', ds.components);
      src.setComponents('s', ss.components);
      if (withLs) {
        src.setKey('l', ls!.hashKey);
        src.setComponents('l', ls!.components);
      }
      if (withMac) {
        src.setMacKey(macKey!);
        src.setMacName('kmac256');
      }
      blob = src.export(opts);
    }

    resetGlobals();
    using dst = new Blob512();
    dst.import(blob);
    assert.equal(dst.mode, 1, `withLs=${withLs} withMac=${withMac}`);
    assertGlobalsRestored(512, 4, 1, 1);

    using ns2 = Seed.fromComponents(primitive, dst.getComponents('n'), dst.getKey('n'));
    using ds2 = Seed.fromComponents(primitive, dst.getComponents('d'), dst.getKey('d'));
    using ss2 = Seed.fromComponents(primitive, dst.getComponents('s'), dst.getKey('s'));
    let ls2: Seed | null = null;
    if (withLs) {
      ls2 = Seed.fromComponents(primitive, dst.getComponents('l'), dst.getKey('l'));
      ns2.attachLockSeed(ls2);
    }

    let mac2: MAC | null = null;
    try {
      if (withMac) {
        assert.equal(dst.getMacName(), 'kmac256');
        assert.ok(bytesEqual(dst.getMacKey(), macKey!));
        mac2 = new MAC('kmac256', dst.getMacKey());
      }

      const pt = withMac
        ? decryptAuth(ns2, ds2, ss2, mac2!, ct)
        : decrypt(ns2, ds2, ss2, ct);
      assert.ok(
        bytesEqual(pt, plaintext),
        `withLs=${withLs} withMac=${withMac}`,
      );
    } finally {
      if (mac2) mac2.free();
      if (ls2) ls2.free();
    }
  } finally {
    if (mac) mac.free();
    if (ls) ls.free();
  }
}

function blob512TripleRoundtrip(
  plaintext: Uint8Array,
  withLs: boolean,
  withMac: boolean,
): void {
  const primitive = 'areion512';
  const keyBits = 2048;

  using ns = new Seed(primitive, keyBits);
  using ds1 = new Seed(primitive, keyBits);
  using ds2 = new Seed(primitive, keyBits);
  using ds3 = new Seed(primitive, keyBits);
  using ss1 = new Seed(primitive, keyBits);
  using ss2 = new Seed(primitive, keyBits);
  using ss3 = new Seed(primitive, keyBits);

  let ls: Seed | null = null;
  if (withLs) {
    ls = new Seed(primitive, keyBits);
    ns.attachLockSeed(ls);
  }

  const macKey = withMac ? tokenBytes(32) : null;
  let mac: MAC | null = null;
  if (withMac) {
    mac = new MAC('kmac256', macKey!);
  }

  try {
    const ct = withMac
      ? encryptAuthTriple(ns, ds1, ds2, ds3, ss1, ss2, ss3, mac!, plaintext)
      : encryptTriple(ns, ds1, ds2, ds3, ss1, ss2, ss3, plaintext);

    let blob: Uint8Array;
    let opts = BlobExportOpts.None;
    if (withLs) opts |= BlobExportOpts.LockSeed;
    if (withMac) opts |= BlobExportOpts.Mac;
    {
      using src = new Blob512();
      const slots: ReadonlyArray<readonly [string, Seed]> = [
        ['n', ns], ['d1', ds1], ['d2', ds2], ['d3', ds3],
        ['s1', ss1], ['s2', ss2], ['s3', ss3],
      ];
      for (const [slot, seed] of slots) {
        src.setKey(slot, seed.hashKey);
        src.setComponents(slot, seed.components);
      }
      if (withLs) {
        src.setKey('l', ls!.hashKey);
        src.setComponents('l', ls!.components);
      }
      if (withMac) {
        src.setMacKey(macKey!);
        src.setMacName('kmac256');
      }
      blob = src.exportTriple(opts);
    }

    resetGlobals();
    using dst = new Blob512();
    dst.importTriple(blob);
    assert.equal(dst.mode, 3, `withLs=${withLs} withMac=${withMac}`);
    assertGlobalsRestored(512, 4, 1, 1);

    const seedSlots = ['n', 'd1', 'd2', 'd3', 's1', 's2', 's3'] as const;
    const restored: Seed[] = [];
    let ls2: Seed | null = null;
    let mac2: MAC | null = null;
    try {
      for (const slot of seedSlots) {
        restored.push(
          Seed.fromComponents(primitive, dst.getComponents(slot), dst.getKey(slot)),
        );
      }
      if (withLs) {
        ls2 = Seed.fromComponents(primitive, dst.getComponents('l'), dst.getKey('l'));
        restored[0]!.attachLockSeed(ls2);
      }
      if (withMac) {
        mac2 = new MAC('kmac256', dst.getMacKey());
      }
      const [r0, r1, r2, r3, r4, r5, r6] = restored as [
        Seed, Seed, Seed, Seed, Seed, Seed, Seed,
      ];
      const pt = withMac
        ? decryptAuthTriple(r0, r1, r2, r3, r4, r5, r6, mac2!, ct)
        : decryptTriple(r0, r1, r2, r3, r4, r5, r6, ct);
      assert.ok(
        bytesEqual(pt, plaintext),
        `withLs=${withLs} withMac=${withMac}`,
      );
    } finally {
      if (mac2) mac2.free();
      if (ls2) ls2.free();
      for (const s of restored) s.free();
    }
  } finally {
    if (mac) mac.free();
    if (ls) ls.free();
  }
}

