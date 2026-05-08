// Cross-process persistence round-trip tests for the high-level
// Encryptor surface.
//
// The `Encryptor.exportState` / `Encryptor.importState` /
// `Encryptor.peekConfig` triplet is the persistence surface required
// for any deployment where encrypt and decrypt run in different
// processes (network, storage, backup, microservices). Without the
// JSON-encoded blob captured at encrypt-side and re-supplied at
// decrypt-side, the encryptor state cannot be reconstructed and the
// ciphertext is unreadable.
//
// Mirrors the Python file's structure adapted to the one-handle,
// JSON-blob-state Encryptor API. The Encryptor blob carries strictly
// more state than the low-level path — PRF keys for every seed slot,
// MAC key, optional dedicated lockSeed material, plus the structural
// metadata (primitive / keyBits / mode / mac).

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';

import {
  Encryptor,
  ITBEasyMismatchError,
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

const EXPECTED_PRF_KEY_LEN: Readonly<Record<string, number>> = {
  areion256: 32,
  areion512: 64,
  siphash24: 0,
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

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function range256(): Uint8Array {
  const out = new Uint8Array(256);
  for (let i = 0; i < 256; i++) out[i] = i;
  return out;
}

function concatU8(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

describe('test_easy_persistence', () => {
  // ─── TestPersistenceRoundtrip ─────────────────────────────────────

  test('roundtrip all hashes single', () => {
    const plaintext = concatU8(
      new TextEncoder().encode('any binary data, including 0x00 bytes -- '),
      range256(),
    );

    for (const [name, width] of CANONICAL_HASHES) {
      for (const keyBits of keyBitsFor(width)) {
        // Day 1 — random encryptor.
        const src = new Encryptor(name, keyBits, 'kmac256', 1);
        const blob = src.exportState();
        const ct = src.encryptAuth(plaintext);
        src.free();

        // Day 2 — restore from saved blob.
        const dst = new Encryptor(name, keyBits, 'kmac256', 1);
        dst.importState(blob);
        const pt = dst.decryptAuth(ct);
        assert.ok(bytesEqual(pt, plaintext), `hash=${name} bits=${keyBits}`);
        dst.free();
      }
    }
  });

  test('roundtrip all hashes triple', () => {
    const plaintext = concatU8(
      new TextEncoder().encode('triple-mode persistence payload '),
      new Uint8Array(Array.from({ length: 64 }, (_, i) => i)),
    );

    for (const [name, width] of CANONICAL_HASHES) {
      for (const keyBits of keyBitsFor(width)) {
        const src = new Encryptor(name, keyBits, 'kmac256', 3);
        const blob = src.exportState();
        const ct = src.encryptAuth(plaintext);
        src.free();

        const dst = new Encryptor(name, keyBits, 'kmac256', 3);
        dst.importState(blob);
        const pt = dst.decryptAuth(ct);
        assert.ok(bytesEqual(pt, plaintext), `hash=${name} bits=${keyBits}`);
        dst.free();
      }
    }
  });

  test('roundtrip with lock seed', () => {
    // Activating LockSeed grows the encryptor to 4 (Single) or 8
    // (Triple) seed slots; the exported blob carries the dedicated
    // lockSeed material via the lock_seed:true field, and importState
    // on a fresh encryptor restores the seed slot AND auto-couples
    // LockSoup + BitSoup overlays (NEXTBIND.md §6).
    const plaintext = concatU8(
      new TextEncoder().encode('lockseed payload '),
      new Uint8Array(Array.from({ length: 32 }, (_, i) => i)),
    );

    for (const [mode, expectedCount] of [[1, 4], [3, 8]] as const) {
      const src = new Encryptor('blake3', 1024, 'kmac256', mode);
      src.setLockSeed(1);
      assert.equal(src.seedCount, expectedCount, `mode=${mode}`);
      const blob = src.exportState();
      const ct = src.encryptAuth(plaintext);
      src.free();

      const dst = new Encryptor('blake3', 1024, 'kmac256', mode);
      assert.equal(dst.seedCount, expectedCount - 1, `mode=${mode} pre-import`);
      dst.importState(blob);
      assert.equal(dst.seedCount, expectedCount, `mode=${mode} post-import`);
      const pt = dst.decryptAuth(ct);
      assert.ok(bytesEqual(pt, plaintext), `mode=${mode}`);
      dst.free();
    }
  });

  test('roundtrip with full config', () => {
    // Per-instance configuration knobs (NonceBits, BarrierFill,
    // BitSoup, LockSoup) round-trip through the state blob along
    // with the seed material — no manual mirror set*() calls
    // required on the receiver. The blob carries the fields the
    // sender explicitly set; the receiver's importState restores
    // them transparently.
    const plaintext = concatU8(
      new TextEncoder().encode('full-config persistence '),
      new Uint8Array(Array.from({ length: 64 }, (_, i) => i)),
    );

    const src = new Encryptor('blake3', 1024, 'kmac256');
    src.setNonceBits(512);
    src.setBarrierFill(4);
    src.setBitSoup(1);
    src.setLockSoup(1);
    const blob = src.exportState();
    const ct = src.encryptAuth(plaintext);
    src.free();

    // Receiver — fresh encryptor without any mirror set*() calls.
    const dst = new Encryptor('blake3', 1024, 'kmac256');
    assert.equal(dst.nonceBits, 128); // default before Import
    dst.importState(blob);
    assert.equal(dst.nonceBits, 512); // restored from blob
    assert.equal(dst.headerSize, 68); // follows nonceBits

    const pt = dst.decryptAuth(ct);
    assert.ok(bytesEqual(pt, plaintext));
    dst.free();
  });

  test('roundtrip barrier fill receiver priority', () => {
    // BarrierFill is asymmetric — the receiver does not need the
    // same margin as the sender. When the receiver explicitly
    // installs a non-default BarrierFill (>1) before Import, that
    // choice takes priority over the blob's barrier_fill.
    const plaintext = new TextEncoder().encode('barrier-fill priority');

    const src = new Encryptor('blake3', 1024, 'kmac256');
    src.setBarrierFill(4);
    const blob = src.exportState();
    const ct = src.encryptAuth(plaintext);
    src.free();

    // Receiver pre-sets BarrierFill=8; Import must NOT downgrade
    // it to the blob's 4.
    const dst = new Encryptor('blake3', 1024, 'kmac256');
    dst.setBarrierFill(8);
    dst.importState(blob);
    const pt = dst.decryptAuth(ct);
    assert.ok(bytesEqual(pt, plaintext));
    dst.free();

    // A receiver that did NOT pre-set BarrierFill picks up the
    // blob value transparently.
    const dst2 = new Encryptor('blake3', 1024, 'kmac256');
    dst2.importState(blob);
    const pt2 = dst2.decryptAuth(ct);
    assert.ok(bytesEqual(pt2, plaintext));
    dst2.free();
  });

  // ─── TestPeekConfig ───────────────────────────────────────────────

  test('peek recovers metadata', () => {
    for (const [primitive, width] of CANONICAL_HASHES) {
      for (const keyBits of keyBitsFor(width)) {
        for (const mode of [1, 3]) {
          for (const mac of ['kmac256', 'hmac-sha256', 'hmac-blake3']) {
            let blob: Uint8Array;
            {
              using enc = new Encryptor(primitive, keyBits, mac, mode);
              blob = enc.exportState();
            }
            const cfg = Encryptor.peekConfig(blob);
            assert.equal(cfg.primitive, primitive);
            assert.equal(cfg.keyBits, keyBits);
            assert.equal(cfg.mode, mode);
            assert.equal(cfg.macName, mac);
          }
        }
      }
    }
  });

  test('peek malformed blob', () => {
    const blobs: Uint8Array[] = [
      new TextEncoder().encode('not json'),
      new Uint8Array(0),
      new TextEncoder().encode('{}'),
      new TextEncoder().encode('{"v":1}'),
    ];
    for (const blob of blobs) {
      assert.throws(
        () => Encryptor.peekConfig(blob),
        (err: unknown) =>
          err instanceof ITBError && err.code === Status.EasyMalformed,
        `blob=${new TextDecoder().decode(blob)}`,
      );
    }
  });

  test('peek too new version', () => {
    // Hand-craft a blob with v=99; peekConfig must reject as
    // malformed (peek conflates too-new with malformed; only the
    // import path differentiates).
    const blob = new TextEncoder().encode('{"v":99,"kind":"itb-easy"}');
    assert.throws(
      () => Encryptor.peekConfig(blob),
      (err: unknown) =>
        err instanceof ITBError && err.code === Status.EasyMalformed,
    );
  });

  // ─── TestImportMismatch ───────────────────────────────────────────

  function makeBaselineBlob(): Uint8Array {
    using src = new Encryptor('blake3', 1024, 'kmac256', 1);
    return src.exportState();
  }

  function expectMismatch(dst: Encryptor, blob: Uint8Array, field: string): void {
    assert.throws(
      () => dst.importState(blob),
      (err: unknown) =>
        err instanceof ITBEasyMismatchError &&
        err.code === Status.EasyMismatch &&
        err.field === field,
      `expected field=${field}`,
    );
  }

  test('import mismatch primitive', () => {
    const blob = makeBaselineBlob();
    using dst = new Encryptor('blake2s', 1024, 'kmac256', 1);
    expectMismatch(dst, blob, 'primitive');
  });

  test('import mismatch key bits', () => {
    const blob = makeBaselineBlob();
    using dst = new Encryptor('blake3', 2048, 'kmac256', 1);
    expectMismatch(dst, blob, 'key_bits');
  });

  test('import mismatch mode', () => {
    const blob = makeBaselineBlob();
    using dst = new Encryptor('blake3', 1024, 'kmac256', 3);
    expectMismatch(dst, blob, 'mode');
  });

  test('import mismatch mac', () => {
    const blob = makeBaselineBlob();
    using dst = new Encryptor('blake3', 1024, 'hmac-sha256', 1);
    expectMismatch(dst, blob, 'mac');
  });

  // ─── TestImportMalformed ──────────────────────────────────────────

  test('import malformed json', () => {
    using enc = new Encryptor('blake3', 1024, 'kmac256');
    assert.throws(
      () => enc.importState(new TextEncoder().encode('this is not json')),
      (err: unknown) =>
        err instanceof ITBError && err.code === Status.EasyMalformed,
    );
  });

  test('import too new version', () => {
    using enc = new Encryptor('blake3', 1024, 'kmac256');
    const blob = new TextEncoder().encode('{"v":99,"kind":"itb-easy"}');
    assert.throws(
      () => enc.importState(blob),
      (err: unknown) =>
        err instanceof ITBError && err.code === Status.EasyVersionTooNew,
    );
  });

  test('import wrong kind', () => {
    using enc = new Encryptor('blake3', 1024, 'kmac256');
    const blob = new TextEncoder().encode('{"v":1,"kind":"not-itb-easy"}');
    assert.throws(
      () => enc.importState(blob),
      (err: unknown) =>
        err instanceof ITBError && err.code === Status.EasyMalformed,
    );
  });

  // ─── TestMaterialGetters ──────────────────────────────────────────

  test('prf key lengths per primitive', () => {
    for (const [name, width] of CANONICAL_HASHES) {
      for (const keyBits of keyBitsFor(width)) {
        using enc = new Encryptor(name, keyBits, 'kmac256');
        if (name === 'siphash24') {
          assert.equal(enc.hasPRFKeys, false, `hash=${name}`);
          assert.throws(
            () => enc.prfKey(0),
            (err: unknown) => err instanceof ITBError,
            `hash=${name}`,
          );
        } else {
          assert.equal(enc.hasPRFKeys, true, `hash=${name}`);
          for (let slot = 0; slot < enc.seedCount; slot++) {
            const key = enc.prfKey(slot);
            assert.equal(
              key.length,
              EXPECTED_PRF_KEY_LEN[name],
              `hash=${name} slot=${slot}`,
            );
          }
        }
      }
    }
  });

  test('seed components lengths per key bits', () => {
    for (const [name, width] of CANONICAL_HASHES) {
      for (const keyBits of keyBitsFor(width)) {
        using enc = new Encryptor(name, keyBits, 'kmac256');
        for (let slot = 0; slot < enc.seedCount; slot++) {
          const comps = enc.seedComponents(slot);
          assert.equal(comps.length * 64, keyBits, `hash=${name} bits=${keyBits} slot=${slot}`);
        }
      }
    }
  });

  test('mac key present', () => {
    for (const mac of ['kmac256', 'hmac-sha256', 'hmac-blake3']) {
      using enc = new Encryptor('blake3', 1024, mac);
      assert.ok(enc.macKey.length > 0, `mac=${mac}`);
    }
  });

  test('seed components out of range', () => {
    using enc = new Encryptor('blake3', 1024, 'kmac256', 1);
    assert.equal(enc.seedCount, 3);
    assert.throws(
      () => enc.seedComponents(3),
      (err: unknown) =>
        err instanceof ITBError && err.code === Status.BadInput,
    );
    assert.throws(
      () => enc.seedComponents(-1),
      (err: unknown) =>
        err instanceof ITBError && err.code === Status.BadInput,
    );
  });
});
