// End-to-end Node.js binding tests for Authenticated Encryption.
//
// Mirrors bindings/python/tests/test_auth.py — exercises the same
// matrix as cmd/cshared/ctest/test_smoke.c auth section: 3 MACs ×
// 3 hash widths × {Single, Triple} round trip plus tamper rejection.

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';

import {
  decryptAuth,
  decryptAuthTriple,
  encryptAuth,
  encryptAuthTriple,
  headerSize,
  ITBError,
  listMacs,
  MAC,
  Seed,
  Status,
} from '../src/index.js';

// (name, keySize, tagSize, minKeyBytes)
const CANONICAL_MACS: ReadonlyArray<readonly [string, number, number, number]> = [
  ['kmac256', 32, 32, 16],
  ['hmac-sha256', 32, 32, 16],
  ['hmac-blake3', 32, 32, 32],
];

// (hash, width) — one representative per ITB key-width axis.
const HASH_BY_WIDTH: ReadonlyArray<readonly [string, number]> = [
  ['siphash24', 128],
  ['blake3', 256],
  ['blake2b512', 512],
];

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function tokenBytes(n: number): Uint8Array {
  return new Uint8Array(randomBytes(n));
}

describe('test_auth', () => {
  // ────────────────────────────────────────────────────────────────
  // MAC introspection.
  // ────────────────────────────────────────────────────────────────

  test('list macs', () => {
    const got = listMacs();
    assert.equal(got.length, CANONICAL_MACS.length);
    for (let i = 0; i < CANONICAL_MACS.length; i++) {
      const [name, keySize, tagSize, minKeyBytes] = CANONICAL_MACS[i]!;
      assert.equal(got[i]!.name, name);
      assert.equal(got[i]!.keySize, keySize);
      assert.equal(got[i]!.tagSize, tagSize);
      assert.equal(got[i]!.minKeyBytes, minKeyBytes);
    }
  });

  // ────────────────────────────────────────────────────────────────
  // MAC lifecycle.
  // ────────────────────────────────────────────────────────────────

  test('mac create and free', () => {
    for (const [name] of CANONICAL_MACS) {
      const m = new MAC(name, tokenBytes(32));
      assert.notEqual(Number(m.handle), 0);
      assert.equal(m.name, name);
      m.free();
      assert.equal(Number(m.handle), 0);
    }
  });

  test('mac using-disposal', () => {
    let captured: MAC | null = null;
    {
      using m = new MAC('hmac-sha256', tokenBytes(32));
      assert.notEqual(Number(m.handle), 0);
      captured = m;
    }
    assert.notEqual(captured, null);
    assert.equal(Number(captured!.handle), 0);
  });

  test('mac bad name', () => {
    assert.throws(
      () => new MAC('nonsense-mac', tokenBytes(32)),
      (err: unknown) =>
        err instanceof ITBError && err.code === Status.BadMac,
    );
  });

  test('mac short key', () => {
    for (const [name, , , minKey] of CANONICAL_MACS) {
      assert.throws(
        () => new MAC(name, tokenBytes(minKey - 1)),
        (err: unknown) =>
          err instanceof ITBError && err.code === Status.BadInput,
        `mac=${name}`,
      );
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Single Ouroboros + Auth: 3 MACs × 3 hash widths.
  // ────────────────────────────────────────────────────────────────

  test('single all macs all widths', () => {
    const plaintext = tokenBytes(4096);
    for (const [macName] of CANONICAL_MACS) {
      for (const [hashName] of HASH_BY_WIDTH) {
        using mac = new MAC(macName, tokenBytes(32));
        const seeds: Seed[] = [];
        try {
          for (let i = 0; i < 3; i++) seeds.push(new Seed(hashName, 1024));
          const [s0, s1, s2] = seeds as [Seed, Seed, Seed];
          const ct = encryptAuth(s0, s1, s2, mac, plaintext);
          const pt = decryptAuth(s0, s1, s2, mac, ct);
          assert.ok(
            bytesEqual(pt, plaintext),
            `mac=${macName} hash=${hashName}`,
          );

          // Tamper: flip 256 bytes after the dynamic header.
          const tampered = new Uint8Array(ct);
          const h = headerSize();
          const end = Math.min(h + 256, tampered.length);
          for (let i = h; i < end; i++) tampered[i]! ^= 0x01;
          assert.throws(
            () => decryptAuth(s0, s1, s2, mac, tampered),
            (err: unknown) =>
              err instanceof ITBError && err.code === Status.MacFailure,
            `mac=${macName} hash=${hashName} tamper`,
          );
        } finally {
          for (const s of seeds) s.free();
        }
      }
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Triple Ouroboros + Auth: 3 MACs × 3 hash widths × 7 seeds.
  // ────────────────────────────────────────────────────────────────

  test('triple all macs all widths', () => {
    const plaintext = tokenBytes(4096);
    for (const [macName] of CANONICAL_MACS) {
      for (const [hashName] of HASH_BY_WIDTH) {
        using mac = new MAC(macName, tokenBytes(32));
        const seeds: Seed[] = [];
        try {
          for (let i = 0; i < 7; i++) seeds.push(new Seed(hashName, 1024));
          const [s0, s1, s2, s3, s4, s5, s6] = seeds as [
            Seed, Seed, Seed, Seed, Seed, Seed, Seed,
          ];
          const ct = encryptAuthTriple(s0, s1, s2, s3, s4, s5, s6, mac, plaintext);
          const pt = decryptAuthTriple(s0, s1, s2, s3, s4, s5, s6, mac, ct);
          assert.ok(
            bytesEqual(pt, plaintext),
            `mac=${macName} hash=${hashName}`,
          );

          const tampered = new Uint8Array(ct);
          const h = headerSize();
          const end = Math.min(h + 256, tampered.length);
          for (let i = h; i < end; i++) tampered[i]! ^= 0x01;
          assert.throws(
            () => decryptAuthTriple(s0, s1, s2, s3, s4, s5, s6, mac, tampered),
            (err: unknown) =>
              err instanceof ITBError && err.code === Status.MacFailure,
            `mac=${macName} hash=${hashName} tamper`,
          );
        } finally {
          for (const s of seeds) s.free();
        }
      }
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Cross-MAC rejection: encrypt with one MAC handle, attempt decrypt
  // with a different handle (different primitive or different key).
  // Must surface STATUS_MAC_FAILURE rather than corrupting plaintext.
  // ────────────────────────────────────────────────────────────────

  test('different primitive', () => {
    const seeds: Seed[] = [];
    try {
      for (let i = 0; i < 3; i++) seeds.push(new Seed('blake3', 1024));
      const [s0, s1, s2] = seeds as [Seed, Seed, Seed];
      using encMac = new MAC('kmac256', tokenBytes(32));
      using decMac = new MAC('hmac-sha256', tokenBytes(32));
      const ct = encryptAuth(
        s0, s1, s2, encMac,
        new TextEncoder().encode('authenticated payload'),
      );
      assert.throws(
        () => decryptAuth(s0, s1, s2, decMac, ct),
        (err: unknown) =>
          err instanceof ITBError && err.code === Status.MacFailure,
      );
    } finally {
      for (const s of seeds) s.free();
    }
  });

  test('same primitive different key', () => {
    const seeds: Seed[] = [];
    try {
      for (let i = 0; i < 3; i++) seeds.push(new Seed('blake3', 1024));
      const [s0, s1, s2] = seeds as [Seed, Seed, Seed];
      using encMac = new MAC('hmac-sha256', tokenBytes(32));
      using decMac = new MAC('hmac-sha256', tokenBytes(32));
      const ct = encryptAuth(
        s0, s1, s2, encMac,
        new TextEncoder().encode('authenticated payload'),
      );
      assert.throws(
        () => decryptAuth(s0, s1, s2, decMac, ct),
        (err: unknown) =>
          err instanceof ITBError && err.code === Status.MacFailure,
      );
    } finally {
      for (const s of seeds) s.free();
    }
  });
});
