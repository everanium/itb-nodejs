// Mixed-mode Encryptor (per-slot PRF primitive selection) tests for
// the Node.js / TypeScript binding. Mirrors the Python coverage:
// round-trip on Single + Triple, optional dedicated lockSeed under
// its own primitive, state-blob Export / Import, mixed-width
// rejection through the cgo boundary, and the per-slot introspection
// accessors (primitiveAt, isMixed).

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';

import {
  Encryptor,
  ITBError,
} from '../../src/index.js';

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function asU8(buf: Uint8Array | Buffer): Uint8Array {
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength).slice();
}

describe('test_easy_mixed', () => {
  // ─── TestMixedSingle ──────────────────────────────────────────────

  test('mixed single basic roundtrip', () => {
    const enc = Encryptor.mixedSingle(
      'blake3',     // primN
      'blake2s',    // primD
      'areion256',  // primS
      null,         // primL
      1024,
      'kmac256',
    );
    try {
      assert.equal(enc.isMixed, true);
      assert.equal(enc.primitive, 'mixed');
      assert.equal(enc.primitiveAt(0), 'blake3');
      assert.equal(enc.primitiveAt(1), 'blake2s');
      assert.equal(enc.primitiveAt(2), 'areion256');

      const plaintext = new TextEncoder().encode('node mixed Single roundtrip payload');
      const ct = enc.encrypt(plaintext);
      assert.ok(bytesEqual(enc.decrypt(ct), plaintext));
    } finally {
      enc.free();
    }
  });

  test('mixed single with dedicated lockseed', () => {
    const enc = Encryptor.mixedSingle(
      'blake3',
      'blake2s',
      'blake3',
      'areion256',
      1024,
      'kmac256',
    );
    try {
      assert.equal(enc.primitiveAt(3), 'areion256');
      const plaintext = new TextEncoder().encode(
        'node mixed Single + dedicated lockSeed payload',
      );
      const ct = enc.encryptAuth(plaintext);
      assert.ok(bytesEqual(enc.decryptAuth(ct), plaintext));
    } finally {
      enc.free();
    }
  });

  test('mixed single aescmac siphash 128bit', () => {
    // SipHash-2-4 in one slot + AES-CMAC in others — 128-bit width
    // with mixed key shapes (siphash24 carries no fixed key bytes,
    // aescmac carries 16). Exercises the per-slot empty / non-empty
    // PRF-key validation in Export / Import.
    const enc = Encryptor.mixedSingle(
      'aescmac',
      'siphash24',
      'aescmac',
      null,
      512,
      'hmac-sha256',
    );
    try {
      const plaintext = new TextEncoder().encode(
        'node mixed 128-bit aescmac+siphash24 mix',
      );
      const ct = enc.encrypt(plaintext);
      assert.ok(bytesEqual(enc.decrypt(ct), plaintext));
    } finally {
      enc.free();
    }
  });

  // ─── TestMixedTriple ──────────────────────────────────────────────

  test('mixed triple basic roundtrip', () => {
    const enc = Encryptor.mixedTriple(
      'areion256',  // primN
      'blake3',     // primD1
      'blake2s',    // primD2
      'chacha20',   // primD3
      'blake2b256', // primS1
      'blake3',     // primS2
      'blake2s',    // primS3
      null,         // primL
      1024,
      'kmac256',
    );
    try {
      const wants = [
        'areion256', 'blake3', 'blake2s', 'chacha20',
        'blake2b256', 'blake3', 'blake2s',
      ];
      for (let i = 0; i < wants.length; i++) {
        assert.equal(enc.primitiveAt(i), wants[i]);
      }
      const plaintext = new TextEncoder().encode('node mixed Triple roundtrip payload');
      const ct = enc.encrypt(plaintext);
      assert.ok(bytesEqual(enc.decrypt(ct), plaintext));
    } finally {
      enc.free();
    }
  });

  test('mixed triple with dedicated lockseed', () => {
    const enc = Encryptor.mixedTriple(
      'blake3',
      'blake2s',
      'blake3',
      'blake2s',
      'blake3',
      'blake2s',
      'blake3',
      'areion256',
      1024,
      'kmac256',
    );
    try {
      assert.equal(enc.primitiveAt(7), 'areion256');
      const base = 'node mixed Triple + lockSeed payload';
      const plaintext = new TextEncoder().encode(base.repeat(16));
      const ct = enc.encryptAuth(plaintext);
      assert.ok(bytesEqual(enc.decryptAuth(ct), plaintext));
    } finally {
      enc.free();
    }
  });

  // ─── TestMixedExportImport ────────────────────────────────────────

  test('mixed single export import', () => {
    const plaintext = asU8(randomBytes(2048));
    let blob: Uint8Array;
    let ct: Uint8Array;
    const sender = Encryptor.mixedSingle(
      'blake3', 'blake2s', 'areion256', null, 1024, 'kmac256',
    );
    try {
      ct = sender.encryptAuth(plaintext);
      blob = sender.exportState();
      assert.ok(blob.length > 0);
    } finally {
      sender.free();
    }

    const receiver = Encryptor.mixedSingle(
      'blake3', 'blake2s', 'areion256', null, 1024, 'kmac256',
    );
    try {
      receiver.importState(blob);
      assert.ok(bytesEqual(receiver.decryptAuth(ct), plaintext));
    } finally {
      receiver.free();
    }
  });

  test('mixed triple export import with lockseed', () => {
    const plaintext = new TextEncoder().encode(
      'node mixed Triple + lockSeed Export/Import'.repeat(16),
    );
    let blob: Uint8Array;
    let ct: Uint8Array;
    const sender = Encryptor.mixedTriple(
      'areion256', 'blake3', 'blake2s', 'chacha20',
      'blake2b256', 'blake3', 'blake2s',
      'areion256', 1024, 'kmac256',
    );
    try {
      ct = sender.encryptAuth(plaintext);
      blob = sender.exportState();
    } finally {
      sender.free();
    }

    const receiver = Encryptor.mixedTriple(
      'areion256', 'blake3', 'blake2s', 'chacha20',
      'blake2b256', 'blake3', 'blake2s',
      'areion256', 1024, 'kmac256',
    );
    try {
      receiver.importState(blob);
      assert.ok(bytesEqual(receiver.decryptAuth(ct), plaintext));
    } finally {
      receiver.free();
    }
  });

  test('mixed shape mismatch', () => {
    // Mixed blob landing on a single-primitive receiver must be
    // rejected as a primitive mismatch.
    let mixedBlob: Uint8Array;
    const mixedSender = Encryptor.mixedSingle(
      'blake3', 'blake2s', 'blake3', null, 1024, 'kmac256',
    );
    try {
      mixedBlob = mixedSender.exportState();
    } finally {
      mixedSender.free();
    }

    const singleRecv = new Encryptor('blake3', 1024, 'kmac256');
    try {
      assert.throws(
        () => singleRecv.importState(mixedBlob),
        (err: unknown) => err instanceof ITBError,
      );
    } finally {
      singleRecv.free();
    }
  });

  // ─── TestMixedRejection ───────────────────────────────────────────

  test('reject mixed width', () => {
    // Mixing a 256-bit primitive with a 512-bit primitive surfaces
    // as ITBError (panic-to-Status path on the Go side).
    assert.throws(
      () => Encryptor.mixedSingle(
        'blake3',     // 256-bit
        'areion512',  // 512-bit ← width mismatch
        'blake3',
        null,
        1024,
        'kmac256',
      ),
      (err: unknown) => err instanceof ITBError,
    );
  });

  test('reject unknown primitive', () => {
    assert.throws(
      () => Encryptor.mixedSingle(
        'no-such-primitive',
        'blake3',
        'blake3',
        null,
        1024,
        'kmac256',
      ),
      (err: unknown) => err instanceof ITBError,
    );
  });

  // ─── TestMixedNonMixed ────────────────────────────────────────────

  test('default constructor is not mixed', () => {
    using enc = new Encryptor('blake3', 1024, 'kmac256');
    assert.equal(enc.isMixed, false);
    for (let i = 0; i < 3; i++) {
      assert.equal(enc.primitiveAt(i), 'blake3');
    }
  });
});
