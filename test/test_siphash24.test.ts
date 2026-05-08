// SipHash-2-4-focused Node.js / TypeScript binding coverage.
//
// Mirrors bindings/python/tests/test_siphash24.py one-to-one. Each
// Python TestCase.test_* becomes a single test() here; the
// per-class subTest loops are inlined since node:test has no
// equivalent of unittest subTest — assertion messages carry the
// loop coordinates so a failing iteration is locatable.
//
// Every test mutates the process-global nonce_bits, so each
// withNonceBits() bracket saves + restores around the loop body.
// node:test runs each test file in its own child process, so
// cross-file races against other primitives' tests do not occur.

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';

import {
  decrypt,
  decryptAuth,
  decryptAuthTriple,
  decryptTriple,
  encrypt,
  encryptAuth,
  encryptAuthTriple,
  encryptTriple,
  getNonceBits,
  headerSize,
  ITBError,
  MAC,
  parseChunkLen,
  Seed,
  setNonceBits,
  Status,
} from '../src/index.js';

// (hash, ITB_seed_width) — SipHash ships only at -128.
const SIPHASH_HASHES: ReadonlyArray<readonly [string, number]> = [
  ['siphash24', 128],
];

// Hash-key length (bytes) per primitive — SipHash has no internal
// fixed key (keyed by seed components), so the FFI hash_key field
// is empty.
const EXPECTED_KEY_LEN: Record<string, number> = {
  siphash24: 0,
};

const NONCE_SIZES: readonly number[] = [128, 256, 512];

const MAC_NAMES: readonly string[] = ['kmac256', 'hmac-sha256', 'hmac-blake3'];

function withNonceBits<T>(n: number, fn: () => T): T {
  const orig = getNonceBits();
  setNonceBits(n);
  try {
    return fn();
  } finally {
    setNonceBits(orig);
  }
}

function tokenBytes(n: number): Uint8Array {
  return new Uint8Array(randomBytes(n));
}

function assertBytesEqual(
  actual: Uint8Array,
  expected: Uint8Array,
  label: string,
): void {
  assert.equal(actual.length, expected.length, `${label} length`);
  const a = Buffer.from(actual.buffer, actual.byteOffset, actual.byteLength);
  const b = Buffer.from(expected.buffer, expected.byteOffset, expected.byteLength);
  assert.equal(Buffer.compare(a, b), 0, `${label} content`);
}

describe('test_siphash24', () => {
  test('roundtrip across nonce sizes', () => {
    const plaintext = tokenBytes(1024);
    for (const n of NONCE_SIZES) {
      for (const [hashName] of SIPHASH_HASHES) {
        withNonceBits(n, () => {
          using s0 = new Seed(hashName, 1024);
          using s1 = new Seed(hashName, 1024);
          using s2 = new Seed(hashName, 1024);
          const ct = encrypt(s0, s1, s2, plaintext);
          const pt = decrypt(s0, s1, s2, ct);
          assertBytesEqual(pt, plaintext, `nonce=${n} hash=${hashName}`);
          assert.equal(
            parseChunkLen(ct.subarray(0, headerSize())),
            ct.length,
            `nonce=${n} hash=${hashName} chunk-len`,
          );
        });
      }
    }
  });

  test('triple roundtrip across nonce sizes', () => {
    const plaintext = tokenBytes(1024);
    for (const n of NONCE_SIZES) {
      for (const [hashName] of SIPHASH_HASHES) {
        withNonceBits(n, () => {
          const seeds: Seed[] = [];
          for (let i = 0; i < 7; i++) {
            seeds.push(new Seed(hashName, 1024));
          }
          try {
            const [s0, s1, s2, s3, s4, s5, s6] = seeds as [
              Seed, Seed, Seed, Seed, Seed, Seed, Seed,
            ];
            const ct = encryptTriple(s0, s1, s2, s3, s4, s5, s6, plaintext);
            const pt = decryptTriple(s0, s1, s2, s3, s4, s5, s6, ct);
            assertBytesEqual(pt, plaintext, `nonce=${n} hash=${hashName}`);
          } finally {
            for (const s of seeds) s.free();
          }
        });
      }
    }
  });

  test('auth across nonce sizes', () => {
    const plaintext = tokenBytes(1024);
    for (const n of NONCE_SIZES) {
      for (const macName of MAC_NAMES) {
        for (const [hashName] of SIPHASH_HASHES) {
          withNonceBits(n, () => {
            using mac = new MAC(macName, tokenBytes(32));
            using s0 = new Seed(hashName, 1024);
            using s1 = new Seed(hashName, 1024);
            using s2 = new Seed(hashName, 1024);
            const ct = encryptAuth(s0, s1, s2, mac, plaintext);
            const pt = decryptAuth(s0, s1, s2, mac, ct);
            assertBytesEqual(
              pt, plaintext,
              `nonce=${n} mac=${macName} hash=${hashName}`,
            );
            const tampered = new Uint8Array(ct);
            const h = headerSize();
            const end = Math.min(h + 256, tampered.length);
            for (let i = h; i < end; i++) tampered[i]! ^= 0x01;
            assert.throws(
              () => decryptAuth(s0, s1, s2, mac, tampered),
              (err: unknown) =>
                err instanceof ITBError && err.code === Status.MacFailure,
              `nonce=${n} mac=${macName} hash=${hashName} tamper`,
            );
          });
        }
      }
    }
  });

  test('triple auth across nonce sizes', () => {
    const plaintext = tokenBytes(1024);
    for (const n of NONCE_SIZES) {
      for (const macName of MAC_NAMES) {
        for (const [hashName] of SIPHASH_HASHES) {
          withNonceBits(n, () => {
            using mac = new MAC(macName, tokenBytes(32));
            const seeds: Seed[] = [];
            for (let i = 0; i < 7; i++) {
              seeds.push(new Seed(hashName, 1024));
            }
            try {
              const [s0, s1, s2, s3, s4, s5, s6] = seeds as [
                Seed, Seed, Seed, Seed, Seed, Seed, Seed,
              ];
              const ct = encryptAuthTriple(
                s0, s1, s2, s3, s4, s5, s6, mac, plaintext,
              );
              const pt = decryptAuthTriple(
                s0, s1, s2, s3, s4, s5, s6, mac, ct,
              );
              assertBytesEqual(
                pt, plaintext,
                `nonce=${n} mac=${macName} hash=${hashName}`,
              );
              const tampered = new Uint8Array(ct);
              const h = headerSize();
              const end = Math.min(h + 256, tampered.length);
              for (let i = h; i < end; i++) tampered[i]! ^= 0x01;
              assert.throws(
                () => decryptAuthTriple(
                  s0, s1, s2, s3, s4, s5, s6, mac, tampered,
                ),
                (err: unknown) =>
                  err instanceof ITBError && err.code === Status.MacFailure,
                `nonce=${n} mac=${macName} hash=${hashName} tamper`,
              );
            } finally {
              for (const s of seeds) s.free();
            }
          });
        }
      }
    }
  });

  test('persistence across nonce sizes', () => {
    const head = new TextEncoder().encode('persistence payload ');
    const tail = tokenBytes(1024);
    const plaintext = new Uint8Array(head.length + tail.length);
    plaintext.set(head, 0);
    plaintext.set(tail, head.length);

    for (const [hashName, width] of SIPHASH_HASHES) {
      const validKeyBits = [512, 1024, 2048].filter((k) => k % width === 0);
      for (const keyBits of validKeyBits) {
        for (const n of NONCE_SIZES) {
          withNonceBits(n, () => {
            const ns = new Seed(hashName, keyBits);
            const ds = new Seed(hashName, keyBits);
            const ss = new Seed(hashName, keyBits);

            let nsComps: bigint[];
            let nsKey: Uint8Array;
            let dsComps: bigint[];
            let dsKey: Uint8Array;
            let ssComps: bigint[];
            let ssKey: Uint8Array;
            let ciphertext: Uint8Array;
            try {
              nsComps = ns.components;
              nsKey = ns.hashKey;
              dsComps = ds.components;
              dsKey = ds.hashKey;
              ssComps = ss.components;
              ssKey = ss.hashKey;

              assert.equal(
                nsKey.length, EXPECTED_KEY_LEN[hashName],
                `hash=${hashName} key_bits=${keyBits} nonce=${n} key-len`,
              );
              assert.equal(
                nsComps.length * 64, keyBits,
                `hash=${hashName} key_bits=${keyBits} nonce=${n} comps`,
              );

              ciphertext = encrypt(ns, ds, ss, plaintext);
            } finally {
              ns.free();
              ds.free();
              ss.free();
            }

            const ns2 = Seed.fromComponents(hashName, nsComps, nsKey);
            const ds2 = Seed.fromComponents(hashName, dsComps, dsKey);
            const ss2 = Seed.fromComponents(hashName, ssComps, ssKey);
            try {
              const decrypted = decrypt(ns2, ds2, ss2, ciphertext);
              assertBytesEqual(
                decrypted, plaintext,
                `hash=${hashName} key_bits=${keyBits} nonce=${n} day2`,
              );
            } finally {
              ns2.free();
              ds2.free();
              ss2.free();
            }
          });
        }
      }
    }
  });

  test('roundtrip sizes', () => {
    const SIZES: readonly number[] = [1, 17, 4096, 65536, 1 << 20];
    for (const [hashName] of SIPHASH_HASHES) {
      for (const n of NONCE_SIZES) {
        for (const sz of SIZES) {
          withNonceBits(n, () => {
            const plaintext = tokenBytes(sz);
            using ns = new Seed(hashName, 1024);
            using ds = new Seed(hashName, 1024);
            using ss = new Seed(hashName, 1024);
            const ct = encrypt(ns, ds, ss, plaintext);
            const pt = decrypt(ns, ds, ss, ct);
            assertBytesEqual(
              pt, plaintext,
              `hash=${hashName} nonce=${n} size=${sz}`,
            );
          });
        }
      }
    }
  });
});
