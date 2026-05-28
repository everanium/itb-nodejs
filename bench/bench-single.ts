// Easy Mode Single-Ouroboros benchmarks for the Node.js binding.
//
// Mirrors the BenchmarkSingle* cohort from itb_ext_test.go for
// PRF-grade primitives, locked at 1024-bit ITB key width and 16
// MiB CSPRNG-filled payload. One mixed-primitive variant
// (`Encryptor.mixedSingle` + dedicated lockSeed) covers the
// Easy Mode Mixed surface alongside the single-primitive grid.
//
// Run with:
//
//   npm run bench:single
//
//   ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ITB_LOCKBATCH=1 npm run bench:single
//   ITB_NONCE_BITS=512 ITB_LOCKSEED=1 npm run bench:single
//
//   ITB_BENCH_FILTER=blake3_encrypt npm run bench:single
//
// The harness emits one Go-bench-style line per case (name, iters,
// ns/op, MB/s). See `common.ts` for the supported environment
// variables and the convergence policy.

/* eslint-disable no-console */

import { randomBytes } from 'node:crypto';

import { Encryptor } from '../src/encryptor.js';
import { setMaxWorkers, setNonceBits } from '../src/library.js';

import {
  KEY_BITS,
  MAC_NAME,
  MIXED_DATA,
  MIXED_LOCK,
  MIXED_NOISE,
  MIXED_START,
  PAYLOAD_16MB,
  PRIMITIVES_CANONICAL,
  envLockBatch,
  envLockSeed,
  envNonceBits,
  runLazy,
} from './common.js';
import type { BenchCase, LazyCase } from './common.js';
import { buildStreamLazyCasesSingle } from './bench-stream.js';

const PAYLOAD_BYTES = PAYLOAD_16MB;

/**
 * When `ITB_LOCKSEED` is set the harness flips the dedicated
 * lockSeed channel on every encryptor. Easy Mode auto-couples
 * BitSoup + LockSoup as a side effect, so no separate calls are
 * issued. When `ITB_LOCKBATCH` is also set, enable the Lock Batch
 * performance Lock Soup mode on the same encryptor.
 */
function applyLockSeedIfRequested(enc: Encryptor): void {
  if (envLockSeed()) {
    enc.setLockSeed(1);
  }
  if (envLockBatch()) {
    enc.setLockBatch(1);
  }
}

/**
 * Construct a single-primitive 1024-bit Single-Ouroboros encryptor
 * with HMAC-BLAKE3 authentication, mirroring the shape used by every
 * benchmark in this module.
 */
function buildSingle(primitive: string): Encryptor {
  const enc = new Encryptor(primitive, KEY_BITS, MAC_NAME, 1);
  applyLockSeedIfRequested(enc);
  return enc;
}

/**
 * Construct a mixed-primitive Single-Ouroboros encryptor matching
 * the README Quick Start composition (BLAKE3 noise / BLAKE2s data /
 * BLAKE2b-256 start). The dedicated lockSeed slot is
 * allocated only when `ITB_LOCKSEED` is set, so the no-LockSeed
 * bench arm measures the plain mixed-primitive cost without the
 * BitSoup + LockSoup auto-couple. The four primitive names share
 * the 256-bit native hash width.
 */
function buildMixedSingle(): Encryptor {
  // When `primL` is set, mixedSingle auto-couples BitSoup + LockSoup
  // on construction; an extra setLockSeed call would be a redundant
  // no-op against the already-active lockSeed slot. When `primL` is
  // null the encryptor stays in plain mixed mode.
  const primL = envLockSeed() ? MIXED_LOCK : null;
  return Encryptor.mixedSingle(
    MIXED_NOISE,
    MIXED_DATA,
    MIXED_START,
    primL,
    KEY_BITS,
    MAC_NAME,
  );
}

/**
 * Build a plain-Encrypt bench case. Encryptor + payload are
 * constructed once outside the measured loop; only the encrypt call
 * is timed.
 */
function makeEncryptCase(name: string, enc: Encryptor): BenchCase {
  const payload = new Uint8Array(randomBytes(PAYLOAD_BYTES));
  return {
    name,
    run: (iters: number) => {
      for (let i = 0; i < iters; i++) {
        enc.encrypt(payload);
      }
    },
    payloadBytes: PAYLOAD_BYTES,
  };
}

/**
 * Build a plain-Decrypt bench case. Pre-encrypts a single
 * ciphertext outside the measured loop; only the decrypt call is
 * timed.
 */
function makeDecryptCase(name: string, enc: Encryptor): BenchCase {
  const payload = new Uint8Array(randomBytes(PAYLOAD_BYTES));
  const ciphertext = enc.encrypt(payload);
  return {
    name,
    run: (iters: number) => {
      for (let i = 0; i < iters; i++) {
        enc.decrypt(ciphertext);
      }
    },
    payloadBytes: PAYLOAD_BYTES,
  };
}

/** Build an authenticated-Encrypt bench case (MAC tag attached). */
function makeEncryptAuthCase(name: string, enc: Encryptor): BenchCase {
  const payload = new Uint8Array(randomBytes(PAYLOAD_BYTES));
  return {
    name,
    run: (iters: number) => {
      for (let i = 0; i < iters; i++) {
        enc.encryptAuth(payload);
      }
    },
    payloadBytes: PAYLOAD_BYTES,
  };
}

/**
 * Build an authenticated-Decrypt bench case (MAC tag verified on
 * the way back).
 */
function makeDecryptAuthCase(name: string, enc: Encryptor): BenchCase {
  const payload = new Uint8Array(randomBytes(PAYLOAD_BYTES));
  const ciphertext = enc.encryptAuth(payload);
  return {
    name,
    run: (iters: number) => {
      for (let i = 0; i < iters; i++) {
        enc.decryptAuth(ciphertext);
      }
    },
    payloadBytes: PAYLOAD_BYTES,
  };
}

/** Build lazy factories for the 40 message cases + 8 streaming cases. */
function buildLazyCases(): LazyCase[] {
  const facs: LazyCase[] = [];
  for (const prim of PRIMITIVES_CANONICAL) {
    const base = `bench_single_${prim}_${KEY_BITS}bit`;
    const p = prim;
    facs.push([`${base}_encrypt_16mb`, () => makeEncryptCase(`${base}_encrypt_16mb`, buildSingle(p))]);
    facs.push([`${base}_decrypt_16mb`, () => makeDecryptCase(`${base}_decrypt_16mb`, buildSingle(p))]);
    facs.push([`${base}_encrypt_auth_16mb`, () => makeEncryptAuthCase(`${base}_encrypt_auth_16mb`, buildSingle(p))]);
    facs.push([`${base}_decrypt_auth_16mb`, () => makeDecryptAuthCase(`${base}_decrypt_auth_16mb`, buildSingle(p))]);
  }
  const baseMixed = `bench_single_mixed_${KEY_BITS}bit`;
  facs.push([`${baseMixed}_encrypt_16mb`, () => makeEncryptCase(`${baseMixed}_encrypt_16mb`, buildMixedSingle())]);
  facs.push([`${baseMixed}_decrypt_16mb`, () => makeDecryptCase(`${baseMixed}_decrypt_16mb`, buildMixedSingle())]);
  facs.push([`${baseMixed}_encrypt_auth_16mb`, () => makeEncryptAuthCase(`${baseMixed}_encrypt_auth_16mb`, buildMixedSingle())]);
  facs.push([`${baseMixed}_decrypt_auth_16mb`, () => makeDecryptAuthCase(`${baseMixed}_decrypt_auth_16mb`, buildMixedSingle())]);
  facs.push(...buildStreamLazyCasesSingle());
  return facs;
}

/** Bench entry point invoked by `main.ts`. */
export async function runSingle(): Promise<void> {
  const nonceBits = envNonceBits(128);
  setMaxWorkers(0);
  setNonceBits(nonceBits);

  console.log(
    `# easy_single primitives=${PRIMITIVES_CANONICAL.length} key_bits=${KEY_BITS} mac=${MAC_NAME} nonce_bits=${nonceBits} lockseed=${envLockSeed() ? 'on' : 'off'} workers=auto`,
  );

  await runLazy(buildLazyCases());
}
