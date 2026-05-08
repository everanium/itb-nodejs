// Easy Mode Single-Ouroboros benchmarks for the Node.js binding.
//
// Mirrors the BenchmarkSingle* cohort from itb_ext_test.go for the
// nine PRF-grade primitives, locked at 1024-bit ITB key width and 16
// MiB CSPRNG-filled payload. One mixed-primitive variant
// (`Encryptor.mixedSingle` with BLAKE3 / BLAKE2s / BLAKE2b-256 +
// Areion-SoEM-256 dedicated lockSeed) covers the Easy Mode Mixed
// surface alongside the single-primitive grid.
//
// Run with:
//
//   npm run bench:single
//
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
  envLockSeed,
  envNonceBits,
  runAll,
} from './common.js';
import type { BenchCase } from './common.js';
import { buildStreamCasesSingle } from './bench-stream.js';

const PAYLOAD_BYTES = PAYLOAD_16MB;

/**
 * When `ITB_LOCKSEED` is set the harness flips the dedicated
 * lockSeed channel on every encryptor. Easy Mode auto-couples
 * BitSoup + LockSoup as a side effect, so no separate calls are
 * issued.
 */
function applyLockSeedIfRequested(enc: Encryptor): void {
  if (envLockSeed()) {
    enc.setLockSeed(1);
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
 * BLAKE2b-256 start). The dedicated Areion-SoEM-256 lockSeed slot is
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

/**
 * Assemble the full case list: 9 single-primitive entries × 4 ops
 * plus 1 mixed entry × 4 ops = 40 cases. Order is primitive-major /
 * op-minor so a filter on a primitive name keeps all four ops
 * grouped together in the output.
 */
function buildCases(): BenchCase[] {
  const cases: BenchCase[] = [];
  for (const prim of PRIMITIVES_CANONICAL) {
    const base = `bench_single_${prim}_${KEY_BITS}bit`;
    cases.push(makeEncryptCase(`${base}_encrypt_16mb`, buildSingle(prim)));
    cases.push(makeDecryptCase(`${base}_decrypt_16mb`, buildSingle(prim)));
    cases.push(
      makeEncryptAuthCase(`${base}_encrypt_auth_16mb`, buildSingle(prim)),
    );
    cases.push(
      makeDecryptAuthCase(`${base}_decrypt_auth_16mb`, buildSingle(prim)),
    );
  }
  const baseMixed = `bench_single_mixed_${KEY_BITS}bit`;
  cases.push(makeEncryptCase(`${baseMixed}_encrypt_16mb`, buildMixedSingle()));
  cases.push(makeDecryptCase(`${baseMixed}_decrypt_16mb`, buildMixedSingle()));
  cases.push(
    makeEncryptAuthCase(
      `${baseMixed}_encrypt_auth_16mb`,
      buildMixedSingle(),
    ),
  );
  cases.push(
    makeDecryptAuthCase(
      `${baseMixed}_decrypt_auth_16mb`,
      buildMixedSingle(),
    ),
  );
  return cases;
}

/** Bench entry point invoked by `main.ts`. */
export async function runSingle(): Promise<void> {
  const nonceBits = envNonceBits(128);
  setMaxWorkers(0);
  setNonceBits(nonceBits);

  console.log(
    `# easy_single primitives=${PRIMITIVES_CANONICAL.length} key_bits=${KEY_BITS} mac=${MAC_NAME} nonce_bits=${nonceBits} lockseed=${envLockSeed() ? 'on' : 'off'} workers=auto`,
  );

  const cases = buildCases();
  cases.push(...buildStreamCasesSingle());
  await runAll(cases);
}
