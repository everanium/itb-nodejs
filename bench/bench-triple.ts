// Easy Mode Triple-Ouroboros benchmarks for the Node.js binding.
//
// Mirrors the BenchmarkTriple* cohort from itb3_ext_test.go for
// PRF-grade primitives, locked at 1024-bit ITB key width and 16
// MiB CSPRNG-filled payload. One mixed-primitive variant
// (`Encryptor.mixedTriple` + dedicated lockSeed) covers the
// Easy Mode Mixed surface alongside the single-primitive grid.
//
// Run with:
//
//   npm run bench:triple
//
//   ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ITB_LOCKBATCH=1 npm run bench:triple
//   ITB_NONCE_BITS=512 ITB_LOCKSEED=1 npm run bench:triple
//
//   ITB_BENCH_FILTER=blake3_encrypt npm run bench:triple
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
  MIXED_DATA1,
  MIXED_DATA2,
  MIXED_DATA3,
  MIXED_LOCK_T,
  MIXED_NOISE_T,
  MIXED_START1,
  MIXED_START2,
  MIXED_START3,
  PAYLOAD_16MB,
  PRIMITIVES_CANONICAL,
  envLockBatch,
  envLockSeed,
  envNonceBits,
  runLazy,
} from './common.js';
import type { BenchCase, LazyCase } from './common.js';
import { buildStreamLazyCasesTriple } from './bench-stream.js';

const PAYLOAD_BYTES = PAYLOAD_16MB;

/**
 * When `ITB_LOCKSEED` is set the harness flips the dedicated
 * lockSeed channel on every encryptor. Easy Mode auto-couples
 * BitSoup + LockSoup as a side effect. When `ITB_LOCKBATCH` is also
 * set, enable the Lock Batch performance Lock Soup mode on the same
 * encryptor.
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
 * Construct a single-primitive 1024-bit Triple-Ouroboros encryptor
 * with HMAC-BLAKE3 authentication. Triple = mode=3, 7-seed layout.
 */
function buildTriple(primitive: string): Encryptor {
  const enc = new Encryptor(primitive, KEY_BITS, MAC_NAME, 3);
  applyLockSeedIfRequested(enc);
  return enc;
}

/**
 * Construct a mixed-primitive Triple-Ouroboros encryptor with the
 * four-name BLAKE family across the seven middle slots. The
 * dedicated lockSeed slot is allocated only when
 * `ITB_LOCKSEED` is set, so the no-LockSeed bench arm measures the
 * plain mixed-primitive cost without the BitSoup + LockSoup
 * auto-couple. The four primitive names share the same native hash
 * width so the `Encryptor.mixedTriple` width-check passes.
 */
function buildMixedTriple(): Encryptor {
  const primL = envLockSeed() ? MIXED_LOCK_T : null;
  return Encryptor.mixedTriple(
    MIXED_NOISE_T,
    MIXED_DATA1,
    MIXED_DATA2,
    MIXED_DATA3,
    MIXED_START1,
    MIXED_START2,
    MIXED_START3,
    primL,
    KEY_BITS,
    MAC_NAME,
  );
}

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
 * Build lazy factories for the 40 message cases + 8 streaming cases.
 */
function buildLazyCases(): LazyCase[] {
  const facs: LazyCase[] = [];
  for (const prim of PRIMITIVES_CANONICAL) {
    const base = `bench_triple_${prim}_${KEY_BITS}bit`;
    const p = prim;
    facs.push([`${base}_encrypt_16mb`, () => makeEncryptCase(`${base}_encrypt_16mb`, buildTriple(p))]);
    facs.push([`${base}_decrypt_16mb`, () => makeDecryptCase(`${base}_decrypt_16mb`, buildTriple(p))]);
    facs.push([`${base}_encrypt_auth_16mb`, () => makeEncryptAuthCase(`${base}_encrypt_auth_16mb`, buildTriple(p))]);
    facs.push([`${base}_decrypt_auth_16mb`, () => makeDecryptAuthCase(`${base}_decrypt_auth_16mb`, buildTriple(p))]);
  }
  const baseMixed = `bench_triple_mixed_${KEY_BITS}bit`;
  facs.push([`${baseMixed}_encrypt_16mb`, () => makeEncryptCase(`${baseMixed}_encrypt_16mb`, buildMixedTriple())]);
  facs.push([`${baseMixed}_decrypt_16mb`, () => makeDecryptCase(`${baseMixed}_decrypt_16mb`, buildMixedTriple())]);
  facs.push([`${baseMixed}_encrypt_auth_16mb`, () => makeEncryptAuthCase(`${baseMixed}_encrypt_auth_16mb`, buildMixedTriple())]);
  facs.push([`${baseMixed}_decrypt_auth_16mb`, () => makeDecryptAuthCase(`${baseMixed}_decrypt_auth_16mb`, buildMixedTriple())]);
  facs.push(...buildStreamLazyCasesTriple());
  return facs;
}

/** Bench entry point invoked by `main.ts`. */
export async function runTriple(): Promise<void> {
  const nonceBits = envNonceBits(128);
  setMaxWorkers(0);
  setNonceBits(nonceBits);

  console.log(
    `# easy_triple primitives=${PRIMITIVES_CANONICAL.length} key_bits=${KEY_BITS} mac=${MAC_NAME} nonce_bits=${nonceBits} lockseed=${envLockSeed() ? 'on' : 'off'} workers=auto`,
  );

  await runLazy(buildLazyCases());
}
