// Easy Mode Triple-Ouroboros benchmarks for the Node.js binding.
//
// Mirrors the BenchmarkTriple* cohort from itb3_ext_test.go for the
// nine PRF-grade primitives, locked at 1024-bit ITB key width and 16
// MiB CSPRNG-filled payload. One mixed-primitive variant
// (`Encryptor.mixedTriple` cycling the same BLAKE family +
// Areion-SoEM-256 dedicated lockSeed used by bench_single's mixed
// case) covers the Easy Mode Mixed surface alongside the
// single-primitive grid.
//
// Run with:
//
//   npm run bench:triple
//
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
  envLockSeed,
  envNonceBits,
  runAll,
} from './common.js';
import type { BenchCase } from './common.js';
import { buildStreamCasesTriple } from './bench-stream.js';

const PAYLOAD_BYTES = PAYLOAD_16MB;

/**
 * When `ITB_LOCKSEED` is set the harness flips the dedicated
 * lockSeed channel on every encryptor. Easy Mode auto-couples
 * BitSoup + LockSoup as a side effect.
 */
function applyLockSeedIfRequested(enc: Encryptor): void {
  if (envLockSeed()) {
    enc.setLockSeed(1);
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
 * dedicated Areion-SoEM-256 lockSeed slot is allocated only when
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
 * Assemble the full case list: 9 single-primitive entries × 4 ops
 * plus 1 mixed entry × 4 ops = 40 cases. Order is primitive-major /
 * op-minor so a filter on a primitive name keeps all four ops
 * grouped together in the output.
 */
function buildCases(): BenchCase[] {
  const cases: BenchCase[] = [];
  for (const prim of PRIMITIVES_CANONICAL) {
    const base = `bench_triple_${prim}_${KEY_BITS}bit`;
    cases.push(makeEncryptCase(`${base}_encrypt_16mb`, buildTriple(prim)));
    cases.push(makeDecryptCase(`${base}_decrypt_16mb`, buildTriple(prim)));
    cases.push(
      makeEncryptAuthCase(`${base}_encrypt_auth_16mb`, buildTriple(prim)),
    );
    cases.push(
      makeDecryptAuthCase(`${base}_decrypt_auth_16mb`, buildTriple(prim)),
    );
  }
  const baseMixed = `bench_triple_mixed_${KEY_BITS}bit`;
  cases.push(makeEncryptCase(`${baseMixed}_encrypt_16mb`, buildMixedTriple()));
  cases.push(makeDecryptCase(`${baseMixed}_decrypt_16mb`, buildMixedTriple()));
  cases.push(
    makeEncryptAuthCase(
      `${baseMixed}_encrypt_auth_16mb`,
      buildMixedTriple(),
    ),
  );
  cases.push(
    makeDecryptAuthCase(
      `${baseMixed}_decrypt_auth_16mb`,
      buildMixedTriple(),
    ),
  );
  return cases;
}

/** Bench entry point invoked by `main.ts`. */
export async function runTriple(): Promise<void> {
  const nonceBits = envNonceBits(128);
  setMaxWorkers(0);
  setNonceBits(nonceBits);

  console.log(
    `# easy_triple primitives=${PRIMITIVES_CANONICAL.length} key_bits=${KEY_BITS} mac=${MAC_NAME} nonce_bits=${nonceBits} lockseed=${envLockSeed() ? 'on' : 'off'} workers=auto`,
  );

  const cases = buildCases();
  cases.push(...buildStreamCasesTriple());
  await runAll(cases);
}
