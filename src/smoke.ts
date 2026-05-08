// Manual smoke runner exercising Phase 1-3:
// - libitb dlopen + metadata (Phase 1)
// - status / errors / global setters (Phase 2)
// - Seed + MAC + low-level encrypt/decrypt (Phase 3)
//
// Run after `npm run build`:
//
//     node dist/smoke.js
//
// or directly via Node 22+'s native type stripping:
//
//     node --experimental-strip-types src/smoke.ts

import { randomBytes } from 'node:crypto';

import {
  channels,
  decrypt,
  decryptAuth,
  decryptAuthTriple,
  decryptTriple,
  encrypt,
  encryptAuth,
  encryptAuthTriple,
  encryptTriple,
  getBarrierFill,
  getNonceBits,
  headerSize,
  ITBError,
  libraryPath,
  listHashes,
  listMacs,
  MAC,
  maxKeyBits,
  Seed,
  Status,
  version,
} from './index.js';

function assertEqual(a: Uint8Array, b: Uint8Array, label: string): void {
  if (a.length !== b.length || !a.every((v, i) => v === b[i])) {
    throw new Error(`${label} mismatch: lengths ${a.length} vs ${b.length}`);
  }
  console.log(`  ok ${label} (${a.length} bytes)`);
}

function smokeMetadata(): void {
  console.log('--- metadata ---');
  console.log(`libitb path  : ${libraryPath}`);
  console.log(`version      : ${version()}`);
  console.log(`max_key_bits : ${maxKeyBits()}`);
  console.log(`channels     : ${channels()}`);
  console.log(`header_size  : ${headerSize()}`);
  console.log(`nonce_bits   : ${getNonceBits()}`);
  console.log(`barrier_fill : ${getBarrierFill()}`);
  console.log();
  console.log('hashes:');
  for (const h of listHashes()) {
    console.log(`  - ${h.name.padEnd(16)} width=${h.width}`);
  }
  console.log();
  console.log('macs:');
  for (const m of listMacs()) {
    console.log(
      `  - ${m.name.padEnd(16)} key=${m.keySize} tag=${m.tagSize} min=${m.minKeyBytes}`,
    );
  }
}

function smokeSingle(): void {
  console.log('\n--- Single Ouroboros round-trip (blake3 / 1024-bit) ---');
  using noise = new Seed('blake3', 1024);
  using data = new Seed('blake3', 1024);
  using start = new Seed('blake3', 1024);
  const plaintext = randomBytes(4096);
  const ct = encrypt(noise, data, start, plaintext);
  const pt = decrypt(noise, data, start, ct);
  assertEqual(pt, plaintext, 'Single round-trip');
}

function smokeTriple(): void {
  console.log('\n--- Triple Ouroboros round-trip (areion256 / 1024-bit) ---');
  using noise = new Seed('areion256', 1024);
  using d1 = new Seed('areion256', 1024);
  using d2 = new Seed('areion256', 1024);
  using d3 = new Seed('areion256', 1024);
  using s1 = new Seed('areion256', 1024);
  using s2 = new Seed('areion256', 1024);
  using s3 = new Seed('areion256', 1024);
  const plaintext = randomBytes(8192);
  const ct = encryptTriple(noise, d1, d2, d3, s1, s2, s3, plaintext);
  const pt = decryptTriple(noise, d1, d2, d3, s1, s2, s3, ct);
  assertEqual(pt, plaintext, 'Triple round-trip');
}

function smokeAuthSingle(): void {
  console.log('\n--- Authenticated Single (aescmac + hmac-blake3) ---');
  using noise = new Seed('aescmac', 1024);
  using data = new Seed('aescmac', 1024);
  using start = new Seed('aescmac', 1024);
  using mac = new MAC('hmac-blake3', randomBytes(32));
  const plaintext = randomBytes(2048);
  const ct = encryptAuth(noise, data, start, mac, plaintext);
  const pt = decryptAuth(noise, data, start, mac, ct);
  assertEqual(pt, plaintext, 'Auth Single round-trip');

  // Tamper test — flip a byte mid-ciphertext, expect MacFailure.
  const tampered = new Uint8Array(ct);
  const idx = Math.floor(tampered.length / 2);
  tampered[idx] = (tampered[idx] ?? 0) ^ 0xff;
  try {
    decryptAuth(noise, data, start, mac, tampered);
    throw new Error('expected ITBError(MacFailure) on tampered ciphertext');
  } catch (e) {
    if (e instanceof ITBError && e.code === Status.MacFailure) {
      console.log(`  ok tamper detected (status=${e.code})`);
    } else {
      throw e;
    }
  }
}

function smokeAuthTriple(): void {
  console.log('\n--- Authenticated Triple (siphash24 + hmac-blake3) ---');
  using noise = new Seed('siphash24', 1024);
  using d1 = new Seed('siphash24', 1024);
  using d2 = new Seed('siphash24', 1024);
  using d3 = new Seed('siphash24', 1024);
  using s1 = new Seed('siphash24', 1024);
  using s2 = new Seed('siphash24', 1024);
  using s3 = new Seed('siphash24', 1024);
  using mac = new MAC('hmac-blake3', randomBytes(32));
  const plaintext = randomBytes(1536);
  const ct = encryptAuthTriple(noise, d1, d2, d3, s1, s2, s3, mac, plaintext);
  const pt = decryptAuthTriple(noise, d1, d2, d3, s1, s2, s3, mac, ct);
  assertEqual(pt, plaintext, 'Auth Triple round-trip');
}

function smokeFromComponents(): void {
  console.log('\n--- Seed.fromComponents persistence ---');
  using original = new Seed('blake2b256', 1024);
  const comps = original.components;
  const key = original.hashKey;
  using restored = Seed.fromComponents('blake2b256', comps, key);
  if (original.width !== restored.width) {
    throw new Error(`width mismatch: ${original.width} vs ${restored.width}`);
  }
  console.log(`  ok components round-trip (${comps.length} u64, key=${key.length} B)`);
}

function main(): void {
  smokeMetadata();
  smokeSingle();
  smokeTriple();
  smokeAuthSingle();
  smokeAuthTriple();
  smokeFromComponents();
  console.log('\n[smoke] all checks passed');
}

main();
