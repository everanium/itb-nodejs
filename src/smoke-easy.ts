// Phase 4 smoke runner — Encryptor, Blob, Streams round-trips.
//
// Run after `npm run build`:
//
//     node dist/smoke-easy.js

import { randomBytes } from 'node:crypto';
import { PassThrough } from 'node:stream';

import {
  Blob512,
  BlobSlot,
  decryptStream,
  encryptStream,
  Encryptor,
  ITBError,
  Seed,
  Status,
} from './index.js';

function assertEqual(a: Uint8Array, b: Uint8Array, label: string): void {
  if (a.length !== b.length || !a.every((v, i) => v === b[i])) {
    throw new Error(`${label} mismatch: lengths ${a.length} vs ${b.length}`);
  }
  console.log(`  ok ${label} (${a.length} bytes)`);
}

function smokeEncryptorSingle(): void {
  console.log('--- Encryptor (blake3, 1024-bit, Single) ---');
  using enc = new Encryptor('blake3', 1024);
  const pt = randomBytes(8192);
  const ct = enc.encryptAuth(pt);
  const back = enc.decryptAuth(ct);
  assertEqual(back, pt, 'Encryptor.encryptAuth/decryptAuth Single');
  console.log(`  primitive=${enc.primitive} mac=${enc.macName} mode=${enc.mode} keyBits=${enc.keyBits}`);
}

function smokeEncryptorTriple(): void {
  console.log('\n--- Encryptor (areion512, 2048-bit, Triple) ---');
  using enc = new Encryptor('areion512', 2048, 'hmac-blake3', 3);
  const pt = randomBytes(16384);
  const ct = enc.encrypt(pt);
  const back = enc.decrypt(ct);
  assertEqual(back, pt, 'Encryptor.encrypt/decrypt Triple');
  console.log(`  isMixed=${enc.isMixed} seedCount=${enc.seedCount}`);
}

function smokeEncryptorMixed(): void {
  console.log('\n--- Encryptor.mixedSingle (mixed primitives, Single) ---');
  using enc = Encryptor.mixedSingle('blake3', 'areion256', 'chacha20', null, 1024);
  const pt = randomBytes(4096);
  const ct = enc.encryptAuth(pt);
  const back = enc.decryptAuth(ct);
  assertEqual(back, pt, 'mixedSingle round-trip');
  console.log(`  isMixed=${enc.isMixed} primitive[0]=${enc.primitiveAt(0)} primitive[1]=${enc.primitiveAt(1)}`);
}

function smokeEncryptorPersistence(): void {
  console.log('\n--- Encryptor persistence (export → peekConfig → import) ---');
  using src = new Encryptor('blake2b256', 1024);
  const blob = src.exportState();
  const cfg = Encryptor.peekConfig(blob);
  console.log(`  peekConfig: prim=${cfg.primitive} keyBits=${cfg.keyBits} mode=${cfg.mode} mac=${cfg.macName}`);
  using dst = new Encryptor(cfg.primitive, cfg.keyBits, cfg.macName, cfg.mode);
  dst.importState(blob);
  const pt = randomBytes(2048);
  const ct = src.encryptAuth(pt);
  const back = dst.decryptAuth(ct);
  assertEqual(back, pt, 'persistence cross-handle round-trip');
}

function smokeEncryptorMismatch(): void {
  console.log('\n--- Encryptor importState mismatch raises ITBEasyMismatchError ---');
  using src = new Encryptor('blake3', 1024);
  const blob = src.exportState();
  using dst = new Encryptor('areion256', 1024);
  try {
    dst.importState(blob);
    throw new Error('expected mismatch error');
  } catch (e) {
    if (e instanceof ITBError && e.code === Status.EasyMismatch) {
      console.log(`  ok mismatch detected (code=${e.code})`);
    } else {
      throw e;
    }
  }
}

function smokeBlobRoundTrip(): void {
  console.log('\n--- Blob512 export → import (Single) ---');
  using src = new Blob512();
  const noiseComps = Array.from({ length: 16 }, (_, i) => BigInt(i + 1));
  const dataComps = Array.from({ length: 16 }, (_, i) => BigInt(i + 100));
  const startComps = Array.from({ length: 16 }, (_, i) => BigInt(i + 200));
  src.setComponents(BlobSlot.N, noiseComps);
  src.setComponents(BlobSlot.D, dataComps);
  src.setComponents(BlobSlot.S, startComps);
  src.setKey(BlobSlot.N, randomBytes(64));
  src.setKey(BlobSlot.D, randomBytes(64));
  src.setKey(BlobSlot.S, randomBytes(64));
  const blob = src.export();
  console.log(`  blob size: ${blob.length} bytes`);

  using dst = new Blob512();
  dst.import(blob);
  const back = dst.getComponents(BlobSlot.D);
  if (back.length !== dataComps.length || !back.every((v, i) => v === dataComps[i])) {
    throw new Error('Blob512 components mismatch on round-trip');
  }
  console.log('  ok Blob512 component round-trip');
}

async function smokeStreamRoundTrip(): Promise<void> {
  console.log('\n--- encryptStream / decryptStream (PassThrough pipes) ---');
  using noise = new Seed('blake3', 1024);
  using data = new Seed('blake3', 1024);
  using start = new Seed('blake3', 1024);

  const plaintext = randomBytes(64 * 1024);
  const inEnc = new PassThrough();
  const ctSink = new PassThrough();
  inEnc.end(plaintext);
  await encryptStream(noise, data, start, inEnc, ctSink);
  // The wrapped Writable is NOT ended by the helper (per stream contract);
  // close it explicitly so the consumer for-await terminates.
  ctSink.end();
  const ctChunks: Buffer[] = [];
  for await (const chunk of ctSink) {
    ctChunks.push(chunk as Buffer);
  }
  const ct = Buffer.concat(ctChunks);
  console.log(`  encrypted: pt=${plaintext.length} → ct=${ct.length} bytes`);

  const inDec = new PassThrough();
  const ptSink = new PassThrough();
  inDec.end(ct);
  await decryptStream(noise, data, start, inDec, ptSink);
  ptSink.end();
  const ptChunks: Buffer[] = [];
  for await (const chunk of ptSink) {
    ptChunks.push(chunk as Buffer);
  }
  const pt = Buffer.concat(ptChunks);
  assertEqual(pt, plaintext, 'stream round-trip (PassThrough)');
}

async function main(): Promise<void> {
  smokeEncryptorSingle();
  smokeEncryptorTriple();
  smokeEncryptorMixed();
  smokeEncryptorPersistence();
  smokeEncryptorMismatch();
  smokeBlobRoundTrip();
  await smokeStreamRoundTrip();
  console.log('\n[smoke-easy] all checks passed');
}

await main();
