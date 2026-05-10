// Streaming benchmarks for the Node.js binding — Easy Mode +
// Low-Level Mode across Single + Triple Ouroboros, encrypt + decrypt,
// with two caller shapes (Streaming AEAD over Readable/Writable and
// plain Streaming via caller-driven per-chunk loop). Eight cases per
// width × two widths = sixteen total streaming cases, mirroring the
// Python / Rust / C# streaming-bench precedent.
//
// The build helpers `buildStreamCasesSingle` / `buildStreamCasesTriple`
// fan the eight per-width cases into the existing `bench-single.ts` /
// `bench-triple.ts` case lists via a single `cases.push(...)`
// invocation. Setup — CSPRNG payload fill, Encryptor / Seed / MAC
// construction, decrypt-side ciphertext pre-encryption — runs outside
// the timed iter body.
//
// Configuration (lock-step across all 16 cases):
//
//   Primitive       areion512 (Areion-SoEM-512)
//   ITB key bits    1024
//   MAC (AEAD only) hmac-blake3 (32-byte CSPRNG key)
//   Total payload   64 MiB CSPRNG
//   Chunk size      16 MiB
//   bit-soup        off (default)
//   lock-soup       off (default)
//   lock-seed       off (default)
//
// AEAD-IO variant — Streaming AEAD wire transcript: 32-byte CSPRNG
// stream_id prefix followed by concatenated authenticated chunks. The
// Easy path drives `Encryptor.encryptStreamAuth(input, output,
// chunkSize)`; the Low-Level path drives the free function
// `encryptStreamAuth(noise, data, start, mac, input, output,
// chunkSize)` from `streams.ts`. Both paths consume a `Readable` and
// emit into a `Writable`; the bench wraps the payload `Uint8Array`
// in `Readable.from` and drains the output `PassThrough` after the
// helper resolves.
//
// UserLoop variant — plain (No-MAC) Streaming via caller-side
// per-chunk loop. Wire framing: 4-byte big-endian ciphertext length
// prefix per chunk, matching the convention documented in
// `tmp/itb_examples/nodejs/main.mjs`. Easy path runs
// `enc.encrypt(chunk)` per chunk; Low-Level path runs
// `encrypt(noise, data, start, chunk)` per chunk.

/* eslint-disable no-console */

import { randomBytes } from 'node:crypto';
import { Readable, PassThrough } from 'node:stream';

import {
  decrypt,
  decryptTriple,
  encrypt,
  encryptTriple,
} from '../src/cipher.js';
import { Encryptor } from '../src/encryptor.js';
import { MAC } from '../src/mac.js';
import { Seed } from '../src/seed.js';
import {
  decryptStreamAuth,
  decryptStreamAuthTriple,
  encryptStreamAuth,
  encryptStreamAuthTriple,
} from '../src/streams.js';

import { KEY_BITS, MAC_NAME } from './common.js';
import type { BenchCase } from './common.js';

/** Streaming primitive — Areion-SoEM-512. */
const STREAM_PRIMITIVE = 'areion512';

/** Total streaming-bench payload (64 MiB). */
const STREAM_PAYLOAD_BYTES = 64 * 1024 * 1024;

/** Per-chunk size for streaming-bench cases (16 MiB). */
const STREAM_CHUNK_SIZE = 16 * 1024 * 1024;

/** 4-byte big-endian length-prefix framing for the caller-driven
 * plain-stream (UserLoop) variant. The decryptor reads four header
 * bytes, parses the chunk length, then reads that many ciphertext
 * bytes — matching the framing convention documented for the
 * Node.js binding's plain caller-driven streaming example. */
const FRAMING_HEADER_BYTES = 4;

/**
 * Build the eight Single Ouroboros streaming-bench cases:
 * Easy + Low-Level, encrypt + decrypt, AEAD-IO + UserLoop.
 */
export function buildStreamCasesSingle(): BenchCase[] {
  const base = `bench_single_stream_${STREAM_PRIMITIVE}_${KEY_BITS}bit_64mb`;
  const cases: BenchCase[] = [];
  cases.push(makeEasyAeadIoEncryptSingle(`${base}_easy_encrypt_aead_io`));
  cases.push(makeEasyAeadIoDecryptSingle(`${base}_easy_decrypt_aead_io`));
  cases.push(makeEasyUserLoopEncryptSingle(`${base}_easy_encrypt_userloop`));
  cases.push(makeEasyUserLoopDecryptSingle(`${base}_easy_decrypt_userloop`));
  cases.push(makeLowLevelAeadIoEncryptSingle(`${base}_lowlevel_encrypt_aead_io`));
  cases.push(makeLowLevelAeadIoDecryptSingle(`${base}_lowlevel_decrypt_aead_io`));
  cases.push(makeLowLevelUserLoopEncryptSingle(`${base}_lowlevel_encrypt_userloop`));
  cases.push(makeLowLevelUserLoopDecryptSingle(`${base}_lowlevel_decrypt_userloop`));
  return cases;
}

/**
 * Build the eight Triple Ouroboros streaming-bench cases:
 * Easy + Low-Level, encrypt + decrypt, AEAD-IO + UserLoop.
 */
export function buildStreamCasesTriple(): BenchCase[] {
  const base = `bench_triple_stream_${STREAM_PRIMITIVE}_${KEY_BITS}bit_64mb`;
  const cases: BenchCase[] = [];
  cases.push(makeEasyAeadIoEncryptTriple(`${base}_easy_encrypt_aead_io`));
  cases.push(makeEasyAeadIoDecryptTriple(`${base}_easy_decrypt_aead_io`));
  cases.push(makeEasyUserLoopEncryptTriple(`${base}_easy_encrypt_userloop`));
  cases.push(makeEasyUserLoopDecryptTriple(`${base}_easy_decrypt_userloop`));
  cases.push(makeLowLevelAeadIoEncryptTriple(`${base}_lowlevel_encrypt_aead_io`));
  cases.push(makeLowLevelAeadIoDecryptTriple(`${base}_lowlevel_decrypt_aead_io`));
  cases.push(makeLowLevelUserLoopEncryptTriple(`${base}_lowlevel_encrypt_userloop`));
  cases.push(makeLowLevelUserLoopDecryptTriple(`${base}_lowlevel_decrypt_userloop`));
  return cases;
}

// ────────────────────────────────────────────────────────────────────
// Setup helpers — Encryptor / Seed / MAC construction outside the
// timed body. Default config — bit-soup / lock-soup / lock-seed are
// NOT engaged on these encryptors regardless of the ITB_LOCKSEED env
// var, so the streaming numbers report the bare streaming overhead
// independent of the existing Single Message ±LockSeed bench arms.
// ────────────────────────────────────────────────────────────────────

function buildEasyEncryptor(mode: number): Encryptor {
  return new Encryptor(STREAM_PRIMITIVE, KEY_BITS, MAC_NAME, mode);
}

function buildSeedsSingle(): { noise: Seed; data: Seed; start: Seed } {
  return {
    noise: new Seed(STREAM_PRIMITIVE, KEY_BITS),
    data: new Seed(STREAM_PRIMITIVE, KEY_BITS),
    start: new Seed(STREAM_PRIMITIVE, KEY_BITS),
  };
}

function buildSeedsTriple(): {
  noise: Seed;
  data1: Seed; data2: Seed; data3: Seed;
  start1: Seed; start2: Seed; start3: Seed;
} {
  return {
    noise: new Seed(STREAM_PRIMITIVE, KEY_BITS),
    data1: new Seed(STREAM_PRIMITIVE, KEY_BITS),
    data2: new Seed(STREAM_PRIMITIVE, KEY_BITS),
    data3: new Seed(STREAM_PRIMITIVE, KEY_BITS),
    start1: new Seed(STREAM_PRIMITIVE, KEY_BITS),
    start2: new Seed(STREAM_PRIMITIVE, KEY_BITS),
    start3: new Seed(STREAM_PRIMITIVE, KEY_BITS),
  };
}

function buildMac(): MAC {
  return new MAC(MAC_NAME, new Uint8Array(randomBytes(32)));
}

// ────────────────────────────────────────────────────────────────────
// Stream plumbing — Readable.from() over a payload Uint8Array splits
// the buffer into chunks at the Streaming AEAD helper's chunkSize
// granularity; PassThrough collects the output bytes for later drain.
// The helpers below stage the readable so the iter body opens a fresh
// Readable per call (Readable instances are not reusable after end).
// ────────────────────────────────────────────────────────────────────

/** Slice a buffer into `STREAM_CHUNK_SIZE`-sized parts as a
 *  pre-built array of Uint8Array views, so the iter body can wrap
 *  them in `Readable.from` without paying slice cost per call. */
function precutPayload(payload: Uint8Array, chunkSize: number): Uint8Array[] {
  const parts: Uint8Array[] = [];
  for (let off = 0; off < payload.length; off += chunkSize) {
    parts.push(payload.subarray(off, Math.min(off + chunkSize, payload.length)));
  }
  return parts;
}

/** Drain a PassThrough end-to-end into a single Uint8Array. */
async function drainPassThrough(pt: PassThrough): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  for await (const c of pt) chunks.push(c as Buffer);
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

// ────────────────────────────────────────────────────────────────────
// Easy Mode — Single Ouroboros
// ────────────────────────────────────────────────────────────────────

function makeEasyAeadIoEncryptSingle(name: string): BenchCase {
  const enc = buildEasyEncryptor(1);
  const payload = new Uint8Array(randomBytes(STREAM_PAYLOAD_BYTES));
  const parts = precutPayload(payload, STREAM_CHUNK_SIZE);
  return {
    name,
    run: async (iters: number) => {
      for (let i = 0; i < iters; i++) {
        const dst = new PassThrough();
        const drainPromise = drainPassThrough(dst);
        await enc.encryptStreamAuth(Readable.from(parts), dst, STREAM_CHUNK_SIZE);
        dst.end();
        await drainPromise;
      }
    },
    payloadBytes: STREAM_PAYLOAD_BYTES,
  };
}

function makeEasyAeadIoDecryptSingle(name: string): BenchCase {
  const enc = buildEasyEncryptor(1);
  const payload = new Uint8Array(randomBytes(STREAM_PAYLOAD_BYTES));
  let transcript: Uint8Array;
  return {
    name,
    run: async (iters: number) => {
      if (transcript === undefined) {
        const parts = precutPayload(payload, STREAM_CHUNK_SIZE);
        const dst = new PassThrough();
        const drainPromise = drainPassThrough(dst);
        await enc.encryptStreamAuth(Readable.from(parts), dst, STREAM_CHUNK_SIZE);
        dst.end();
        transcript = await drainPromise;
      }
      const ctParts = precutPayload(transcript, STREAM_CHUNK_SIZE);
      for (let i = 0; i < iters; i++) {
        const dst = new PassThrough();
        const drainPromise = drainPassThrough(dst);
        await enc.decryptStreamAuth(Readable.from(ctParts), dst);
        dst.end();
        await drainPromise;
      }
    },
    payloadBytes: STREAM_PAYLOAD_BYTES,
  };
}

function makeEasyUserLoopEncryptSingle(name: string): BenchCase {
  const enc = buildEasyEncryptor(1);
  const payload = new Uint8Array(randomBytes(STREAM_PAYLOAD_BYTES));
  return {
    name,
    run: (iters: number) => {
      for (let i = 0; i < iters; i++) {
        encryptUserLoopEasy(enc, payload, () => { /* discard */ });
      }
    },
    payloadBytes: STREAM_PAYLOAD_BYTES,
  };
}

function makeEasyUserLoopDecryptSingle(name: string): BenchCase {
  const enc = buildEasyEncryptor(1);
  const payload = new Uint8Array(randomBytes(STREAM_PAYLOAD_BYTES));
  const transcript = encryptUserLoopEasyToBytes(enc, payload);
  return {
    name,
    run: (iters: number) => {
      for (let i = 0; i < iters; i++) {
        decryptUserLoopEasy(enc, transcript, () => { /* discard */ });
      }
    },
    payloadBytes: STREAM_PAYLOAD_BYTES,
  };
}

// ────────────────────────────────────────────────────────────────────
// Easy Mode — Triple Ouroboros
// ────────────────────────────────────────────────────────────────────

function makeEasyAeadIoEncryptTriple(name: string): BenchCase {
  const enc = buildEasyEncryptor(3);
  const payload = new Uint8Array(randomBytes(STREAM_PAYLOAD_BYTES));
  const parts = precutPayload(payload, STREAM_CHUNK_SIZE);
  return {
    name,
    run: async (iters: number) => {
      for (let i = 0; i < iters; i++) {
        const dst = new PassThrough();
        const drainPromise = drainPassThrough(dst);
        await enc.encryptStreamAuth(Readable.from(parts), dst, STREAM_CHUNK_SIZE);
        dst.end();
        await drainPromise;
      }
    },
    payloadBytes: STREAM_PAYLOAD_BYTES,
  };
}

function makeEasyAeadIoDecryptTriple(name: string): BenchCase {
  const enc = buildEasyEncryptor(3);
  const payload = new Uint8Array(randomBytes(STREAM_PAYLOAD_BYTES));
  let transcript: Uint8Array;
  return {
    name,
    run: async (iters: number) => {
      if (transcript === undefined) {
        const parts = precutPayload(payload, STREAM_CHUNK_SIZE);
        const dst = new PassThrough();
        const drainPromise = drainPassThrough(dst);
        await enc.encryptStreamAuth(Readable.from(parts), dst, STREAM_CHUNK_SIZE);
        dst.end();
        transcript = await drainPromise;
      }
      const ctParts = precutPayload(transcript, STREAM_CHUNK_SIZE);
      for (let i = 0; i < iters; i++) {
        const dst = new PassThrough();
        const drainPromise = drainPassThrough(dst);
        await enc.decryptStreamAuth(Readable.from(ctParts), dst);
        dst.end();
        await drainPromise;
      }
    },
    payloadBytes: STREAM_PAYLOAD_BYTES,
  };
}

function makeEasyUserLoopEncryptTriple(name: string): BenchCase {
  const enc = buildEasyEncryptor(3);
  const payload = new Uint8Array(randomBytes(STREAM_PAYLOAD_BYTES));
  return {
    name,
    run: (iters: number) => {
      for (let i = 0; i < iters; i++) {
        encryptUserLoopEasy(enc, payload, () => { /* discard */ });
      }
    },
    payloadBytes: STREAM_PAYLOAD_BYTES,
  };
}

function makeEasyUserLoopDecryptTriple(name: string): BenchCase {
  const enc = buildEasyEncryptor(3);
  const payload = new Uint8Array(randomBytes(STREAM_PAYLOAD_BYTES));
  const transcript = encryptUserLoopEasyToBytes(enc, payload);
  return {
    name,
    run: (iters: number) => {
      for (let i = 0; i < iters; i++) {
        decryptUserLoopEasy(enc, transcript, () => { /* discard */ });
      }
    },
    payloadBytes: STREAM_PAYLOAD_BYTES,
  };
}

// ────────────────────────────────────────────────────────────────────
// Low-Level Mode — Single Ouroboros
// ────────────────────────────────────────────────────────────────────

function makeLowLevelAeadIoEncryptSingle(name: string): BenchCase {
  const seeds = buildSeedsSingle();
  const mac = buildMac();
  const payload = new Uint8Array(randomBytes(STREAM_PAYLOAD_BYTES));
  const parts = precutPayload(payload, STREAM_CHUNK_SIZE);
  return {
    name,
    run: async (iters: number) => {
      for (let i = 0; i < iters; i++) {
        const dst = new PassThrough();
        const drainPromise = drainPassThrough(dst);
        await encryptStreamAuth(
          seeds.noise, seeds.data, seeds.start, mac,
          Readable.from(parts), dst, STREAM_CHUNK_SIZE,
        );
        dst.end();
        await drainPromise;
      }
    },
    payloadBytes: STREAM_PAYLOAD_BYTES,
  };
}

function makeLowLevelAeadIoDecryptSingle(name: string): BenchCase {
  const seeds = buildSeedsSingle();
  const mac = buildMac();
  const payload = new Uint8Array(randomBytes(STREAM_PAYLOAD_BYTES));
  let transcript: Uint8Array;
  return {
    name,
    run: async (iters: number) => {
      if (transcript === undefined) {
        const parts = precutPayload(payload, STREAM_CHUNK_SIZE);
        const dst = new PassThrough();
        const drainPromise = drainPassThrough(dst);
        await encryptStreamAuth(
          seeds.noise, seeds.data, seeds.start, mac,
          Readable.from(parts), dst, STREAM_CHUNK_SIZE,
        );
        dst.end();
        transcript = await drainPromise;
      }
      const ctParts = precutPayload(transcript, STREAM_CHUNK_SIZE);
      for (let i = 0; i < iters; i++) {
        const dst = new PassThrough();
        const drainPromise = drainPassThrough(dst);
        await decryptStreamAuth(
          seeds.noise, seeds.data, seeds.start, mac,
          Readable.from(ctParts), dst,
        );
        dst.end();
        await drainPromise;
      }
    },
    payloadBytes: STREAM_PAYLOAD_BYTES,
  };
}

function makeLowLevelUserLoopEncryptSingle(name: string): BenchCase {
  const seeds = buildSeedsSingle();
  const payload = new Uint8Array(randomBytes(STREAM_PAYLOAD_BYTES));
  return {
    name,
    run: (iters: number) => {
      for (let i = 0; i < iters; i++) {
        encryptUserLoopLowLevelSingle(
          seeds.noise, seeds.data, seeds.start, payload, () => { /* discard */ });
      }
    },
    payloadBytes: STREAM_PAYLOAD_BYTES,
  };
}

function makeLowLevelUserLoopDecryptSingle(name: string): BenchCase {
  const seeds = buildSeedsSingle();
  const payload = new Uint8Array(randomBytes(STREAM_PAYLOAD_BYTES));
  const transcript = encryptUserLoopLowLevelSingleToBytes(
    seeds.noise, seeds.data, seeds.start, payload);
  return {
    name,
    run: (iters: number) => {
      for (let i = 0; i < iters; i++) {
        decryptUserLoopLowLevelSingle(
          seeds.noise, seeds.data, seeds.start, transcript, () => { /* discard */ });
      }
    },
    payloadBytes: STREAM_PAYLOAD_BYTES,
  };
}

// ────────────────────────────────────────────────────────────────────
// Low-Level Mode — Triple Ouroboros
// ────────────────────────────────────────────────────────────────────

function makeLowLevelAeadIoEncryptTriple(name: string): BenchCase {
  const s = buildSeedsTriple();
  const mac = buildMac();
  const payload = new Uint8Array(randomBytes(STREAM_PAYLOAD_BYTES));
  const parts = precutPayload(payload, STREAM_CHUNK_SIZE);
  return {
    name,
    run: async (iters: number) => {
      for (let i = 0; i < iters; i++) {
        const dst = new PassThrough();
        const drainPromise = drainPassThrough(dst);
        await encryptStreamAuthTriple(
          s.noise, s.data1, s.data2, s.data3,
          s.start1, s.start2, s.start3, mac,
          Readable.from(parts), dst, STREAM_CHUNK_SIZE,
        );
        dst.end();
        await drainPromise;
      }
    },
    payloadBytes: STREAM_PAYLOAD_BYTES,
  };
}

function makeLowLevelAeadIoDecryptTriple(name: string): BenchCase {
  const s = buildSeedsTriple();
  const mac = buildMac();
  const payload = new Uint8Array(randomBytes(STREAM_PAYLOAD_BYTES));
  let transcript: Uint8Array;
  return {
    name,
    run: async (iters: number) => {
      if (transcript === undefined) {
        const parts = precutPayload(payload, STREAM_CHUNK_SIZE);
        const dst = new PassThrough();
        const drainPromise = drainPassThrough(dst);
        await encryptStreamAuthTriple(
          s.noise, s.data1, s.data2, s.data3,
          s.start1, s.start2, s.start3, mac,
          Readable.from(parts), dst, STREAM_CHUNK_SIZE,
        );
        dst.end();
        transcript = await drainPromise;
      }
      const ctParts = precutPayload(transcript, STREAM_CHUNK_SIZE);
      for (let i = 0; i < iters; i++) {
        const dst = new PassThrough();
        const drainPromise = drainPassThrough(dst);
        await decryptStreamAuthTriple(
          s.noise, s.data1, s.data2, s.data3,
          s.start1, s.start2, s.start3, mac,
          Readable.from(ctParts), dst,
        );
        dst.end();
        await drainPromise;
      }
    },
    payloadBytes: STREAM_PAYLOAD_BYTES,
  };
}

function makeLowLevelUserLoopEncryptTriple(name: string): BenchCase {
  const s = buildSeedsTriple();
  const payload = new Uint8Array(randomBytes(STREAM_PAYLOAD_BYTES));
  return {
    name,
    run: (iters: number) => {
      for (let i = 0; i < iters; i++) {
        encryptUserLoopLowLevelTriple(
          s.noise, s.data1, s.data2, s.data3,
          s.start1, s.start2, s.start3, payload, () => { /* discard */ });
      }
    },
    payloadBytes: STREAM_PAYLOAD_BYTES,
  };
}

function makeLowLevelUserLoopDecryptTriple(name: string): BenchCase {
  const s = buildSeedsTriple();
  const payload = new Uint8Array(randomBytes(STREAM_PAYLOAD_BYTES));
  const transcript = encryptUserLoopLowLevelTripleToBytes(
    s.noise, s.data1, s.data2, s.data3,
    s.start1, s.start2, s.start3, payload);
  return {
    name,
    run: (iters: number) => {
      for (let i = 0; i < iters; i++) {
        decryptUserLoopLowLevelTriple(
          s.noise, s.data1, s.data2, s.data3,
          s.start1, s.start2, s.start3, transcript, () => { /* discard */ });
      }
    },
    payloadBytes: STREAM_PAYLOAD_BYTES,
  };
}

// ────────────────────────────────────────────────────────────────────
// UserLoop helpers — Easy Mode plain caller-driven per-chunk loop.
// Wire framing: 4-byte big-endian ciphertext length prefix per chunk,
// matching the Node.js binding's plain-stream framing convention
// documented in `tmp/itb_examples/nodejs/main.mjs`. The bench
// callbacks discard the wire bytes; the encrypt-side and decrypt-side
// loops both pay the same per-chunk FFI + framing cost regardless of
// what consumes the output.
// ────────────────────────────────────────────────────────────────────

type Sink = (buf: Uint8Array) => void;

function encodeBe32(n: number): Uint8Array {
  const out = new Uint8Array(FRAMING_HEADER_BYTES);
  out[0] = (n >>> 24) & 0xff;
  out[1] = (n >>> 16) & 0xff;
  out[2] = (n >>> 8) & 0xff;
  out[3] = n & 0xff;
  return out;
}

function decodeBe32(buf: Uint8Array, off: number): number {
  return (
    ((buf[off]! << 24) >>> 0) |
    (buf[off + 1]! << 16) |
    (buf[off + 2]! << 8) |
    buf[off + 3]!
  ) >>> 0;
}

function encryptUserLoopEasy(enc: Encryptor, payload: Uint8Array, sink: Sink): void {
  for (let off = 0; off < payload.length; off += STREAM_CHUNK_SIZE) {
    const chunk = payload.subarray(off, Math.min(off + STREAM_CHUNK_SIZE, payload.length));
    const ct = enc.encrypt(chunk);
    sink(encodeBe32(ct.length));
    sink(ct);
  }
}

function encryptUserLoopEasyToBytes(enc: Encryptor, payload: Uint8Array): Uint8Array {
  const parts: Uint8Array[] = [];
  encryptUserLoopEasy(enc, payload, (buf) => parts.push(buf));
  return concatU8(parts);
}

function decryptUserLoopEasy(enc: Encryptor, transcript: Uint8Array, sink: Sink): void {
  let off = 0;
  while (off < transcript.length) {
    const len = decodeBe32(transcript, off);
    off += FRAMING_HEADER_BYTES;
    const ct = transcript.subarray(off, off + len);
    off += len;
    const pt = enc.decrypt(ct);
    sink(pt);
  }
}

function encryptUserLoopLowLevelSingle(
  noise: Seed, data: Seed, start: Seed,
  payload: Uint8Array, sink: Sink,
): void {
  for (let off = 0; off < payload.length; off += STREAM_CHUNK_SIZE) {
    const chunk = payload.subarray(off, Math.min(off + STREAM_CHUNK_SIZE, payload.length));
    const ct = encrypt(noise, data, start, chunk);
    sink(encodeBe32(ct.length));
    sink(ct);
  }
}

function encryptUserLoopLowLevelSingleToBytes(
  noise: Seed, data: Seed, start: Seed, payload: Uint8Array,
): Uint8Array {
  const parts: Uint8Array[] = [];
  encryptUserLoopLowLevelSingle(noise, data, start, payload, (buf) => parts.push(buf));
  return concatU8(parts);
}

function decryptUserLoopLowLevelSingle(
  noise: Seed, data: Seed, start: Seed,
  transcript: Uint8Array, sink: Sink,
): void {
  let off = 0;
  while (off < transcript.length) {
    const len = decodeBe32(transcript, off);
    off += FRAMING_HEADER_BYTES;
    const ct = transcript.subarray(off, off + len);
    off += len;
    const pt = decrypt(noise, data, start, ct);
    sink(pt);
  }
}

function encryptUserLoopLowLevelTriple(
  noise: Seed,
  data1: Seed, data2: Seed, data3: Seed,
  start1: Seed, start2: Seed, start3: Seed,
  payload: Uint8Array, sink: Sink,
): void {
  for (let off = 0; off < payload.length; off += STREAM_CHUNK_SIZE) {
    const chunk = payload.subarray(off, Math.min(off + STREAM_CHUNK_SIZE, payload.length));
    const ct = encryptTriple(noise, data1, data2, data3, start1, start2, start3, chunk);
    sink(encodeBe32(ct.length));
    sink(ct);
  }
}

function encryptUserLoopLowLevelTripleToBytes(
  noise: Seed,
  data1: Seed, data2: Seed, data3: Seed,
  start1: Seed, start2: Seed, start3: Seed,
  payload: Uint8Array,
): Uint8Array {
  const parts: Uint8Array[] = [];
  encryptUserLoopLowLevelTriple(
    noise, data1, data2, data3, start1, start2, start3,
    payload, (buf) => parts.push(buf));
  return concatU8(parts);
}

function decryptUserLoopLowLevelTriple(
  noise: Seed,
  data1: Seed, data2: Seed, data3: Seed,
  start1: Seed, start2: Seed, start3: Seed,
  transcript: Uint8Array, sink: Sink,
): void {
  let off = 0;
  while (off < transcript.length) {
    const len = decodeBe32(transcript, off);
    off += FRAMING_HEADER_BYTES;
    const ct = transcript.subarray(off, off + len);
    off += len;
    const pt = decryptTriple(noise, data1, data2, data3, start1, start2, start3, ct);
    sink(pt);
  }
}

function concatU8(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
