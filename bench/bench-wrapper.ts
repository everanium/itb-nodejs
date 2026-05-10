// Format-deniability wrapper benchmarks for the Node.js binding.
//
// Mirrors `bindings/python/wrapper/benchmarks/bench_wrapper.py` and
// `bindings/rust/benches/bench_wrapper.rs` and `wrapper/bench_test.go`.
// Three test scopes:
//
//   * Wrapper Only — pure outer cipher round-trip throughput on a
//     16 MiB random buffer (no ITB call). Two shapes: `wrap` (alloc
//     fresh wire) and `wrapInPlace` (mutate caller's buffer).
//     Encrypt + decrypt timed together — one round-trip per iter.
//     6 sub-benches = 3 ciphers × 2 shapes.
//
//   * Message — full ITB encrypt-then-wrap and unwrap-then-decrypt
//     timed separately on a 16 MiB plaintext. 4 modes (Easy No MAC,
//     Easy Auth, Low-Level No MAC, Low-Level Auth) × 3 ciphers × 2
//     directions = 24 per Single, 24 per Triple = 48 sub-benches.
//
//   * Streaming — full ITB streaming encrypt-then-wrap and
//     unwrap-then-decrypt timed separately on a 64 MiB plaintext
//     through 16 MiB chunks. 4 modes (AEAD Easy IO-Driven, AEAD
//     Low-Level IO-Driven, No MAC Easy User-Driven Loop, No MAC
//     Low-Level User-Driven Loop) × 3 ciphers × 2 directions = 24
//     per Single, 24 per Triple = 48 sub-benches.
//
// Total: 6 + 48 + 48 = 102 sub-benches.
//
// Binding asymmetry — the Node.js binding exposes Streaming AEAD as
// `Encryptor.encryptStreamAuth` / `decryptStreamAuth` plus the free
// functions `encryptStreamAuth` / `decryptStreamAuth`, but does NOT
// expose a `stream.Readable` / `stream.Writable` adapter pair on top
// of the wrap surface for Non-AEAD streaming. The Non-AEAD streaming
// arm therefore covers the User-Driven Loop variant only (per-chunk
// encrypt + caller-side u32_LE framing pushed through one wrap-stream
// session). See CLAUDE.md.
//
// Run with:
//
//     npm run bench:wrapper
//
//     ITB_BENCH_FILTER=wrapper_only npm run bench:wrapper
//
//     ITB_BENCH_FILTER=msg_single_easy_nomac/aes/encrypt npm run bench:wrapper
//
// The harness emits one Go-bench-style line per case (name, iters,
// ns/op, MB/s). See `common.ts` for the supported environment
// variables and the convergence policy.

/* eslint-disable no-console */

import { randomBytes } from 'node:crypto';
import { PassThrough } from 'node:stream';

import {
  CIPHER_NAMES,
  Encryptor,
  MAC,
  Seed,
  decryptAuth,
  decryptAuthTriple,
  decryptStreamAuth,
  decryptStreamAuthTriple,
  decryptTriple,
  decrypt as itbDecrypt,
  encryptAuth,
  encryptAuthTriple,
  encryptStreamAuth,
  encryptStreamAuthTriple,
  encryptTriple,
  encrypt as itbEncrypt,
  setBarrierFill,
  setBitSoup,
  setLockSoup,
  setMaxWorkers,
  setNonceBits,
  unwrap,
  unwrapInPlace,
  UnwrapStreamReader,
  wrap,
  wrapInPlace,
  WrapStreamWriter,
  wrapperGenerateKey,
  wrapperNonceSize,
} from '../src/index.js';
import type { CipherName } from '../src/index.js';

import { runAll } from './common.js';
import type { BenchCase } from './common.js';

// ─── Constants ────────────────────────────────────────────────────

const PRIMITIVE = 'areion512';
const KEY_BITS_SINGLE = 1024;
const KEY_BITS_TRIPLE = 1024;
const MAC_NAME = 'hmac-blake3';

const MESSAGE_BYTES = 16 << 20;
const STREAM_TOTAL_BYTES = 64 << 20;
const STREAM_CHUNK_BYTES = 16 << 20;

const MAC_KEY = Buffer.from(
  '11223344556677889900aabbccddeeff' + '102030405060708090a0b0c0d0e0f001',
  'hex',
);

// ─── Helpers ──────────────────────────────────────────────────────

function buildEncryptorSingle(macName: string | null): Encryptor {
  return new Encryptor(PRIMITIVE, KEY_BITS_SINGLE, macName, 1);
}

function buildEncryptorTriple(macName: string | null): Encryptor {
  return new Encryptor(PRIMITIVE, KEY_BITS_TRIPLE, macName, 3);
}

function buildSeedsSingle(): [Seed, Seed, Seed] {
  return [
    new Seed(PRIMITIVE, KEY_BITS_SINGLE),
    new Seed(PRIMITIVE, KEY_BITS_SINGLE),
    new Seed(PRIMITIVE, KEY_BITS_SINGLE),
  ];
}

function buildSeedsTriple(): [Seed, Seed, Seed, Seed, Seed, Seed, Seed] {
  return [
    new Seed(PRIMITIVE, KEY_BITS_TRIPLE),
    new Seed(PRIMITIVE, KEY_BITS_TRIPLE),
    new Seed(PRIMITIVE, KEY_BITS_TRIPLE),
    new Seed(PRIMITIVE, KEY_BITS_TRIPLE),
    new Seed(PRIMITIVE, KEY_BITS_TRIPLE),
    new Seed(PRIMITIVE, KEY_BITS_TRIPLE),
    new Seed(PRIMITIVE, KEY_BITS_TRIPLE),
  ];
}

async function drain(stream: PassThrough): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

// ─── Wrapper Only sub-benches (6 cases) ──────────────────────────

function buildWrapperOnlyCases(): BenchCase[] {
  const cases: BenchCase[] = [];
  for (const cipher of CIPHER_NAMES) {
    const key = wrapperGenerateKey(cipher);
    const blob = randomBytes(MESSAGE_BYTES);
    cases.push({
      name: `bench_wrapper_only/${cipher}/wrap`,
      payloadBytes: MESSAGE_BYTES,
      run: (iters: number) => {
        for (let i = 0; i < iters; i++) {
          const wire = wrap(cipher, key, blob);
          const recovered = unwrap(cipher, key, wire);
          if (recovered.length !== blob.length) {
            throw new Error(`wrapper only ${cipher}: length mismatch`);
          }
        }
      },
    });
    cases.push({
      name: `bench_wrapper_only/${cipher}/wrap_in_place`,
      payloadBytes: MESSAGE_BYTES,
      run: (iters: number) => {
        for (let i = 0; i < iters; i++) {
          const buf = Buffer.from(blob);
          const nonce = wrapInPlace(cipher, key, buf);
          // For symmetric round-trip, build the wire and unwrap.
          const wire = Buffer.concat([nonce, buf]);
          unwrapInPlace(cipher, key, wire);
        }
      },
    });
  }
  return cases;
}

// ─── Message sub-benches (Single + Triple) ───────────────────────

interface MessageMode {
  readonly tag: string;
  readonly buildEncryptCipherText: (
    cipher: CipherName,
    payload: Buffer,
  ) => Buffer;
  readonly runEncrypt: (cipher: CipherName, payload: Buffer) => void;
  readonly runDecrypt: (cipher: CipherName, wire: Buffer) => void;
}

function buildMessageModesSingle(): MessageMode[] {
  // Build the modes; each holds a long-lived Encryptor / seed set
  // captured in the closure so the per-iter body does not pay
  // construction cost.
  const modes: MessageMode[] = [];

  // Mode 1: Easy No MAC
  {
    const enc = buildEncryptorSingle(null);
    const buildCt = (_cipher: CipherName, payload: Buffer) =>
      Buffer.from(enc.encrypt(payload));
    modes.push({
      tag: 'msg_single_easy_nomac',
      buildEncryptCipherText: buildCt,
      runEncrypt: (cipher, payload) => {
        const ct = Buffer.from(enc.encrypt(payload));
        const nonce = wrapInPlace(cipher, _outerKeyFor(cipher), ct);
        // Use the wire (concat) to avoid being optimised away.
        if (nonce.length === 0 && ct.length === 0) throw new Error('unreachable');
      },
      runDecrypt: (cipher, wire) => {
        const buf = Buffer.from(wire);
        const recovered = unwrapInPlace(cipher, _outerKeyFor(cipher), buf);
        const pt = enc.decrypt(recovered);
        if (pt.length === 0) throw new Error('unreachable');
      },
    });
  }

  // Mode 2: Easy MAC Authenticated
  {
    const enc = buildEncryptorSingle(MAC_NAME);
    const buildCt = (_cipher: CipherName, payload: Buffer) =>
      Buffer.from(enc.encryptAuth(payload));
    modes.push({
      tag: 'msg_single_easy_auth',
      buildEncryptCipherText: buildCt,
      runEncrypt: (cipher, payload) => {
        const ct = Buffer.from(enc.encryptAuth(payload));
        const nonce = wrapInPlace(cipher, _outerKeyFor(cipher), ct);
        if (nonce.length === 0 && ct.length === 0) throw new Error('unreachable');
      },
      runDecrypt: (cipher, wire) => {
        const buf = Buffer.from(wire);
        const recovered = unwrapInPlace(cipher, _outerKeyFor(cipher), buf);
        const pt = enc.decryptAuth(recovered);
        if (pt.length === 0) throw new Error('unreachable');
      },
    });
  }

  // Mode 3: Low-Level No MAC
  {
    const seeds = buildSeedsSingle();
    const [s0, s1, s2] = seeds;
    const buildCt = (_cipher: CipherName, payload: Buffer) =>
      Buffer.from(itbEncrypt(s0, s1, s2, payload));
    modes.push({
      tag: 'msg_single_lowlevel_nomac',
      buildEncryptCipherText: buildCt,
      runEncrypt: (cipher, payload) => {
        const ct = Buffer.from(itbEncrypt(s0, s1, s2, payload));
        const nonce = wrapInPlace(cipher, _outerKeyFor(cipher), ct);
        if (nonce.length === 0 && ct.length === 0) throw new Error('unreachable');
      },
      runDecrypt: (cipher, wire) => {
        const buf = Buffer.from(wire);
        const recovered = unwrapInPlace(cipher, _outerKeyFor(cipher), buf);
        const pt = itbDecrypt(s0, s1, s2, recovered);
        if (pt.length === 0) throw new Error('unreachable');
      },
    });
  }

  // Mode 4: Low-Level MAC Authenticated
  {
    const seeds = buildSeedsSingle();
    const [s0, s1, s2] = seeds;
    const mac = new MAC(MAC_NAME, MAC_KEY);
    const buildCt = (_cipher: CipherName, payload: Buffer) =>
      Buffer.from(encryptAuth(s0, s1, s2, mac, payload));
    modes.push({
      tag: 'msg_single_lowlevel_auth',
      buildEncryptCipherText: buildCt,
      runEncrypt: (cipher, payload) => {
        const ct = Buffer.from(encryptAuth(s0, s1, s2, mac, payload));
        const nonce = wrapInPlace(cipher, _outerKeyFor(cipher), ct);
        if (nonce.length === 0 && ct.length === 0) throw new Error('unreachable');
      },
      runDecrypt: (cipher, wire) => {
        const buf = Buffer.from(wire);
        const recovered = unwrapInPlace(cipher, _outerKeyFor(cipher), buf);
        const pt = decryptAuth(s0, s1, s2, mac, recovered);
        if (pt.length === 0) throw new Error('unreachable');
      },
    });
  }

  return modes;
}

function buildMessageModesTriple(): MessageMode[] {
  const modes: MessageMode[] = [];

  {
    const enc = buildEncryptorTriple(null);
    const buildCt = (_cipher: CipherName, payload: Buffer) =>
      Buffer.from(enc.encrypt(payload));
    modes.push({
      tag: 'msg_triple_easy_nomac',
      buildEncryptCipherText: buildCt,
      runEncrypt: (cipher, payload) => {
        const ct = Buffer.from(enc.encrypt(payload));
        wrapInPlace(cipher, _outerKeyFor(cipher), ct);
      },
      runDecrypt: (cipher, wire) => {
        const buf = Buffer.from(wire);
        const recovered = unwrapInPlace(cipher, _outerKeyFor(cipher), buf);
        enc.decrypt(recovered);
      },
    });
  }

  {
    const enc = buildEncryptorTriple(MAC_NAME);
    const buildCt = (_cipher: CipherName, payload: Buffer) =>
      Buffer.from(enc.encryptAuth(payload));
    modes.push({
      tag: 'msg_triple_easy_auth',
      buildEncryptCipherText: buildCt,
      runEncrypt: (cipher, payload) => {
        const ct = Buffer.from(enc.encryptAuth(payload));
        wrapInPlace(cipher, _outerKeyFor(cipher), ct);
      },
      runDecrypt: (cipher, wire) => {
        const buf = Buffer.from(wire);
        const recovered = unwrapInPlace(cipher, _outerKeyFor(cipher), buf);
        enc.decryptAuth(recovered);
      },
    });
  }

  {
    const seeds = buildSeedsTriple();
    const [n, d1, d2, d3, s1, s2, s3] = seeds;
    const buildCt = (_cipher: CipherName, payload: Buffer) =>
      Buffer.from(encryptTriple(n, d1, d2, d3, s1, s2, s3, payload));
    modes.push({
      tag: 'msg_triple_lowlevel_nomac',
      buildEncryptCipherText: buildCt,
      runEncrypt: (cipher, payload) => {
        const ct = Buffer.from(encryptTriple(n, d1, d2, d3, s1, s2, s3, payload));
        wrapInPlace(cipher, _outerKeyFor(cipher), ct);
      },
      runDecrypt: (cipher, wire) => {
        const buf = Buffer.from(wire);
        const recovered = unwrapInPlace(cipher, _outerKeyFor(cipher), buf);
        decryptTriple(n, d1, d2, d3, s1, s2, s3, recovered);
      },
    });
  }

  {
    const seeds = buildSeedsTriple();
    const [n, d1, d2, d3, s1, s2, s3] = seeds;
    const mac = new MAC(MAC_NAME, MAC_KEY);
    const buildCt = (_cipher: CipherName, payload: Buffer) =>
      Buffer.from(encryptAuthTriple(n, d1, d2, d3, s1, s2, s3, mac, payload));
    modes.push({
      tag: 'msg_triple_lowlevel_auth',
      buildEncryptCipherText: buildCt,
      runEncrypt: (cipher, payload) => {
        const ct = Buffer.from(
          encryptAuthTriple(n, d1, d2, d3, s1, s2, s3, mac, payload),
        );
        wrapInPlace(cipher, _outerKeyFor(cipher), ct);
      },
      runDecrypt: (cipher, wire) => {
        const buf = Buffer.from(wire);
        const recovered = unwrapInPlace(cipher, _outerKeyFor(cipher), buf);
        decryptAuthTriple(n, d1, d2, d3, s1, s2, s3, mac, recovered);
      },
    });
  }

  return modes;
}

// Per-cipher key cache — re-used across every benchmark to keep the
// hot loop free of CSPRNG overhead.
const _outerKeyCache = new Map<CipherName, Buffer>();
function _outerKeyFor(cipher: CipherName): Buffer {
  let key = _outerKeyCache.get(cipher);
  if (key === undefined) {
    key = wrapperGenerateKey(cipher);
    _outerKeyCache.set(cipher, key);
  }
  return key;
}

function buildMessageCases(modes: MessageMode[]): BenchCase[] {
  const cases: BenchCase[] = [];
  const payload = randomBytes(MESSAGE_BYTES);
  for (const mode of modes) {
    for (const cipher of CIPHER_NAMES) {
      const key = _outerKeyFor(cipher);
      // Pre-build the wire for the decrypt sub-bench so the encrypt
      // path is not in the timed loop.
      const ctPristine = mode.buildEncryptCipherText(cipher, payload);
      const wirePristine = wrap(cipher, key, ctPristine);

      cases.push({
        name: `bench_${mode.tag}/${cipher}/encrypt`,
        payloadBytes: MESSAGE_BYTES,
        run: (iters: number) => {
          for (let i = 0; i < iters; i++) {
            mode.runEncrypt(cipher, payload);
          }
        },
      });
      cases.push({
        name: `bench_${mode.tag}/${cipher}/decrypt`,
        payloadBytes: MESSAGE_BYTES,
        run: (iters: number) => {
          for (let i = 0; i < iters; i++) {
            // wire is mutated by unwrapInPlace inside the run body —
            // refresh from pristine each iter so the outer cipher
            // input is the same wire every call. The Buffer.from
            // copy cost is small relative to ITB Decrypt at 16 MiB.
            mode.runDecrypt(cipher, wirePristine);
          }
        },
      });
    }
  }
  return cases;
}

// ─── Streaming sub-benches (Single + Triple) ─────────────────────

interface StreamMode {
  readonly tag: string;
  readonly buildWire: (cipher: CipherName, payload: Buffer) => Promise<Buffer>;
  readonly runEncrypt: (cipher: CipherName, payload: Buffer) => Promise<void>;
  readonly runDecrypt: (cipher: CipherName, wire: Buffer) => Promise<void>;
}

function buildStreamModesSingle(): StreamMode[] {
  const modes: StreamMode[] = [];

  // 1) Streaming AEAD Easy IO-Driven — buffered inner-transcript
  // bridge to the wrap layer.
  {
    const enc = buildEncryptorSingle(MAC_NAME);
    const wireOf = async (cipher: CipherName, payload: Buffer): Promise<Buffer> => {
      const innerOut = new PassThrough();
      const innerIn = new PassThrough();
      innerIn.end(payload);
      await enc.encryptStreamAuth(innerIn, innerOut, STREAM_CHUNK_BYTES);
      innerOut.end();
      const innerBytes = await drain(innerOut);
      const ww = new WrapStreamWriter(cipher, _outerKeyFor(cipher));
      try {
        const body = ww.update(innerBytes);
        return Buffer.concat([ww.nonce, body]);
      } finally {
        ww.close();
      }
    };
    modes.push({
      tag: 'stream_single_aead_easy_io',
      buildWire: wireOf,
      runEncrypt: async (cipher, payload) => {
        await wireOf(cipher, payload);
      },
      runDecrypt: async (cipher, wire) => {
        const nlen = wrapperNonceSize(cipher);
        const ur = new UnwrapStreamReader(
          cipher,
          _outerKeyFor(cipher),
          wire.subarray(0, nlen),
        );
        let inner: Buffer;
        try {
          inner = ur.update(wire.subarray(nlen));
        } finally {
          ur.close();
        }
        const ptIn = new PassThrough();
        ptIn.end(inner);
        const ptOut = new PassThrough();
        await enc.decryptStreamAuth(ptIn, ptOut);
        ptOut.end();
        await drain(ptOut);
      },
    });
  }

  // 2) Streaming AEAD Low-Level IO-Driven
  {
    const seeds = buildSeedsSingle();
    const [s0, s1, s2] = seeds;
    const mac = new MAC(MAC_NAME, MAC_KEY);
    const wireOf = async (cipher: CipherName, payload: Buffer): Promise<Buffer> => {
      const innerOut = new PassThrough();
      const innerIn = new PassThrough();
      innerIn.end(payload);
      await encryptStreamAuth(s0, s1, s2, mac, innerIn, innerOut, STREAM_CHUNK_BYTES);
      innerOut.end();
      const innerBytes = await drain(innerOut);
      const ww = new WrapStreamWriter(cipher, _outerKeyFor(cipher));
      try {
        const body = ww.update(innerBytes);
        return Buffer.concat([ww.nonce, body]);
      } finally {
        ww.close();
      }
    };
    modes.push({
      tag: 'stream_single_aead_lowlevel_io',
      buildWire: wireOf,
      runEncrypt: async (cipher, payload) => {
        await wireOf(cipher, payload);
      },
      runDecrypt: async (cipher, wire) => {
        const nlen = wrapperNonceSize(cipher);
        const ur = new UnwrapStreamReader(
          cipher,
          _outerKeyFor(cipher),
          wire.subarray(0, nlen),
        );
        let inner: Buffer;
        try {
          inner = ur.update(wire.subarray(nlen));
        } finally {
          ur.close();
        }
        const ptIn = new PassThrough();
        ptIn.end(inner);
        const ptOut = new PassThrough();
        await decryptStreamAuth(s0, s1, s2, mac, ptIn, ptOut);
        ptOut.end();
        await drain(ptOut);
      },
    });
  }

  // 3) Streaming Easy No MAC, User-Driven Loop
  {
    const enc = buildEncryptorSingle(null);
    const wireOf = async (cipher: CipherName, payload: Buffer): Promise<Buffer> => {
      const ww = new WrapStreamWriter(cipher, _outerKeyFor(cipher));
      const parts: Buffer[] = [ww.nonce];
      try {
        let off = 0;
        while (off < payload.length) {
          const take = Math.min(STREAM_CHUNK_BYTES, payload.length - off);
          const ct = enc.encrypt(payload.subarray(off, off + take));
          const lenLe = Buffer.alloc(4);
          lenLe.writeUInt32LE(ct.length, 0);
          parts.push(ww.update(lenLe));
          parts.push(ww.update(Buffer.from(ct)));
          off += take;
        }
      } finally {
        ww.close();
      }
      return Buffer.concat(parts);
    };
    modes.push({
      tag: 'stream_single_noaead_easy_userloop',
      buildWire: wireOf,
      runEncrypt: async (cipher, payload) => {
        await wireOf(cipher, payload);
      },
      runDecrypt: async (cipher, wire) => {
        const nlen = wrapperNonceSize(cipher);
        const ur = new UnwrapStreamReader(
          cipher,
          _outerKeyFor(cipher),
          wire.subarray(0, nlen),
        );
        let decrypted: Buffer;
        try {
          decrypted = ur.update(wire.subarray(nlen));
        } finally {
          ur.close();
        }
        let pos = 0;
        while (pos < decrypted.length) {
          const clen = decrypted.readUInt32LE(pos);
          pos += 4;
          enc.decrypt(decrypted.subarray(pos, pos + clen));
          pos += clen;
        }
      },
    });
  }

  // 4) Streaming Low-Level No MAC, User-Driven Loop
  {
    const seeds = buildSeedsSingle();
    const [s0, s1, s2] = seeds;
    const wireOf = async (cipher: CipherName, payload: Buffer): Promise<Buffer> => {
      const ww = new WrapStreamWriter(cipher, _outerKeyFor(cipher));
      const parts: Buffer[] = [ww.nonce];
      try {
        let off = 0;
        while (off < payload.length) {
          const take = Math.min(STREAM_CHUNK_BYTES, payload.length - off);
          const ct = itbEncrypt(s0, s1, s2, payload.subarray(off, off + take));
          const lenLe = Buffer.alloc(4);
          lenLe.writeUInt32LE(ct.length, 0);
          parts.push(ww.update(lenLe));
          parts.push(ww.update(Buffer.from(ct)));
          off += take;
        }
      } finally {
        ww.close();
      }
      return Buffer.concat(parts);
    };
    modes.push({
      tag: 'stream_single_noaead_lowlevel_userloop',
      buildWire: wireOf,
      runEncrypt: async (cipher, payload) => {
        await wireOf(cipher, payload);
      },
      runDecrypt: async (cipher, wire) => {
        const nlen = wrapperNonceSize(cipher);
        const ur = new UnwrapStreamReader(
          cipher,
          _outerKeyFor(cipher),
          wire.subarray(0, nlen),
        );
        let decrypted: Buffer;
        try {
          decrypted = ur.update(wire.subarray(nlen));
        } finally {
          ur.close();
        }
        let pos = 0;
        while (pos < decrypted.length) {
          const clen = decrypted.readUInt32LE(pos);
          pos += 4;
          itbDecrypt(s0, s1, s2, decrypted.subarray(pos, pos + clen));
          pos += clen;
        }
      },
    });
  }

  return modes;
}

function buildStreamModesTriple(): StreamMode[] {
  const modes: StreamMode[] = [];

  // 1) Streaming AEAD Easy IO-Driven (Triple)
  {
    const enc = buildEncryptorTriple(MAC_NAME);
    const wireOf = async (cipher: CipherName, payload: Buffer): Promise<Buffer> => {
      const innerOut = new PassThrough();
      const innerIn = new PassThrough();
      innerIn.end(payload);
      await enc.encryptStreamAuth(innerIn, innerOut, STREAM_CHUNK_BYTES);
      innerOut.end();
      const innerBytes = await drain(innerOut);
      const ww = new WrapStreamWriter(cipher, _outerKeyFor(cipher));
      try {
        const body = ww.update(innerBytes);
        return Buffer.concat([ww.nonce, body]);
      } finally {
        ww.close();
      }
    };
    modes.push({
      tag: 'stream_triple_aead_easy_io',
      buildWire: wireOf,
      runEncrypt: async (cipher, payload) => {
        await wireOf(cipher, payload);
      },
      runDecrypt: async (cipher, wire) => {
        const nlen = wrapperNonceSize(cipher);
        const ur = new UnwrapStreamReader(
          cipher,
          _outerKeyFor(cipher),
          wire.subarray(0, nlen),
        );
        let inner: Buffer;
        try {
          inner = ur.update(wire.subarray(nlen));
        } finally {
          ur.close();
        }
        const ptIn = new PassThrough();
        ptIn.end(inner);
        const ptOut = new PassThrough();
        await enc.decryptStreamAuth(ptIn, ptOut);
        ptOut.end();
        await drain(ptOut);
      },
    });
  }

  // 2) Streaming AEAD Low-Level IO-Driven (Triple)
  {
    const seeds = buildSeedsTriple();
    const [n, d1, d2, d3, s1, s2, s3] = seeds;
    const mac = new MAC(MAC_NAME, MAC_KEY);
    const wireOf = async (cipher: CipherName, payload: Buffer): Promise<Buffer> => {
      const innerOut = new PassThrough();
      const innerIn = new PassThrough();
      innerIn.end(payload);
      await encryptStreamAuthTriple(
        n, d1, d2, d3, s1, s2, s3, mac, innerIn, innerOut, STREAM_CHUNK_BYTES,
      );
      innerOut.end();
      const innerBytes = await drain(innerOut);
      const ww = new WrapStreamWriter(cipher, _outerKeyFor(cipher));
      try {
        const body = ww.update(innerBytes);
        return Buffer.concat([ww.nonce, body]);
      } finally {
        ww.close();
      }
    };
    modes.push({
      tag: 'stream_triple_aead_lowlevel_io',
      buildWire: wireOf,
      runEncrypt: async (cipher, payload) => {
        await wireOf(cipher, payload);
      },
      runDecrypt: async (cipher, wire) => {
        const nlen = wrapperNonceSize(cipher);
        const ur = new UnwrapStreamReader(
          cipher,
          _outerKeyFor(cipher),
          wire.subarray(0, nlen),
        );
        let inner: Buffer;
        try {
          inner = ur.update(wire.subarray(nlen));
        } finally {
          ur.close();
        }
        const ptIn = new PassThrough();
        ptIn.end(inner);
        const ptOut = new PassThrough();
        await decryptStreamAuthTriple(
          n, d1, d2, d3, s1, s2, s3, mac, ptIn, ptOut,
        );
        ptOut.end();
        await drain(ptOut);
      },
    });
  }

  // 3) Streaming Easy No MAC, User-Driven Loop (Triple)
  {
    const enc = buildEncryptorTriple(null);
    const wireOf = async (cipher: CipherName, payload: Buffer): Promise<Buffer> => {
      const ww = new WrapStreamWriter(cipher, _outerKeyFor(cipher));
      const parts: Buffer[] = [ww.nonce];
      try {
        let off = 0;
        while (off < payload.length) {
          const take = Math.min(STREAM_CHUNK_BYTES, payload.length - off);
          const ct = enc.encrypt(payload.subarray(off, off + take));
          const lenLe = Buffer.alloc(4);
          lenLe.writeUInt32LE(ct.length, 0);
          parts.push(ww.update(lenLe));
          parts.push(ww.update(Buffer.from(ct)));
          off += take;
        }
      } finally {
        ww.close();
      }
      return Buffer.concat(parts);
    };
    modes.push({
      tag: 'stream_triple_noaead_easy_userloop',
      buildWire: wireOf,
      runEncrypt: async (cipher, payload) => {
        await wireOf(cipher, payload);
      },
      runDecrypt: async (cipher, wire) => {
        const nlen = wrapperNonceSize(cipher);
        const ur = new UnwrapStreamReader(
          cipher,
          _outerKeyFor(cipher),
          wire.subarray(0, nlen),
        );
        let decrypted: Buffer;
        try {
          decrypted = ur.update(wire.subarray(nlen));
        } finally {
          ur.close();
        }
        let pos = 0;
        while (pos < decrypted.length) {
          const clen = decrypted.readUInt32LE(pos);
          pos += 4;
          enc.decrypt(decrypted.subarray(pos, pos + clen));
          pos += clen;
        }
      },
    });
  }

  // 4) Streaming Low-Level No MAC, User-Driven Loop (Triple)
  {
    const seeds = buildSeedsTriple();
    const [n, d1, d2, d3, s1, s2, s3] = seeds;
    const wireOf = async (cipher: CipherName, payload: Buffer): Promise<Buffer> => {
      const ww = new WrapStreamWriter(cipher, _outerKeyFor(cipher));
      const parts: Buffer[] = [ww.nonce];
      try {
        let off = 0;
        while (off < payload.length) {
          const take = Math.min(STREAM_CHUNK_BYTES, payload.length - off);
          const ct = encryptTriple(
            n, d1, d2, d3, s1, s2, s3, payload.subarray(off, off + take),
          );
          const lenLe = Buffer.alloc(4);
          lenLe.writeUInt32LE(ct.length, 0);
          parts.push(ww.update(lenLe));
          parts.push(ww.update(Buffer.from(ct)));
          off += take;
        }
      } finally {
        ww.close();
      }
      return Buffer.concat(parts);
    };
    modes.push({
      tag: 'stream_triple_noaead_lowlevel_userloop',
      buildWire: wireOf,
      runEncrypt: async (cipher, payload) => {
        await wireOf(cipher, payload);
      },
      runDecrypt: async (cipher, wire) => {
        const nlen = wrapperNonceSize(cipher);
        const ur = new UnwrapStreamReader(
          cipher,
          _outerKeyFor(cipher),
          wire.subarray(0, nlen),
        );
        let decrypted: Buffer;
        try {
          decrypted = ur.update(wire.subarray(nlen));
        } finally {
          ur.close();
        }
        let pos = 0;
        while (pos < decrypted.length) {
          const clen = decrypted.readUInt32LE(pos);
          pos += 4;
          decryptTriple(n, d1, d2, d3, s1, s2, s3, decrypted.subarray(pos, pos + clen));
          pos += clen;
        }
      },
    });
  }

  return modes;
}

async function buildStreamCases(modes: StreamMode[]): Promise<BenchCase[]> {
  const cases: BenchCase[] = [];
  const payload = randomBytes(STREAM_TOTAL_BYTES);
  for (const mode of modes) {
    for (const cipher of CIPHER_NAMES) {
      // Pre-build the wire for the decrypt sub-bench so the encrypt
      // path is not in the timed loop.
      const wirePristine = await mode.buildWire(cipher, payload);
      cases.push({
        name: `bench_${mode.tag}/${cipher}/encrypt`,
        payloadBytes: STREAM_TOTAL_BYTES,
        run: async (iters: number) => {
          for (let i = 0; i < iters; i++) {
            await mode.runEncrypt(cipher, payload);
          }
        },
      });
      cases.push({
        name: `bench_${mode.tag}/${cipher}/decrypt`,
        payloadBytes: STREAM_TOTAL_BYTES,
        run: async (iters: number) => {
          for (let i = 0; i < iters; i++) {
            await mode.runDecrypt(cipher, wirePristine);
          }
        },
      });
    }
  }
  return cases;
}

// ─── Entry point ──────────────────────────────────────────────────

export async function runWrapperBench(): Promise<void> {
  setMaxWorkers(0);
  setNonceBits(128);
  setBarrierFill(1);
  setBitSoup(0);
  setLockSoup(0);

  console.log(
    `# wrapper primitive=${PRIMITIVE} key_bits_single=${KEY_BITS_SINGLE} ` +
      `key_bits_triple=${KEY_BITS_TRIPLE} mac=${MAC_NAME} ` +
      `message_bytes=${MESSAGE_BYTES} stream_total=${STREAM_TOTAL_BYTES} ` +
      `stream_chunk=${STREAM_CHUNK_BYTES} workers=auto`,
  );

  const cases: BenchCase[] = [];
  cases.push(...buildWrapperOnlyCases());

  const msgSingle = buildMessageModesSingle();
  const msgTriple = buildMessageModesTriple();
  cases.push(...buildMessageCases(msgSingle));
  cases.push(...buildMessageCases(msgTriple));

  const streamSingle = buildStreamModesSingle();
  const streamTriple = buildStreamModesTriple();
  cases.push(...(await buildStreamCases(streamSingle)));
  cases.push(...(await buildStreamCases(streamTriple)));

  // Sanity assertion: 6 + 24 + 24 + 24 + 24 = 102.
  if (cases.length !== 102) {
    console.error(
      `bench-wrapper: case count mismatch — expected 102, got ${cases.length}`,
    );
  }

  await runAll(cases);
}

// `main.ts`-style direct invocation when run as a standalone module.
if (process.argv[1] !== undefined && process.argv[1].endsWith('bench-wrapper.js')) {
  runWrapperBench().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}
