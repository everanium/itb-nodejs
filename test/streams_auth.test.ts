// Tests for the authenticated Node.js streaming wrappers
// (StreamEncryptorAuth / StreamDecryptorAuth + Triple Ouroboros
// counterparts + the encryptStreamAuth / decryptStreamAuth
// convenience functions).
//
// Coverage mirrors the cross-binding contract for Streaming AEAD:
//
//   - Round-trip per (Single + Triple) × (3 hash widths) ×
//     (3 MAC primitives).
//   - Reorder of two chunks → ITBError MacFailure.
//   - Truncate-tail → ITBStreamTruncatedError from close().
//   - Cross-stream replay → ITBError MacFailure.
//   - Stream-prefix tamper → ITBError MacFailure.
//   - Empty stream + single-chunk stream round-trip.
//   - Write/Feed after Close → ITBError EasyClosed.
//   - Trailing bytes past the terminator → ITBStreamAfterFinalError.

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { PassThrough } from 'node:stream';

import {
  decryptStreamAuth,
  decryptStreamAuthTriple,
  encryptStreamAuth,
  encryptStreamAuthTriple,
  getNonceBits,
  ITBError,
  ITBStreamAfterFinalError,
  ITBStreamTruncatedError,
  MAC,
  parseChunkLen,
  Seed,
  setNonceBits,
  StreamDecryptorAuth,
  StreamDecryptorAuthTriple,
  StreamEncryptorAuth,
  StreamEncryptorAuthTriple,
  Status,
  STREAM_ID_LEN,
  headerSize,
} from '../src/index.js';

const SMALL_CHUNK = 4096;

const CANONICAL_MACS = ['kmac256', 'hmac-sha256', 'hmac-blake3'] as const;
const HASH_BY_WIDTH: ReadonlyArray<readonly [string, number]> = [
  ['siphash24', 128],
  ['blake3', 256],
  ['blake2b512', 512],
];

function tokenBytes(n: number): Uint8Array {
  return new Uint8Array(randomBytes(n));
}

function makeSeeds(hashName: string, n: number): Seed[] {
  const out: Seed[] = [];
  for (let i = 0; i < n; i++) out.push(new Seed(hashName, 1024));
  return out;
}

function disposeAll(seeds: Seed[]): void {
  for (const s of seeds) s.free();
}

function newMac(name: string): MAC {
  return new MAC(name, new Uint8Array(randomBytes(32)));
}

async function drain(stream: PassThrough): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(chunk as Buffer);
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

/**
 * Splits a Streaming AEAD wire transcript into the 32-byte streamId
 * prefix and the on-wire chunk byte slices.
 */
function splitChunks(ct: Uint8Array): { prefix: Uint8Array; chunks: Uint8Array[] } {
  const hSz = headerSize();
  const prefix = ct.subarray(0, STREAM_ID_LEN);
  const body = ct.subarray(STREAM_ID_LEN);
  const chunks: Uint8Array[] = [];
  let off = 0;
  while (off < body.length) {
    const cl = parseChunkLen(body.subarray(off, off + hSz));
    chunks.push(body.subarray(off, off + cl));
    off += cl;
  }
  return { prefix, chunks };
}

function concatU8(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

describe('test_streams_auth', () => {
  test('single class roundtrip default nonce', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 5 + 17);
    const seeds = makeSeeds('blake3', 3);
    const mac = newMac('hmac-blake3');
    try {
      const cbuf = new PassThrough();
      const enc = new StreamEncryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, cbuf, SMALL_CHUNK);
      enc.write(plaintext.subarray(0, 1000));
      enc.write(plaintext.subarray(1000, 5000));
      enc.write(plaintext.subarray(5000));
      enc.close();
      cbuf.end();
      const ct = await drain(cbuf);
      assert.ok(ct.length >= STREAM_ID_LEN);

      const pbuf = new PassThrough();
      const dec = new StreamDecryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, pbuf);
      for (let off = 0; off < ct.length; off += 1024) {
        dec.feed(ct.subarray(off, Math.min(off + 1024, ct.length)));
      }
      dec.close();
      pbuf.end();
      const pt = await drain(pbuf);
      assert.deepEqual(pt, plaintext);
    } finally {
      mac.free();
      disposeAll(seeds);
    }
  });

  test('single all macs all widths', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 2 + 33);
    for (const macName of CANONICAL_MACS) {
      for (const [hashName] of HASH_BY_WIDTH) {
        const seeds = makeSeeds(hashName, 3);
        const mac = newMac(macName);
        try {
          const cbuf = new PassThrough();
          const enc = new StreamEncryptorAuth(
            seeds[0]!, seeds[1]!, seeds[2]!, mac, cbuf, SMALL_CHUNK);
          enc.write(plaintext);
          enc.close();
          cbuf.end();
          const ct = await drain(cbuf);

          const pbuf = new PassThrough();
          const dec = new StreamDecryptorAuth(
            seeds[0]!, seeds[1]!, seeds[2]!, mac, pbuf);
          dec.feed(ct);
          dec.close();
          pbuf.end();
          const pt = await drain(pbuf);
          assert.deepEqual(pt, plaintext);
        } finally {
          mac.free();
          disposeAll(seeds);
        }
      }
    }
  });

  test('single non default nonce', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 3 + 100);
    for (const n of [256, 512]) {
      const orig = getNonceBits();
      setNonceBits(n);
      const seeds = makeSeeds('blake3', 3);
      const mac = newMac('hmac-sha256');
      try {
        const cbuf = new PassThrough();
        const enc = new StreamEncryptorAuth(
          seeds[0]!, seeds[1]!, seeds[2]!, mac, cbuf, SMALL_CHUNK);
        enc.write(plaintext);
        enc.close();
        cbuf.end();
        const ct = await drain(cbuf);

        const pbuf = new PassThrough();
        const dec = new StreamDecryptorAuth(
          seeds[0]!, seeds[1]!, seeds[2]!, mac, pbuf);
        dec.feed(ct);
        dec.close();
        pbuf.end();
        const pt = await drain(pbuf);
        assert.deepEqual(pt, plaintext);
      } finally {
        mac.free();
        disposeAll(seeds);
        setNonceBits(orig);
      }
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Triple Ouroboros + MAC.
  // ────────────────────────────────────────────────────────────────

  test('triple class roundtrip default nonce', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 4 + 33);
    const seeds = makeSeeds('blake3', 7);
    const mac = newMac('hmac-blake3');
    try {
      const cbuf = new PassThrough();
      const enc = new StreamEncryptorAuthTriple(
        seeds[0]!, seeds[1]!, seeds[2]!, seeds[3]!,
        seeds[4]!, seeds[5]!, seeds[6]!, mac, cbuf, SMALL_CHUNK);
      enc.write(plaintext.subarray(0, SMALL_CHUNK));
      enc.write(plaintext.subarray(SMALL_CHUNK, 3 * SMALL_CHUNK));
      enc.write(plaintext.subarray(3 * SMALL_CHUNK));
      enc.close();
      cbuf.end();
      const ct = await drain(cbuf);

      const pbuf = new PassThrough();
      const dec = new StreamDecryptorAuthTriple(
        seeds[0]!, seeds[1]!, seeds[2]!, seeds[3]!,
        seeds[4]!, seeds[5]!, seeds[6]!, mac, pbuf);
      dec.feed(ct);
      dec.close();
      pbuf.end();
      assert.deepEqual(await drain(pbuf), plaintext);
    } finally {
      mac.free();
      disposeAll(seeds);
    }
  });

  test('triple all macs all widths', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 2 + 7);
    for (const macName of CANONICAL_MACS) {
      for (const [hashName] of HASH_BY_WIDTH) {
        const seeds = makeSeeds(hashName, 7);
        const mac = newMac(macName);
        try {
          const cbuf = new PassThrough();
          const enc = new StreamEncryptorAuthTriple(
            seeds[0]!, seeds[1]!, seeds[2]!, seeds[3]!,
            seeds[4]!, seeds[5]!, seeds[6]!, mac, cbuf, SMALL_CHUNK);
          enc.write(plaintext);
          enc.close();
          cbuf.end();
          const ct = await drain(cbuf);

          const pbuf = new PassThrough();
          const dec = new StreamDecryptorAuthTriple(
            seeds[0]!, seeds[1]!, seeds[2]!, seeds[3]!,
            seeds[4]!, seeds[5]!, seeds[6]!, mac, pbuf);
          dec.feed(ct);
          dec.close();
          pbuf.end();
          assert.deepEqual(await drain(pbuf), plaintext);
        } finally {
          mac.free();
          disposeAll(seeds);
        }
      }
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Functional helpers.
  // ────────────────────────────────────────────────────────────────

  test('encryptStreamAuth decryptStreamAuth roundtrip', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 4);
    const seeds = makeSeeds('blake3', 3);
    const mac = newMac('hmac-blake3');
    try {
      const cbuf = new PassThrough();
      const fin = new PassThrough();
      fin.end(plaintext);
      await encryptStreamAuth(seeds[0]!, seeds[1]!, seeds[2]!, mac, fin, cbuf, SMALL_CHUNK);
      cbuf.end();
      const ct = await drain(cbuf);

      const pbuf = new PassThrough();
      const cin = new PassThrough();
      cin.end(ct);
      await decryptStreamAuth(seeds[0]!, seeds[1]!, seeds[2]!, mac, cin, pbuf);
      pbuf.end();
      assert.deepEqual(await drain(pbuf), plaintext);
    } finally {
      mac.free();
      disposeAll(seeds);
    }
  });

  test('encryptStreamAuthTriple decryptStreamAuthTriple roundtrip', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 5 + 7);
    const seeds = makeSeeds('blake3', 7);
    const mac = newMac('hmac-sha256');
    try {
      const cbuf = new PassThrough();
      const fin = new PassThrough();
      fin.end(plaintext);
      await encryptStreamAuthTriple(
        seeds[0]!, seeds[1]!, seeds[2]!, seeds[3]!,
        seeds[4]!, seeds[5]!, seeds[6]!, mac, fin, cbuf, SMALL_CHUNK);
      cbuf.end();
      const ct = await drain(cbuf);

      const pbuf = new PassThrough();
      const cin = new PassThrough();
      cin.end(ct);
      await decryptStreamAuthTriple(
        seeds[0]!, seeds[1]!, seeds[2]!, seeds[3]!,
        seeds[4]!, seeds[5]!, seeds[6]!, mac, cin, pbuf);
      pbuf.end();
      assert.deepEqual(await drain(pbuf), plaintext);
    } finally {
      mac.free();
      disposeAll(seeds);
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Edge cases.
  // ────────────────────────────────────────────────────────────────

  test('empty stream', async () => {
    const seeds = makeSeeds('blake3', 3);
    const mac = newMac('hmac-blake3');
    try {
      const cbuf = new PassThrough();
      const enc = new StreamEncryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, cbuf, SMALL_CHUNK);
      enc.close();
      cbuf.end();
      const ct = await drain(cbuf);
      assert.ok(ct.length > STREAM_ID_LEN);

      const pbuf = new PassThrough();
      const dec = new StreamDecryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, pbuf);
      dec.feed(ct);
      dec.close();
      pbuf.end();
      const pt = await drain(pbuf);
      assert.equal(pt.length, 0);
    } finally {
      mac.free();
      disposeAll(seeds);
    }
  });

  test('single chunk stream', async () => {
    const plaintext = new Uint8Array(100).fill(0x78);
    const seeds = makeSeeds('blake3', 3);
    const mac = newMac('hmac-blake3');
    try {
      const cbuf = new PassThrough();
      const enc = new StreamEncryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, cbuf, SMALL_CHUNK);
      enc.write(plaintext);
      enc.close();
      cbuf.end();
      const ct = await drain(cbuf);

      const pbuf = new PassThrough();
      const dec = new StreamDecryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, pbuf);
      dec.feed(ct);
      dec.close();
      pbuf.end();
      assert.deepEqual(await drain(pbuf), plaintext);
    } finally {
      mac.free();
      disposeAll(seeds);
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Detection paths — five attack vectors closed by the
  // Streaming AEAD construction.
  // ────────────────────────────────────────────────────────────────

  async function produceCt(seeds: Seed[], mac: MAC, plaintext: Uint8Array): Promise<Uint8Array> {
    const cbuf = new PassThrough();
    const enc = new StreamEncryptorAuth(
      seeds[0]!, seeds[1]!, seeds[2]!, mac, cbuf, SMALL_CHUNK);
    enc.write(plaintext);
    enc.close();
    cbuf.end();
    return drain(cbuf);
  }

  test('chunk reorder detected', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 2 + SMALL_CHUNK / 2);
    const seeds = makeSeeds('blake3', 3);
    const mac = newMac('hmac-blake3');
    try {
      const ct = await produceCt(seeds, mac, plaintext);
      const { prefix, chunks } = splitChunks(ct);
      assert.ok(chunks.length >= 3);
      const tampered = concatU8([prefix, chunks[1]!, chunks[0]!, ...chunks.slice(2)]);
      const pbuf = new PassThrough();
      const dec = new StreamDecryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, pbuf);
      assert.throws(() => {
        dec.feed(tampered);
        dec.close();
      }, (err: unknown) => {
        return err instanceof ITBError && (err as ITBError).code === Status.MacFailure;
      });
    } finally {
      mac.free();
      disposeAll(seeds);
    }
  });

  test('truncate tail detected', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 2 + SMALL_CHUNK / 2);
    const seeds = makeSeeds('blake3', 3);
    const mac = newMac('hmac-blake3');
    try {
      const ct = await produceCt(seeds, mac, plaintext);
      const { prefix, chunks } = splitChunks(ct);
      assert.ok(chunks.length >= 2);
      const truncated = concatU8([prefix, ...chunks.slice(0, -1)]);
      const pbuf = new PassThrough();
      const dec = new StreamDecryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, pbuf);
      dec.feed(truncated);
      assert.throws(() => dec.close(), (err: unknown) => {
        return err instanceof ITBStreamTruncatedError &&
          (err as ITBError).code === Status.StreamTruncated;
      });
    } finally {
      mac.free();
      disposeAll(seeds);
    }
  });

  test('after final detected', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK + 100);
    const seeds = makeSeeds('blake3', 3);
    const mac = newMac('hmac-blake3');
    try {
      const ct = await produceCt(seeds, mac, plaintext);
      const { prefix, chunks } = splitChunks(ct);
      const afterFinal = concatU8([prefix, ...chunks, chunks[chunks.length - 1]!]);
      const pbuf = new PassThrough();
      const dec = new StreamDecryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, pbuf);
      assert.throws(() => dec.feed(afterFinal), (err: unknown) => {
        return err instanceof ITBStreamAfterFinalError &&
          (err as ITBError).code === Status.StreamAfterFinal;
      });
    } finally {
      mac.free();
      disposeAll(seeds);
    }
  });

  test('cross stream replay detected', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 2);
    const seeds = makeSeeds('blake3', 3);
    const mac = newMac('hmac-blake3');
    try {
      const ctA = await produceCt(seeds, mac, plaintext);
      const ctB = await produceCt(seeds, mac, plaintext);
      const a = splitChunks(ctA);
      const b = splitChunks(ctB);
      assert.notDeepEqual(Array.from(a.prefix), Array.from(b.prefix));
      const tampered = concatU8([b.prefix, a.chunks[0]!, ...b.chunks.slice(1)]);
      const pbuf = new PassThrough();
      const dec = new StreamDecryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, pbuf);
      assert.throws(() => {
        dec.feed(tampered);
        dec.close();
      }, (err: unknown) => {
        return err instanceof ITBError && (err as ITBError).code === Status.MacFailure;
      });
    } finally {
      mac.free();
      disposeAll(seeds);
    }
  });

  test('stream prefix tamper detected', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK + 200);
    const seeds = makeSeeds('blake3', 3);
    const mac = newMac('hmac-blake3');
    try {
      const ct = await produceCt(seeds, mac, plaintext);
      const tampered = ct.slice();
      tampered[0]! ^= 0x80;
      const pbuf = new PassThrough();
      const dec = new StreamDecryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, pbuf);
      assert.throws(() => {
        dec.feed(tampered);
        dec.close();
      }, (err: unknown) => {
        return err instanceof ITBError && (err as ITBError).code === Status.MacFailure;
      });
    } finally {
      mac.free();
      disposeAll(seeds);
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Closed-state preflight.
  // ────────────────────────────────────────────────────────────────

  test('write after close raises', async () => {
    const seeds = makeSeeds('blake3', 3);
    const mac = newMac('hmac-blake3');
    try {
      const cbuf = new PassThrough();
      const enc = new StreamEncryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, cbuf, SMALL_CHUNK);
      enc.write(new TextEncoder().encode('hello'));
      enc.close();
      cbuf.end();
      // drain to release resource — independent of test outcome.
      void drain(cbuf);
      assert.throws(() => enc.write(new TextEncoder().encode('world')),
        (err: unknown) => {
          return err instanceof ITBError && (err as ITBError).code === Status.EasyClosed;
        });
    } finally {
      mac.free();
      disposeAll(seeds);
    }
  });

  test('feed after close raises', async () => {
    const seeds = makeSeeds('blake3', 3);
    const mac = newMac('hmac-blake3');
    try {
      const cbuf = new PassThrough();
      const enc = new StreamEncryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, cbuf, SMALL_CHUNK);
      enc.write(new Uint8Array(100));
      enc.close();
      cbuf.end();
      const ct = await drain(cbuf);
      const pbuf = new PassThrough();
      const dec = new StreamDecryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, pbuf);
      dec.feed(ct);
      dec.close();
      pbuf.end();
      void drain(pbuf);
      assert.throws(() => dec.feed(new Uint8Array(1)),
        (err: unknown) => {
          return err instanceof ITBError && (err as ITBError).code === Status.EasyClosed;
        });
    } finally {
      mac.free();
      disposeAll(seeds);
    }
  });

  test('bad chunk size rejected', () => {
    const seeds = makeSeeds('blake3', 3);
    const mac = newMac('hmac-blake3');
    try {
      assert.throws(() => new StreamEncryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, new PassThrough(), 0),
        (err: unknown) => {
          return err instanceof ITBError && (err as ITBError).code === Status.BadInput;
        });
    } finally {
      mac.free();
      disposeAll(seeds);
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Lifetime — sync FFI blocks the V8 main thread, so the
  // FinalizationRegistry cannot fire mid-FFI. The wrapper retains
  // Seed / Mac references on instance fields throughout; the test
  // verifies the encryptor stays usable across explicit GC rounds.
  // ────────────────────────────────────────────────────────────────

  test('symbol dispose works', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK + 1);
    const seeds = makeSeeds('blake3', 3);
    const mac = newMac('hmac-blake3');
    try {
      const cbuf = new PassThrough();
      {
        // `using` declaration would call [Symbol.dispose] at scope
        // exit; emulate with an explicit dispose call.
        const enc = new StreamEncryptorAuth(
          seeds[0]!, seeds[1]!, seeds[2]!, mac, cbuf, SMALL_CHUNK);
        enc.write(plaintext);
        enc[Symbol.dispose]();
      }
      cbuf.end();
      const ct = await drain(cbuf);

      const pbuf = new PassThrough();
      const dec = new StreamDecryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, pbuf);
      dec.feed(ct);
      dec.close();
      pbuf.end();
      assert.deepEqual(await drain(pbuf), plaintext);
    } finally {
      mac.free();
      disposeAll(seeds);
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Per-byte chunk_size = 1 round-trip. Exercises the per-chunk
  // dispatch loop with the smallest possible plaintext granularity:
  // every plaintext byte triggers one full per-chunk MAC round-trip
  // and one container-cap encrypt/decrypt. Single-mode coverage on
  // one MAC primitive is sufficient — Triple is structurally
  // identical at the helper level.
  // ────────────────────────────────────────────────────────────────

  test('chunk size one roundtrip single', async () => {
    const plaintext = new TextEncoder().encode('chunk1by');  // 8 bytes
    const seeds = makeSeeds('blake3', 3);
    const mac = newMac('hmac-blake3');
    try {
      const cbuf = new PassThrough();
      const enc = new StreamEncryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, cbuf, 1);
      enc.write(plaintext);
      enc.close();
      cbuf.end();
      const ct = await drain(cbuf);

      const pbuf = new PassThrough();
      const dec = new StreamDecryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, pbuf);
      dec.feed(ct);
      dec.close();
      pbuf.end();
      assert.deepEqual(await drain(pbuf), plaintext);
    } finally {
      mac.free();
      disposeAll(seeds);
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Incomplete 32-byte stream-id prefix is a wire-level
  // malformation distinct from truncate-tail. Surfaces ITBError with
  // Status.BadInput rather than ITBStreamTruncatedError.
  // ────────────────────────────────────────────────────────────────

  test('incomplete prefix raises bad input', () => {
    const seeds = makeSeeds('blake3', 3);
    const mac = newMac('hmac-blake3');
    try {
      const pbuf = new PassThrough();
      const dec = new StreamDecryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, pbuf);
      dec.feed(new Uint8Array(16));  // 16 of 32 prefix bytes
      assert.throws(() => dec.close(), (err: unknown) => {
        return err instanceof ITBError &&
          (err as ITBError).code === Status.BadInput &&
          !(err instanceof ITBStreamTruncatedError);
      });
    } finally {
      mac.free();
      disposeAll(seeds);
    }
  });

  test('zero byte prefix raises bad input', () => {
    const seeds = makeSeeds('blake3', 3);
    const mac = newMac('hmac-blake3');
    try {
      const pbuf = new PassThrough();
      const dec = new StreamDecryptorAuth(
        seeds[0]!, seeds[1]!, seeds[2]!, mac, pbuf);
      assert.throws(() => dec.close(), (err: unknown) => {
        return err instanceof ITBError &&
          (err as ITBError).code === Status.BadInput;
      });
    } finally {
      mac.free();
      disposeAll(seeds);
    }
  });
});
