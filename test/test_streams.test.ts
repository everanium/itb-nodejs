// Tests for the Node.js streaming wrappers (`StreamEncryptor` /
// `StreamDecryptor` + `StreamEncryptorTriple` / `StreamDecryptorTriple`
// + the `encryptStream` / `decryptStream` / `*Triple` convenience
// functions).
//
// Mirrors bindings/python/tests/test_streams.py — every test uses
// `PassThrough` as both input and output to exercise the file-like
// contract without touching disk. Multi-chunk inputs are constructed
// by calling `.write()` multiple times with sub-chunk slices, ensuring
// the encryptor's accumulator + flush logic processes more than one
// chunk per stream.
//
// The wrapped `Writable` is NOT auto-ended by `StreamEncryptor` /
// `StreamDecryptor` (or by `encryptStream` / `decryptStream`) — this
// is the binding's documented lifecycle contract; the caller retains
// ownership of the wrapped stream. Each test calls `output.end()`
// after the wrapper is closed so the for-await consumer terminates.
//
// Triple-Ouroboros and non-default nonce-bits configurations are
// covered explicitly. Tests that mutate `setNonceBits` wrap the
// mutation in save/restore. node:test runs each test file in its own
// child process, so cross-file races against other test binaries do
// not occur. Within this file `test()` calls run serially.

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { PassThrough } from 'node:stream';

import {
  decryptStream,
  decryptStreamTriple,
  encryptStream,
  encryptStreamTriple,
  getNonceBits,
  ITBError,
  Seed,
  setNonceBits,
  StreamDecryptor,
  StreamDecryptorTriple,
  StreamEncryptor,
  StreamEncryptorTriple,
  Status,
} from '../src/index.js';

// Small chunk size to force multiple chunks for short inputs and
// exercise the accumulator-flush path. ITB still accepts these sizes;
// only the wire-format chunk count is amplified.
const SMALL_CHUNK = 4096;

function tokenBytes(n: number): Uint8Array {
  return new Uint8Array(randomBytes(n));
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function makeSeeds(hashName: string, n: number): Seed[] {
  const out: Seed[] = [];
  for (let i = 0; i < n; i++) out.push(new Seed(hashName, 1024));
  return out;
}

function disposeAll(seeds: Seed[]): void {
  for (const s of seeds) s.free();
}

/**
 * Drains a `PassThrough` (already `.end()`-ed) into a single
 * `Uint8Array`. The `for await` consumer terminates once the
 * underlying stream has been closed by the writer.
 */
async function drain(stream: PassThrough): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(chunk as Buffer);
  }
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

describe('test_streams', () => {
  // ────────────────────────────────────────────────────────────────
  // Single Ouroboros — class-based round-trip.
  // ────────────────────────────────────────────────────────────────

  test('single class roundtrip default nonce', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 5 + 17);
    const seeds = makeSeeds('blake3', 3);
    try {
      const cbuf = new PassThrough();
      const [s0, s1, s2] = seeds as [Seed, Seed, Seed];
      {
        const enc = new StreamEncryptor(s0, s1, s2, cbuf, SMALL_CHUNK);
        // Push data in three irregular slices, exercising the
        // accumulator path on partial chunks.
        enc.write(plaintext.subarray(0, 1000));
        enc.write(plaintext.subarray(1000, 5000));
        enc.write(plaintext.subarray(5000));
        enc.close();
      }
      cbuf.end();
      const ct = await drain(cbuf);

      const pbuf = new PassThrough();
      {
        const dec = new StreamDecryptor(s0, s1, s2, pbuf);
        // Feed ciphertext in 1-KB shards.
        for (let off = 0; off < ct.length; off += 1024) {
          dec.feed(ct.subarray(off, Math.min(off + 1024, ct.length)));
        }
        dec.close();
      }
      pbuf.end();
      const recovered = await drain(pbuf);
      assert.ok(bytesEqual(recovered, plaintext));
    } finally {
      disposeAll(seeds);
    }
  });

  test('single class roundtrip non default nonce', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 3 + 100);
    for (const n of [256, 512]) {
      const orig = getNonceBits();
      setNonceBits(n);
      try {
        const seeds = makeSeeds('blake3', 3);
        try {
          const cbuf = new PassThrough();
          const [s0, s1, s2] = seeds as [Seed, Seed, Seed];
          {
            const enc = new StreamEncryptor(s0, s1, s2, cbuf, SMALL_CHUNK);
            enc.write(plaintext);
            enc.close();
          }
          cbuf.end();
          const ct = await drain(cbuf);

          const pbuf = new PassThrough();
          {
            const dec = new StreamDecryptor(s0, s1, s2, pbuf);
            dec.feed(ct);
            dec.close();
          }
          pbuf.end();
          const recovered = await drain(pbuf);
          assert.ok(bytesEqual(recovered, plaintext), `nonce=${n}`);
        } finally {
          disposeAll(seeds);
        }
      } finally {
        setNonceBits(orig);
      }
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Single Ouroboros — function-based round-trip.
  // ────────────────────────────────────────────────────────────────

  test('encrypt stream decrypt stream', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 4);
    const seeds = makeSeeds('blake3', 3);
    try {
      const fin = new PassThrough();
      fin.end(Buffer.from(plaintext));
      const cbuf = new PassThrough();
      const [s0, s1, s2] = seeds as [Seed, Seed, Seed];
      await encryptStream(s0, s1, s2, fin, cbuf, SMALL_CHUNK);
      cbuf.end();
      const ct = await drain(cbuf);

      const cin = new PassThrough();
      cin.end(Buffer.from(ct));
      const pbuf = new PassThrough();
      await decryptStream(s0, s1, s2, cin, pbuf);
      pbuf.end();
      const recovered = await drain(pbuf);
      assert.ok(bytesEqual(recovered, plaintext));
    } finally {
      disposeAll(seeds);
    }
  });

  test('encrypt stream across nonce sizes', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 3 + 256);
    for (const n of [128, 256, 512]) {
      const orig = getNonceBits();
      setNonceBits(n);
      try {
        const seeds = makeSeeds('blake3', 3);
        try {
          const fin = new PassThrough();
          fin.end(Buffer.from(plaintext));
          const cbuf = new PassThrough();
          const [s0, s1, s2] = seeds as [Seed, Seed, Seed];
          await encryptStream(s0, s1, s2, fin, cbuf, SMALL_CHUNK);
          cbuf.end();
          const ct = await drain(cbuf);

          const cin = new PassThrough();
          cin.end(Buffer.from(ct));
          const pbuf = new PassThrough();
          await decryptStream(s0, s1, s2, cin, pbuf);
          pbuf.end();
          const recovered = await drain(pbuf);
          assert.ok(bytesEqual(recovered, plaintext), `nonce=${n}`);
        } finally {
          disposeAll(seeds);
        }
      } finally {
        setNonceBits(orig);
      }
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Triple Ouroboros — class-based round-trip.
  // ────────────────────────────────────────────────────────────────

  test('triple class roundtrip default nonce', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 4 + 33);
    const seeds = makeSeeds('blake3', 7);
    try {
      const [s0, s1, s2, s3, s4, s5, s6] = seeds as [
        Seed, Seed, Seed, Seed, Seed, Seed, Seed,
      ];
      const cbuf = new PassThrough();
      {
        const enc = new StreamEncryptorTriple(
          s0, s1, s2, s3, s4, s5, s6, cbuf, SMALL_CHUNK,
        );
        enc.write(plaintext.subarray(0, SMALL_CHUNK));
        enc.write(plaintext.subarray(SMALL_CHUNK, 3 * SMALL_CHUNK));
        enc.write(plaintext.subarray(3 * SMALL_CHUNK));
        enc.close();
      }
      cbuf.end();
      const ct = await drain(cbuf);

      const pbuf = new PassThrough();
      {
        const dec = new StreamDecryptorTriple(s0, s1, s2, s3, s4, s5, s6, pbuf);
        dec.feed(ct);
        dec.close();
      }
      pbuf.end();
      const recovered = await drain(pbuf);
      assert.ok(bytesEqual(recovered, plaintext));
    } finally {
      disposeAll(seeds);
    }
  });

  test('triple class roundtrip non default nonce', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 3);
    for (const n of [256, 512]) {
      const orig = getNonceBits();
      setNonceBits(n);
      try {
        const seeds = makeSeeds('blake3', 7);
        try {
          const [s0, s1, s2, s3, s4, s5, s6] = seeds as [
            Seed, Seed, Seed, Seed, Seed, Seed, Seed,
          ];
          const cbuf = new PassThrough();
          {
            const enc = new StreamEncryptorTriple(
              s0, s1, s2, s3, s4, s5, s6, cbuf, SMALL_CHUNK,
            );
            enc.write(plaintext);
            enc.close();
          }
          cbuf.end();
          const ct = await drain(cbuf);

          const pbuf = new PassThrough();
          {
            const dec = new StreamDecryptorTriple(s0, s1, s2, s3, s4, s5, s6, pbuf);
            dec.feed(ct);
            dec.close();
          }
          pbuf.end();
          const recovered = await drain(pbuf);
          assert.ok(bytesEqual(recovered, plaintext), `nonce=${n}`);
        } finally {
          disposeAll(seeds);
        }
      } finally {
        setNonceBits(orig);
      }
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Triple Ouroboros — function-based round-trip.
  // ────────────────────────────────────────────────────────────────

  test('encrypt stream triple decrypt stream triple', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 5 + 7);
    const seeds = makeSeeds('blake3', 7);
    try {
      const [s0, s1, s2, s3, s4, s5, s6] = seeds as [
        Seed, Seed, Seed, Seed, Seed, Seed, Seed,
      ];
      const fin = new PassThrough();
      fin.end(Buffer.from(plaintext));
      const cbuf = new PassThrough();
      await encryptStreamTriple(
        s0, s1, s2, s3, s4, s5, s6, fin, cbuf, SMALL_CHUNK,
      );
      cbuf.end();
      const ct = await drain(cbuf);

      const cin = new PassThrough();
      cin.end(Buffer.from(ct));
      const pbuf = new PassThrough();
      await decryptStreamTriple(s0, s1, s2, s3, s4, s5, s6, cin, pbuf);
      pbuf.end();
      const recovered = await drain(pbuf);
      assert.ok(bytesEqual(recovered, plaintext));
    } finally {
      disposeAll(seeds);
    }
  });

  test('encrypt stream triple across nonce sizes', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 3 + 100);
    for (const n of [128, 256, 512]) {
      const orig = getNonceBits();
      setNonceBits(n);
      try {
        const seeds = makeSeeds('blake3', 7);
        try {
          const [s0, s1, s2, s3, s4, s5, s6] = seeds as [
            Seed, Seed, Seed, Seed, Seed, Seed, Seed,
          ];
          const fin = new PassThrough();
          fin.end(Buffer.from(plaintext));
          const cbuf = new PassThrough();
          await encryptStreamTriple(
            s0, s1, s2, s3, s4, s5, s6, fin, cbuf, SMALL_CHUNK,
          );
          cbuf.end();
          const ct = await drain(cbuf);

          const cin = new PassThrough();
          cin.end(Buffer.from(ct));
          const pbuf = new PassThrough();
          await decryptStreamTriple(s0, s1, s2, s3, s4, s5, s6, cin, pbuf);
          pbuf.end();
          const recovered = await drain(pbuf);
          assert.ok(bytesEqual(recovered, plaintext), `nonce=${n}`);
        } finally {
          disposeAll(seeds);
        }
      } finally {
        setNonceBits(orig);
      }
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Stream error paths.
  // ────────────────────────────────────────────────────────────────

  test('write after close raises', () => {
    const seeds = makeSeeds('blake3', 3);
    try {
      const [s0, s1, s2] = seeds as [Seed, Seed, Seed];
      const cbuf = new PassThrough();
      const enc = new StreamEncryptor(s0, s1, s2, cbuf, SMALL_CHUNK);
      enc.write(new TextEncoder().encode('hello'));
      enc.close();
      assert.throws(
        () => enc.write(new TextEncoder().encode('world')),
        (err: unknown) =>
          err instanceof ITBError && err.code === Status.EasyClosed,
      );
    } finally {
      disposeAll(seeds);
    }
  });

  test('partial chunk at close raises', async () => {
    const seeds = makeSeeds('blake3', 3);
    try {
      const [s0, s1, s2] = seeds as [Seed, Seed, Seed];
      const cbuf = new PassThrough();
      {
        const enc = new StreamEncryptor(s0, s1, s2, cbuf, SMALL_CHUNK);
        enc.write(new Uint8Array(100).fill(0x78));
        enc.close();
      }
      cbuf.end();
      const ct = await drain(cbuf);

      const pbuf = new PassThrough();
      const dec = new StreamDecryptor(s0, s1, s2, pbuf);
      // Feed only the first 30 bytes — header complete (≥20) but body
      // truncated. close() must raise on the trailing incomplete chunk.
      dec.feed(ct.subarray(0, Math.min(30, ct.length)));
      assert.throws(
        () => dec.close(),
        (err: unknown) =>
          err instanceof ITBError && err.code === Status.BadInput,
      );
    } finally {
      disposeAll(seeds);
    }
  });

});
