// Tests for the authenticated streaming methods on the high-level
// Encryptor (encryptStreamAuth / decryptStreamAuth).
//
// Drives the Easy Mode Streaming AEAD ABI export — one Encryptor
// instance covers the seed material, MAC closure, and per-instance
// configuration. Coverage parallels streams_auth.test.ts at the
// per-encryptor entry point.

import { test, describe } from 'node:test';
import { strict as assert } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { PassThrough } from 'node:stream';

import {
  Encryptor,
  ITBError,
  ITBStreamAfterFinalError,
  ITBStreamTruncatedError,
  parseChunkLen,
  Status,
  STREAM_ID_LEN,
} from '../../src/index.js';

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

async function drain(stream: PassThrough): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(chunk as Buffer);
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

function splitChunks(ct: Uint8Array, headerSize: number): { prefix: Uint8Array; chunks: Uint8Array[] } {
  const prefix = ct.subarray(0, STREAM_ID_LEN);
  const body = ct.subarray(STREAM_ID_LEN);
  const chunks: Uint8Array[] = [];
  let off = 0;
  while (off < body.length) {
    const cl = parseChunkLen(body.subarray(off, off + headerSize));
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

describe('test_easy_streams_auth', () => {
  test('default constructor roundtrip', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 3 + 17);
    const enc = new Encryptor('blake3', 1024, 'hmac-blake3');
    try {
      const cbuf = new PassThrough();
      const fin = new PassThrough();
      fin.end(plaintext);
      await enc.encryptStreamAuth(fin, cbuf, SMALL_CHUNK);
      cbuf.end();
      const ct = await drain(cbuf);
      assert.ok(ct.length > STREAM_ID_LEN);

      const pbuf = new PassThrough();
      const cin = new PassThrough();
      cin.end(ct);
      await enc.decryptStreamAuth(cin, pbuf);
      pbuf.end();
      assert.deepEqual(await drain(pbuf), plaintext);
    } finally {
      enc.close();
    }
  });

  test('all mac hash combinations single', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 2 + 9);
    for (const macName of CANONICAL_MACS) {
      for (const [hashName] of HASH_BY_WIDTH) {
        const enc = new Encryptor(hashName, 1024, macName);
        try {
          const cbuf = new PassThrough();
          const fin = new PassThrough();
          fin.end(plaintext);
          await enc.encryptStreamAuth(fin, cbuf, SMALL_CHUNK);
          cbuf.end();
          const ct = await drain(cbuf);

          const pbuf = new PassThrough();
          const cin = new PassThrough();
          cin.end(ct);
          await enc.decryptStreamAuth(cin, pbuf);
          pbuf.end();
          assert.deepEqual(await drain(pbuf), plaintext);
        } finally {
          enc.close();
        }
      }
    }
  });

  test('all mac hash combinations triple', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK + 100);
    for (const macName of CANONICAL_MACS) {
      for (const [hashName] of HASH_BY_WIDTH) {
        const enc = new Encryptor(hashName, 1024, macName, 3);
        try {
          const cbuf = new PassThrough();
          const fin = new PassThrough();
          fin.end(plaintext);
          await enc.encryptStreamAuth(fin, cbuf, SMALL_CHUNK);
          cbuf.end();
          const ct = await drain(cbuf);

          const pbuf = new PassThrough();
          const cin = new PassThrough();
          cin.end(ct);
          await enc.decryptStreamAuth(cin, pbuf);
          pbuf.end();
          assert.deepEqual(await drain(pbuf), plaintext);
        } finally {
          enc.close();
        }
      }
    }
  });

  test('empty stream', async () => {
    const enc = new Encryptor('blake3', 1024, 'hmac-blake3');
    try {
      const cbuf = new PassThrough();
      const fin = new PassThrough();
      fin.end(new Uint8Array(0));
      await enc.encryptStreamAuth(fin, cbuf, SMALL_CHUNK);
      cbuf.end();
      const ct = await drain(cbuf);
      assert.ok(ct.length > STREAM_ID_LEN);

      const pbuf = new PassThrough();
      const cin = new PassThrough();
      cin.end(ct);
      await enc.decryptStreamAuth(cin, pbuf);
      pbuf.end();
      const pt = await drain(pbuf);
      assert.equal(pt.length, 0);
    } finally {
      enc.close();
    }
  });

  test('single chunk stream', async () => {
    const plaintext = new Uint8Array(100).fill(0x78);
    const enc = new Encryptor('blake3', 1024, 'hmac-blake3');
    try {
      const cbuf = new PassThrough();
      const fin = new PassThrough();
      fin.end(plaintext);
      await enc.encryptStreamAuth(fin, cbuf, SMALL_CHUNK);
      cbuf.end();
      const ct = await drain(cbuf);

      const pbuf = new PassThrough();
      const cin = new PassThrough();
      cin.end(ct);
      await enc.decryptStreamAuth(cin, pbuf);
      pbuf.end();
      assert.deepEqual(await drain(pbuf), plaintext);
    } finally {
      enc.close();
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Detection paths.
  // ────────────────────────────────────────────────────────────────

  test('truncate tail detected', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 2 + SMALL_CHUNK / 2);
    const enc = new Encryptor('blake3', 1024, 'hmac-blake3');
    try {
      const cbuf = new PassThrough();
      const fin = new PassThrough();
      fin.end(plaintext);
      await enc.encryptStreamAuth(fin, cbuf, SMALL_CHUNK);
      cbuf.end();
      const ct = await drain(cbuf);
      const { prefix, chunks } = splitChunks(ct, enc.headerSize);
      const truncated = concatU8([prefix, ...chunks.slice(0, -1)]);

      const pbuf = new PassThrough();
      const cin = new PassThrough();
      cin.end(truncated);
      await assert.rejects(enc.decryptStreamAuth(cin, pbuf), (err: unknown) => {
        return err instanceof ITBStreamTruncatedError &&
          (err as ITBError).code === Status.StreamTruncated;
      });
    } finally {
      enc.close();
    }
  });

  test('after final detected', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK + 100);
    const enc = new Encryptor('blake3', 1024, 'hmac-blake3');
    try {
      const cbuf = new PassThrough();
      const fin = new PassThrough();
      fin.end(plaintext);
      await enc.encryptStreamAuth(fin, cbuf, SMALL_CHUNK);
      cbuf.end();
      const ct = await drain(cbuf);
      const { prefix, chunks } = splitChunks(ct, enc.headerSize);
      const afterFinal = concatU8([prefix, ...chunks, chunks[chunks.length - 1]!]);

      const pbuf = new PassThrough();
      const cin = new PassThrough();
      cin.end(afterFinal);
      await assert.rejects(enc.decryptStreamAuth(cin, pbuf), (err: unknown) => {
        return err instanceof ITBStreamAfterFinalError &&
          (err as ITBError).code === Status.StreamAfterFinal;
      });
    } finally {
      enc.close();
    }
  });

  test('chunk reorder detected', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK * 2 + SMALL_CHUNK / 2);
    const enc = new Encryptor('blake3', 1024, 'hmac-blake3');
    try {
      const cbuf = new PassThrough();
      const fin = new PassThrough();
      fin.end(plaintext);
      await enc.encryptStreamAuth(fin, cbuf, SMALL_CHUNK);
      cbuf.end();
      const ct = await drain(cbuf);
      const { prefix, chunks } = splitChunks(ct, enc.headerSize);
      assert.ok(chunks.length >= 3);
      const tampered = concatU8([prefix, chunks[1]!, chunks[0]!, ...chunks.slice(2)]);

      const pbuf = new PassThrough();
      const cin = new PassThrough();
      cin.end(tampered);
      await assert.rejects(enc.decryptStreamAuth(cin, pbuf), (err: unknown) => {
        return err instanceof ITBError && (err as ITBError).code === Status.MacFailure;
      });
    } finally {
      enc.close();
    }
  });

  test('stream prefix tamper detected', async () => {
    const plaintext = tokenBytes(SMALL_CHUNK + 200);
    const enc = new Encryptor('blake3', 1024, 'hmac-blake3');
    try {
      const cbuf = new PassThrough();
      const fin = new PassThrough();
      fin.end(plaintext);
      await enc.encryptStreamAuth(fin, cbuf, SMALL_CHUNK);
      cbuf.end();
      const ct = await drain(cbuf);
      ct[0]! ^= 0x80;

      const pbuf = new PassThrough();
      const cin = new PassThrough();
      cin.end(ct);
      await assert.rejects(enc.decryptStreamAuth(cin, pbuf), (err: unknown) => {
        return err instanceof ITBError && (err as ITBError).code === Status.MacFailure;
      });
    } finally {
      enc.close();
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Closed-state preflight.
  // ────────────────────────────────────────────────────────────────

  test('call after close raises', async () => {
    const enc = new Encryptor('blake3', 1024, 'hmac-blake3');
    const cbuf = new PassThrough();
    const fin = new PassThrough();
    fin.end(new TextEncoder().encode('hello'));
    await enc.encryptStreamAuth(fin, cbuf, SMALL_CHUNK);
    cbuf.end();
    void drain(cbuf);
    enc.close();
    await assert.rejects(enc.encryptStreamAuth(
      (() => { const p = new PassThrough(); p.end(new TextEncoder().encode('world')); return p; })(),
      new PassThrough(), SMALL_CHUNK),
      (err: unknown) => {
        return err instanceof ITBError && (err as ITBError).code === Status.EasyClosed;
      });
  });

  test('call after free raises', async () => {
    const enc = new Encryptor('blake3', 1024, 'hmac-blake3');
    const cbuf = new PassThrough();
    const fin = new PassThrough();
    fin.end(new TextEncoder().encode('hello'));
    await enc.encryptStreamAuth(fin, cbuf, SMALL_CHUNK);
    cbuf.end();
    void drain(cbuf);
    enc.free();
    await assert.rejects(enc.decryptStreamAuth(new PassThrough(), new PassThrough()),
      (err: unknown) => {
        return err instanceof ITBError && (err as ITBError).code === Status.EasyClosed;
      });
  });

  test('bad chunk size rejected', async () => {
    const enc = new Encryptor('blake3', 1024, 'hmac-blake3');
    try {
      await assert.rejects(enc.encryptStreamAuth(
        (() => { const p = new PassThrough(); p.end(new Uint8Array(1)); return p; })(),
        new PassThrough(), -1),
        (err: unknown) => {
          return err instanceof ITBError && (err as ITBError).code === Status.BadInput;
        });
    } finally {
      enc.close();
    }
  });

  // ────────────────────────────────────────────────────────────────
  // Subsequent calls — verify the encryptor is reusable.
  // ────────────────────────────────────────────────────────────────

  test('subsequent calls after stream', async () => {
    const enc = new Encryptor('blake3', 1024, 'hmac-blake3');
    try {
      // First stream
      const cbuf1 = new PassThrough();
      const fin1 = new PassThrough();
      fin1.end(new TextEncoder().encode('first stream'));
      await enc.encryptStreamAuth(fin1, cbuf1, SMALL_CHUNK);
      cbuf1.end();
      void drain(cbuf1);

      // Second stream — same encryptor, fresh streamId
      const cbuf2 = new PassThrough();
      const fin2 = new PassThrough();
      fin2.end(new TextEncoder().encode('second stream'));
      await enc.encryptStreamAuth(fin2, cbuf2, SMALL_CHUNK);
      cbuf2.end();
      const ct = await drain(cbuf2);

      const pbuf = new PassThrough();
      const cin = new PassThrough();
      cin.end(ct);
      await enc.decryptStreamAuth(cin, pbuf);
      pbuf.end();
      assert.deepEqual(await drain(pbuf),
        new TextEncoder().encode('second stream'));
    } finally {
      enc.close();
    }
  });
});
