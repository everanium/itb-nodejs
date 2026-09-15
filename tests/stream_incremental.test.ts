// Explicit write / end / read round trip with pathological batch
// sizes (17-byte feed, 23-byte drain) across multiple chunks.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { DecryptStream, EncryptStream, Opts, Pipeline } from '../src/index.js';

function throughSession(sess: EncryptStream | DecryptStream, input: Buffer): Buffer {
  // 17-byte writes, then end + 23-byte drains.
  for (let off = 0; off < input.length; off += 17) {
    sess.write(input.subarray(off, Math.min(off + 17, input.length)));
  }
  sess.end();
  const parts: Buffer[] = [];
  const buf = new Uint8Array(23);
  for (;;) {
    const { n, finished } = sess.read(buf);
    parts.push(Buffer.from(buf.subarray(0, n)));
    if (finished) {
      return Buffer.concat(parts);
    }
  }
}

test('incremental tiny batches', () => {
  // Small chunk size so the 64 KiB payload spans many chunks.
  const opts = new Opts().withChunkSize(4096);
  const sender = Pipeline.init('streaming-aead-triple-mac-v1', opts);
  const receiver = Pipeline.load(sender.save());

  const plain = Buffer.alloc(65_536);
  for (let i = 0; i < plain.length; i++) {
    plain[i] = i % 241;
  }

  const encSess = sender.encryptStream();
  const wire = throughSession(encSess, plain);
  encSess.free();
  assert.ok(wire.length > 0);

  const decSess = receiver.decryptStream();
  const back = throughSession(decSess, wire);
  decSess.free();
  assert.deepEqual(back, plain);

  sender.free();
  receiver.free();
});
