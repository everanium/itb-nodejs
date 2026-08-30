// Round trip through the stream pumps on a Streaming AEAD profile.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { Opts, Pipeline } from '../src/index.js';

/** Slices `whole` into `step`-byte chunks for the pump source side. */
function* chunked(whole: Buffer, step: number): Generator<Buffer> {
  for (let off = 0; off < whole.length; off += step) {
    yield whole.subarray(off, Math.min(off + step, whole.length));
  }
}

test('pump round trip 1 MiB', () => {
  const opts = new Opts();
  const sender = Pipeline.init('streaming-aead-triple-mac-v1', opts);
  const receiver = Pipeline.open('streaming-aead-triple-mac-v1', sender.blob, opts);

  const plain = Buffer.alloc(1 << 20);
  for (let i = 0; i < plain.length; i++) {
    plain[i] = i % 251;
  }

  const wireParts: Buffer[] = [];
  sender.encryptStreamPump(chunked(plain, 64 * 1024), (w) => wireParts.push(w));
  const wire = Buffer.concat(wireParts);
  assert.ok(wire.length > 0);

  const backParts: Buffer[] = [];
  receiver.decryptStreamPump(chunked(wire, 64 * 1024), (p) => backParts.push(p));
  assert.deepEqual(Buffer.concat(backParts), plain);

  sender.free();
  receiver.free();
});

test('pump matches one-shot', () => {
  const opts = new Opts();
  const sender = Pipeline.init('streaming-aead-triple-mac-v1', opts);
  const receiver = Pipeline.open('streaming-aead-triple-mac-v1', sender.blob, opts);

  const plain = Buffer.alloc(65_536);
  for (let i = 0; i < plain.length; i++) {
    plain[i] = i % 199;
  }
  const wire = sender.encryptStreamOneShot(plain);

  const backParts: Buffer[] = [];
  receiver.decryptStreamPump(chunked(wire, 4096), (p) => backParts.push(p));
  assert.deepEqual(Buffer.concat(backParts), plain);

  const back2 = receiver.decryptStreamOneShot(wire);
  assert.deepEqual(back2, plain);

  sender.free();
  receiver.free();
});
