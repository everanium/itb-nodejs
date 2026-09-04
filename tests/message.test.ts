// Single Message round trip across every shipped cipher profile at
// small (4 KiB) and medium (256 KiB) payloads. The blob-only profile
// has no cipher surface and is exercised in errors.test.ts instead.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { Opts, Pipeline } from '../src/index.js';

/** Deterministic non-trivial payload (xorshift fill). */
function payload(n: number, seed: number): Buffer {
  let x = BigInt(seed) | 1n;
  const mask = (1n << 64n) - 1n;
  const out = Buffer.alloc(n);
  for (let i = 0; i < n; i++) {
    x = (x ^ (x << 13n)) & mask;
    x = x ^ (x >> 7n);
    x = (x ^ (x << 17n)) & mask;
    out[i] = Number(x & 0xffn);
  }
  return out;
}

const PROFILES = [
  'streaming-aead-triple-mac-v1',
  'streaming-noaead-triple-v1',
  'singlemsg-triple-mac-v1',
  'singlemsg-triple-nomac-v1',
  'streaming-aead-triple-mac-mixed-v1',
  'streaming-noaead-triple-mixed-v1',
  'singlemsg-triple-mac-mixed-v1',
  'singlemsg-triple-nomac-mixed-v1',
];

test('message round trip every profile', () => {
  const opts = new Opts();
  for (const profile of PROFILES) {
    const sender = Pipeline.init(profile, opts);
    const receiver = Pipeline.load(sender.save());
    for (const size of [4 * 1024, 256 * 1024]) {
      const plain = payload(size, size);
      const wire = sender.encryptMessage(plain);
      const back = receiver.decryptMessage(wire);
      assert.deepEqual(back, plain, `${profile} @${size}`);
    }
    sender.free();
    receiver.free();
  }
});
