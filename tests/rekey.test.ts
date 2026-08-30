// Init → Rekey → Open receiver with the rotated blob → round trip.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { Opts, Pipeline } from '../src/index.js';

test('rekey round trip', () => {
  const opts = new Opts();
  const sender = Pipeline.init('singlemsg-triple-mac-v1', opts);
  const blobBefore = Buffer.from(sender.blob);

  const perm = Buffer.alloc(32, 0x11);
  const wrap = Buffer.alloc(32, 0x22);
  sender.rekey(perm, wrap);
  assert.notDeepEqual(sender.blob, blobBefore, 'rekey must refresh the blob');

  const receiver = Pipeline.open('singlemsg-triple-mac-v1', sender.blob, opts);
  const plain = Buffer.from('post-rekey payload');
  const wire = sender.encryptMessage(plain);
  assert.deepEqual(receiver.decryptMessage(wire), plain);

  sender.free();
  receiver.free();
});
