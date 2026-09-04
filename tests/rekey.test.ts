// Init → Rekey → Load receiver with the rotated blob → round trip.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { Opts, Pipeline } from '../src/index.js';

test('rekey round trip', () => {
  const opts = new Opts();
  const sender = Pipeline.init('singlemsg-triple-mac-v1', opts);
  const blobBefore = sender.save();

  const perm = Buffer.alloc(32, 0x11);
  const wrap = Buffer.alloc(32, 0x22);
  const rotated = sender.rekey(perm, wrap);
  assert.notDeepEqual(rotated, blobBefore, 'rekey must refresh the blob');
  assert.deepEqual(sender.save(), rotated, 'save must observe the rekey');

  const receiver = Pipeline.load(rotated);
  const plain = Buffer.from('post-rekey payload');
  const wire = sender.encryptMessage(plain);
  assert.deepEqual(receiver.decryptMessage(wire), plain);

  sender.free();
  receiver.free();
});
