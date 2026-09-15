// Init → save → Load → encryptMessage → decryptMessage round trip.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { Opts, Pipeline } from '../src/index.js';

test('smoke round trip', () => {
  const opts = new Opts();
  const sender = Pipeline.init('singlemsg-triple-mac-v1', opts);
  const blob = sender.save();
  assert.ok(blob.length > 0);

  const receiver = Pipeline.load(blob);

  const plain = Buffer.from('smoke round-trip payload');
  const wire = sender.encryptMessage(plain);
  assert.notDeepEqual(wire, plain);

  const back = receiver.decryptMessage(wire);
  assert.deepEqual(back, plain);

  sender.free();
  receiver.free();
});
