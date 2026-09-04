// Freeing an encrypt session mid-flight cleans up and leaves the
// Pipeline usable.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { Opts, Pipeline } from '../src/index.js';

test('free mid-flight then reuse pipeline', () => {
  const opts = new Opts();
  const sender = Pipeline.init('streaming-aead-triple-mac-v1', opts);

  const sess = sender.encryptStream();
  sess.write(Buffer.alloc(100_000, 0xa5));
  // Freed here without end() — free cancels the session; the test
  // passing (process not hanging) is the assertion.
  sess.free();

  // The Pipeline stays usable after the cancelled session.
  const receiver = Pipeline.load(sender.save());
  const wire = sender.encryptMessage(Buffer.from('after cancel'));
  assert.deepEqual(receiver.decryptMessage(wire), Buffer.from('after cancel'));

  sender.free();
  receiver.free();
});
