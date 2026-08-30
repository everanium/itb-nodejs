// Error-mapping surface: opaque-string relay, closed Pipeline,
// duplicate profile registration (with an 8-entry `innerHashes`
// constellation).

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { ItbError, Opts, Pipeline, Status, registerProfile } from '../src/index.js';

function statusOf(fn: () => unknown): number {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof ItbError, `expected ItbError, got ${e}`);
    return e.status;
  }
  assert.fail('expected an ItbError to be thrown');
}

test('unknown profile is BadInput with diagnostic', () => {
  try {
    Pipeline.init('no-such-profile');
    assert.fail('init must throw');
  } catch (e) {
    assert.ok(e instanceof ItbError);
    assert.equal(e.status, Status.BadInput);
    assert.ok(e.message.length > 0);
  }
});

test('unknown opts key is BadInput', () => {
  // Typoed key (lowercase s) — Go rejects unknown keys.
  const opts = new Opts().withRaw('chunksize', '4096');
  assert.equal(
    statusOf(() => Pipeline.init('singlemsg-triple-mac-v1', opts)),
    Status.BadInput,
  );
});

test('closed pipeline reports TripleClosed', () => {
  const p = Pipeline.init('singlemsg-triple-mac-v1');
  p.close();
  p.close(); // idempotent
  assert.equal(
    statusOf(() => p.encryptMessage(Buffer.from('payload'))),
    Status.TripleClosed,
  );
  p.free();
});

test('register profile mixed then duplicate', () => {
  // 8-entry width-256 innerHashes constellation, layers off.
  const opts = new Opts()
    .withRaw('mode', 'singlemsg-nomac')
    .withRaw('width', '256')
    .withRaw(
      'innerHashes',
      'blake3,blake2s,areion256,blake2b256,chacha20,blake3,blake2s,areion256',
    )
    .withRaw('keyBits', '1024')
    .withRaw('parallaxOn', 'false')
    .withRaw('wrapperOn', 'false');
  registerProfile('nodejs-binding-test-mixed', opts);

  // The registered profile round-trips.
  const sender = Pipeline.init('nodejs-binding-test-mixed');
  const receiver = Pipeline.open('nodejs-binding-test-mixed', sender.blob);
  const wire = sender.encryptMessage(Buffer.from('custom profile'));
  assert.deepEqual(receiver.decryptMessage(wire), Buffer.from('custom profile'));
  sender.free();
  receiver.free();

  // Duplicate name is a distinct status.
  assert.equal(
    statusOf(() => registerProfile('nodejs-binding-test-mixed', opts)),
    Status.ProfileExists,
  );
});

test('opaque primitive name relay', () => {
  // An unknown inner-hash name is relayed to Go and rejected there —
  // the binding performs no name validation of its own.
  const opts = new Opts().withInnerHash('no-such-hash');
  const status = statusOf(() => Pipeline.init('singlemsg-triple-mac-v1', opts));
  assert.notEqual(status, Status.Ok);
});
