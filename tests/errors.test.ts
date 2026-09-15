// Error-mapping surface: opaque-string relay, unknown profile, closed
// Pipeline, profile registration from a JSON record (with an 8-entry
// `hashes` constellation), duplicate registration.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { ItbError, Opts, Pipeline, Status, inspect, lookup, profiles, register } from '../src/index.js';

function statusOf(fn: () => unknown): number {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof ItbError, `expected ItbError, got ${e}`);
    return e.status;
  }
  assert.fail('expected an ItbError to be thrown');
}

test('unknown profile is UnknownProfile with diagnostic', () => {
  try {
    Pipeline.init('no-such-profile');
    assert.fail('init must throw');
  } catch (e) {
    assert.ok(e instanceof ItbError);
    assert.equal(e.status, Status.UnknownProfile);
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

test('register mixed then duplicate', () => {
  // 8-entry width-256 hashes constellation, layers off.
  const profile = {
    mode: 'singlemsg-nomac',
    width: 256,
    hashes: [
      'blake3', 'blake2s', 'areion256', 'blake2b256',
      'chacha20', 'blake3', 'blake2s', 'areion256',
    ],
    keybits: 1024,
    parallax: false,
    wrapper: false,
  };
  register('nodejs-binding-test-mixed', profile);

  // The registered profile round-trips and is visible in the
  // catalogue.
  assert.ok(profiles().includes('nodejs-binding-test-mixed'));
  assert.deepEqual(lookup('nodejs-binding-test-mixed').hashes, profile.hashes);
  const sender = Pipeline.init('nodejs-binding-test-mixed');
  const receiver = Pipeline.load(sender.save());
  const wire = sender.encryptMessage(Buffer.from('custom profile'));
  assert.deepEqual(receiver.decryptMessage(wire), Buffer.from('custom profile'));
  sender.free();
  receiver.free();

  // Duplicate name is a distinct status.
  assert.equal(
    statusOf(() => register('nodejs-binding-test-mixed', profile)),
    Status.ProfileExists,
  );

  // Strict record decode on the Go side: an unknown key is rejected
  // there, not by the binding.
  assert.equal(
    statusOf(() => register('nodejs-binding-test-badkey', '{"mode":"singlemsg-nomac","bogus":1}')),
    Status.BadInput,
  );
});

test('opaque primitive name relay', () => {
  // An unknown inner-hash name is relayed to Go and rejected there —
  // the binding performs no name validation of its own.
  const opts = new Opts().withInnerHash('no-such-hash');
  const status = statusOf(() => Pipeline.init('singlemsg-triple-mac-v1', opts));
  assert.notEqual(status, Status.Ok);
});

test('per-call innerHashes override round-trips', () => {
  // The single-primitive width-512 base profile takes an 8-slot
  // per-call MixedHashes override (Go-side Opts.MixedHashes, wired
  // through the innerHashes= opts key). The override lands in the
  // blob's profile record, so the receiver loads with no opts.
  const mix = [
    'areion512', 'blake2b512', 'areion512', 'blake2b512',
    'areion512', 'blake2b512', 'areion512', 'blake2b512',
  ];
  const senderOpts = new Opts().withInnerHashes(mix);
  const sender = Pipeline.init('singlemsg-triple-mac-v1', senderOpts);
  assert.deepEqual(inspect(sender.save()).hashes, mix);
  const receiver = Pipeline.load(sender.save());
  const plain = Buffer.from('per-call inner-hashes override round-trip payload');
  const wire = sender.encryptMessage(plain);
  assert.deepEqual(receiver.decryptMessage(wire), plain);
  sender.free();
  receiver.free();
});
