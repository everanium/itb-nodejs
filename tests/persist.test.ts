// Session persistence: save / load in memory, saveF / loadF through a
// temp file (mode 0600), inspect, lookup / profiles, maxWorkers.

import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { ItbError, Opts, Pipeline, Status, inspect, lookup, profiles } from '../src/index.js';

const PROFILE = 'singlemsg-triple-mac-v1';

function statusOf(fn: () => unknown): number {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof ItbError, `expected ItbError, got ${e}`);
    return e.status;
  }
  assert.fail('expected an ItbError to be thrown');
}

test('save / load round trip', () => {
  const sender = Pipeline.init(PROFILE);
  const blob = sender.save();
  assert.ok(blob.length > 0);
  assert.deepEqual(sender.save(), blob, 'save is stable between calls');
  const receiver = Pipeline.load(blob);
  assert.deepEqual(receiver.save(), blob, 'load retains the blob');
  const wire = sender.encryptMessage(Buffer.from('in-memory persist'));
  assert.deepEqual(receiver.decryptMessage(wire), Buffer.from('in-memory persist'));
  sender.free();
  receiver.free();
});

test('saveF / loadF round trip', () => {
  const dir = mkdtempSync(join(tmpdir(), 'itb-nodejs-persist-'));
  try {
    const path = join(dir, 'session.blob');
    const sender = Pipeline.init(PROFILE);
    sender.saveF(path);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    const receiver = Pipeline.loadF(path);
    assert.deepEqual(receiver.save(), sender.save());
    const wire = sender.encryptMessage(Buffer.from('file persist'));
    assert.deepEqual(receiver.decryptMessage(wire), Buffer.from('file persist'));
    sender.free();
    receiver.free();
    assert.equal(statusOf(() => Pipeline.loadF(join(dir, 'absent.blob'))), Status.BadInput);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('load with master override', () => {
  const sender = Pipeline.init(PROFILE);
  const perm = Buffer.alloc(32, 0x31);
  const wrap = Buffer.alloc(32, 0x32);
  const rotated = sender.rekey(perm, wrap);
  const receiver = Pipeline.load(sender.save(), { perm, wrap });
  assert.deepEqual(receiver.save(), rotated);
  const wire = sender.encryptMessage(Buffer.from('master override'));
  assert.deepEqual(receiver.decryptMessage(wire), Buffer.from('master override'));
  sender.free();
  receiver.free();
});

test('inspect matches lookup', () => {
  const pipe = Pipeline.init(PROFILE);
  const record = inspect(pipe.save());
  pipe.free();
  assert.equal(record.name, PROFILE);
  assert.equal(record.mode, 'singlemsg-mac');
  assert.ok(record.keybits > 0);
  assert.deepEqual(record, lookup(PROFILE));
  assert.equal(statusOf(() => inspect(Buffer.from('not a blob'))), Status.BadInput);
  assert.equal(statusOf(() => lookup('no-such-profile')), Status.UnknownProfile);
});

test('profiles is sorted and resolves', () => {
  const names = profiles();
  assert.ok(names.includes(PROFILE));
  assert.deepEqual(names, [...names].sort());
  for (const name of names) {
    assert.equal(lookup(name).name, name);
  }
});

test('maxWorkers', () => {
  const pipe = Pipeline.init(PROFILE);
  pipe.maxWorkers(2);
  pipe.maxWorkers(-1); // clamped to auto, never rejected
  pipe.maxWorkers(10_000); // clamped to 256
  const wire = pipe.encryptMessage(Buffer.from('after cap change'));
  assert.deepEqual(pipe.decryptMessage(wire), Buffer.from('after cap change'));
  pipe.close();
  assert.equal(statusOf(() => pipe.maxWorkers(2)), Status.TripleClosed);
  pipe.free();

  // A negative init-time cap is clamped as well.
  const neg = Pipeline.init(PROFILE, new Opts().withMaxWorkers(-1));
  assert.deepEqual(neg.decryptMessage(neg.encryptMessage(Buffer.from('negative cap'))), Buffer.from('negative cap'));
  neg.free();
});
