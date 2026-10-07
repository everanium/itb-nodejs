// Runtime surface: the process-wide Go knobs (heap limit, GC
// percentage, GOMAXPROCS, heap profile, pool counters) and the shipped
// inner-hash registry enumeration.

import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  ItbError,
  Opts,
  Pipeline,
  Status,
  drbgAutoTier,
  hashNames,
  poolStats,
  poolStatsLen,
  setGCPercent,
  setGOMAXPROCS,
  setMemoryLimit,
  writeHeapProfile,
} from '../src/index.js';

test('setGOMAXPROCS queries then restores', () => {
  // A non-positive argument queries without changing; the setter
  // returns the value that was in force before it.
  const before = setGOMAXPROCS(0);
  assert.ok(before > 0);
  assert.equal(setGOMAXPROCS(2), before);
  assert.equal(setGOMAXPROCS(0), 2);
  setGOMAXPROCS(before);
  assert.equal(setGOMAXPROCS(0), before);
});

test('writeHeapProfile writes a readable profile', () => {
  const dir = mkdtempSync(join(tmpdir(), 'itb3-heapprof-'));
  const path = join(dir, 'heap.prof');
  try {
    writeHeapProfile(path);
    assert.ok(statSync(path).size > 0);
    // pprof profiles are gzip-wrapped protobuf.
    assert.deepEqual(readFileSync(path).subarray(0, 2), Buffer.from([0x1f, 0x8b]));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('writeHeapProfile reports the os diagnostic', () => {
  assert.throws(
    () => writeHeapProfile('/no-such-directory-itb3-test/heap.prof'),
    (e: unknown) => {
      assert.ok(e instanceof ItbError);
      assert.equal(e.status, Status.BadInput);
      assert.match(e.message, /heap\.prof/);
      return true;
    },
  );
});

test('poolStats length matches the declared layout', () => {
  const length = poolStatsLen();
  assert.ok(length > 0);
  const stats = poolStats();
  assert.equal(stats.length, length);
  // Slot 0 carries the tier count T; the vector is 1 + 5*T + 8.
  const tiers = Number(stats[0]);
  assert.ok(tiers > 0);
  assert.equal(length, 1 + 5 * tiers + 8);
});

test('poolStats counters are monotonic across work', () => {
  const before = poolStats();
  const pipe = Pipeline.init('singlemsg-triple-mac-v1', new Opts());
  pipe.decryptMessage(pipe.encryptMessage(Buffer.alloc(4096, 0x78)));
  pipe.free();
  const after = poolStats();
  assert.equal(after.length, before.length);
  let sumBefore = 0n;
  let sumAfter = 0n;
  for (let i = 1; i < after.length; i++) {
    assert.ok(after[i]! >= before[i]!);
    sumBefore += before[i]!;
    sumAfter += after[i]!;
  }
  assert.ok(sumAfter > sumBefore);
});

test('memory limit and GC percentage query without changing', () => {
  const limit = setMemoryLimit(-1);
  assert.equal(setMemoryLimit(-1), limit);
  const pct = setGCPercent(-1);
  assert.equal(setGCPercent(-1), pct);
});

test('hashNames enumerates the shipped registry', () => {
  const names = hashNames();
  assert.ok(names.length > 1);
  assert.equal(new Set(names).size, names.length);
  for (const name of names) {
    assert.equal(typeof name, 'string');
    assert.ok(name.length > 0);
  }
  // The enumeration is what a caller validates a primitive name
  // against, so a shipped name resolves and a typo does not.
  assert.ok(names.includes('areion512'));
  assert.ok(!names.includes('areion512-nope'));
});

test('every enumerated name constructs a Pipeline', () => {
  const probe = Buffer.from('registry probe');
  for (const name of hashNames()) {
    const opts = new Opts().withInnerHash(name).withParallax(false);
    const pipe = Pipeline.init('singlemsg-triple-nomac-v1', opts);
    assert.deepEqual(pipe.decryptMessage(pipe.encryptMessage(probe)), probe);
    pipe.free();
  }
});

test('drbgAutoTier names one of the two fill ciphers', () => {
  // Resolved per host; the value is one of the two fill ciphers.
  assert.ok(['aes-256-ctr', 'chacha20'].includes(drbgAutoTier()));
});
