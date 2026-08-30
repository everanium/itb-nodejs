// A decrypt session fed a tampered wire fails with a sticky MAC
// failure. Uses a position probe rather than a single bit flip
// because the over-sized container carries CSPRNG residue in the
// non-payload area — a flip that lands inside the residue is
// architecturally inert (residue is not payload) and the session
// finishes clean. Probing 32 evenly-spaced positions makes the
// all-residue probability negligible; the first position that
// surfaces an error must give Status.MacFailure and remain sticky
// on subsequent reads.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import { ItbError, Opts, Pipeline, Status } from '../src/index.js';

test('tampered wire sticky failure', () => {
  const opts = new Opts();
  const sender = Pipeline.init('streaming-aead-triple-mac-v1', opts);
  const receiver = Pipeline.open('streaming-aead-triple-mac-v1', sender.blob, opts);

  const plain = Buffer.alloc(65_536);
  for (let i = 0; i < plain.length; i++) {
    plain[i] = i % 227;
  }
  const baseWire = sender.encryptStreamOneShot(plain);
  assert.ok(baseWire.length > 128, `wire too short for a distributed probe: ${baseWire.length}`);

  const PROBES = 32;
  // Evenly spread through the wire body; skip the first / last
  // 16 bytes so a hit against the outer envelope framing does not
  // muddy the observation.
  const bodyStart = 16;
  const bodyEnd = baseWire.length - 16;
  const stride = Math.floor((bodyEnd - bodyStart) / PROBES);

  for (let probe = 0; probe < PROBES; probe++) {
    const idx = bodyStart + probe * stride;
    const wire = Buffer.from(baseWire);
    wire[idx]! ^= 0x01;

    const sess = receiver.decryptStream();
    // Ignore Write / End status — the failure may surface on either
    // side or only on the drain that follows.
    try {
      sess.write(wire);
      sess.end();
    } catch {
      // Failure surfaced early; the drain below re-observes it.
    }

    const buf = new Uint8Array(4096);
    let firstErr: ItbError | undefined;
    let finishedClean = false;
    for (;;) {
      try {
        const { finished } = sess.read(buf);
        if (finished) {
          finishedClean = true;
          break;
        }
      } catch (e) {
        assert.ok(e instanceof ItbError);
        firstErr = e;
        break;
      }
    }
    if (finishedClean) {
      // Residue hit at this offset — try the next probe.
      sess.free();
      continue;
    }
    assert.ok(firstErr, 'read loop exited without error nor finish');
    assert.equal(
      firstErr.status,
      Status.MacFailure,
      `expected MAC failure on tampered wire at probe ${probe} (byte ${idx}), ` +
        `got status ${firstErr.status}`,
    );

    // Sticky: a subsequent read reports the same status.
    let again: ItbError | undefined;
    try {
      sess.read(buf);
    } catch (e) {
      assert.ok(e instanceof ItbError);
      again = e;
    }
    assert.ok(again, 'second read must fail too');
    assert.equal(again.status, firstErr.status);

    sess.free();
    sender.free();
    receiver.free();
    return;
  }
  assert.fail(
    `no probe among ${PROBES} evenly-spaced positions surfaced a MAC failure — ` +
      'either the probe pattern is degenerate or authentication is not ' +
      'covering the wire body it should',
  );
});
