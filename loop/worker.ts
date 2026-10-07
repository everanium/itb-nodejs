// The worker: its thread body (its own handles opened from the Init
// blob, one warmup iteration, the warmup gate, the main loop), one
// iteration, the session pump loop the stream shape drives, and the
// round-trip comparison that decides between a worker error and a data
// mismatch.
//
// This unit is also the worker thread's entry point: the launcher
// starts a thread on the compiled form of this file, which is why
// nothing else imports it.

import { isMainThread, parentPort, workerData } from 'node:worker_threads';
import { Pipeline } from '../src/index.js';
import { workerMaintenance } from './ops.js';
import { PAYLOAD_ROTATING, fillPayload, seedWorker } from './payload.js';
import { nowNs } from './size.js';
import {
  PUMP_SLICE,
  SHAPE_BOTH,
  SHAPE_MESSAGE,
  SHAPE_STREAM,
  SHAPE_STREAM_ONE_SHOT,
  WorkerState,
  Shared,
  errRaw,
  hardExit,
  shapeName,
  statusDetail,
  workerFail,
  type WorkerData,
  type WorkerMsg,
  type WorkerReport,
} from './state.js';

/**
 * Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair and
 * ITB drives the chunk loop internally; the C ABI has no reader /
 * writer entry, so the caller drives it: open a session, feed slices of
 * at most 1 MiB, drain whatever the session has produced after every
 * write (a read before end never blocks), end, then drain until the
 * session reports finished (after end, a read on an empty spool blocks
 * until the terminal bytes arrive). The loop is written here rather
 * than delegated to the binding's pump convenience so it stands in the
 * utility, at the same place, in every language.
 */
function pump(pipe: Pipeline, encrypt: boolean, src: Uint8Array): Buffer {
  const session = encrypt ? pipe.encryptStream() : pipe.decryptStream();
  try {
    const parts: Buffer[] = [];
    const slice = Buffer.allocUnsafe(PUMP_SLICE);
    let off = 0;
    while (off < src.length) {
      const end = Math.min(off + PUMP_SLICE, src.length);
      session.write(src.subarray(off, end));
      off = end;
      for (;;) {
        const { n } = session.read(slice);
        if (n === 0) {
          break;
        }
        parts.push(Buffer.from(slice.subarray(0, n)));
      }
    }
    session.end();
    for (;;) {
      const { n, finished } = session.read(slice);
      if (n > 0) {
        parts.push(Buffer.from(slice.subarray(0, n)));
      }
      if (finished) {
        break;
      }
    }
    return Buffer.concat(parts);
  } finally {
    session.free();
  }
}

/**
 * First offset at which a and b differ; the shorter length when one is
 * a prefix of the other.
 */
function firstDifference(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) {
      return i;
    }
  }
  return n;
}

/**
 * Up to 16 bytes of buf from off as lowercase hex, or "-" when buf has
 * no bytes there.
 */
function hexWindow(buf: Uint8Array, off: number): string {
  if (off >= buf.length) {
    return '-';
  }
  return Buffer.from(buf.subarray(off, off + 16)).toString('hex');
}

/** Records a worker error for a failed cipher call. */
function cipherFail(
  w: WorkerState,
  it: number,
  shape: number,
  direction: string,
  e: unknown,
): void {
  workerFail(
    w,
    `g${w.id} iter ${it} shape=${shapeName(shape)}: ${direction}: ${statusDetail(e)}`,
  );
}

/**
 * One iteration. In order: refill the plaintext under rotating mode;
 * pick the surface; encrypt (timed); decrypt (timed); compare the
 * round-trip with the plaintext; bump the counters. A shared-handle
 * binding wraps the whole round-trip in a read lock so handle-mutating
 * maintenance never lands between an encrypt and its matching decrypt;
 * under this binding's independent-handles mode the handles belong to
 * this thread alone, maintenance runs after this returns from the
 * worker loop, and there is nothing to exclude. Returns false after
 * recording the worker error.
 */
function iterate(w: WorkerState, it: number): boolean {
  if (w.payloadMode === PAYLOAD_ROTATING) {
    w.rng = fillPayload(w.plaintext, PAYLOAD_ROTATING, w.seeded, w.rng);
  }

  // Shape dispatch. message is one whole-buffer call on the Single
  // Message Pipeline; stream_one_shot is one whole-buffer call on the
  // streaming Pipeline (the C ABI's ITB_Triple_EncryptStream, which
  // routes to the same one-shot stream entry the Go harness calls
  // by name); stream opens a session on the same streaming Pipeline and
  // drives the chunk loop from here. Under both the three rotate by
  // iteration number so the session path and the whole-buffer path
  // alternate on one handle inside every worker — the cross-path
  // state-reuse hazard this harness exists to catch.
  let shape = w.cfg.shape;
  if (shape === SHAPE_BOTH) {
    shape = [SHAPE_STREAM, SHAPE_MESSAGE, SHAPE_STREAM_ONE_SHOT][it % 3]!;
  }

  const want = w.plaintext;
  let wire: Buffer;
  let got: Buffer;
  if (shape === SHAPE_STREAM) {
    let t0 = nowNs();
    try {
      wire = pump(w.streamPipe!, true, want);
    } catch (e) {
      cipherFail(w, it, shape, 'encrypt', e);
      return false;
    }
    w.nanosEnc += nowNs() - t0;
    t0 = nowNs();
    try {
      got = pump(w.streamPipe!, false, wire);
    } catch (e) {
      cipherFail(w, it, shape, 'decrypt', e);
      return false;
    }
    w.nanosDec += nowNs() - t0;
  } else {
    const pipe = shape === SHAPE_MESSAGE ? w.msgPipe! : w.streamPipe!;
    const enc =
      shape === SHAPE_MESSAGE
        ? (b: Uint8Array) => pipe.encryptMessage(b)
        : (b: Uint8Array) => pipe.encryptStreamOneShot(b);
    const dec =
      shape === SHAPE_MESSAGE
        ? (b: Uint8Array) => pipe.decryptMessage(b)
        : (b: Uint8Array) => pipe.decryptStreamOneShot(b);
    let t0 = nowNs();
    try {
      wire = enc(want);
    } catch (e) {
      cipherFail(w, it, shape, 'encrypt', e);
      return false;
    }
    w.nanosEnc += nowNs() - t0;
    t0 = nowNs();
    try {
      got = dec(wire);
    } catch (e) {
      cipherFail(w, it, shape, 'decrypt', e);
      return false;
    }
    w.nanosDec += nowNs() - t0;
  }

  // Failure model. A cipher call that returns a non-OK status is a
  // worker error: it is recorded, the run is asked to stop, the other
  // workers finish their in-flight iteration, and the error is listed
  // in the summary with the FAIL verdict. A round-trip that returns OK
  // with different bytes is a data mismatch: the process terminates
  // here, without summary or cleanup, because the Pipeline state that
  // produced the wrong bytes is the evidence and nothing that runs
  // afterwards may touch it.
  if (!got.equals(want)) {
    const off = firstDifference(want, got);
    errRaw(
      `loop: DATA MISMATCH g${w.id} iter ${it} shape=${shapeName(shape)}: ` +
        `want ${want.length} bytes, got ${got.length} bytes, ` +
        `first difference at offset ${off}: ` +
        `want ${hexWindow(want, off)} got ${hexWindow(got, off)}\n`,
    );
    w.shared.requestStop();
    hardExit(3);
    // TypeScript-specific. Reached only where libc's own exit entry
    // could not be resolved: a worker thread cannot set the process
    // status, so the launcher is asked to, and this thread stops doing
    // anything that could touch the evidence.
    parentPort?.postMessage({ t: 'fatal', code: 3 } satisfies WorkerMsg);
    for (;;) {
      Atomics.wait(w.shared.cells, 0, w.shared.cells[0]!, 1000);
    }
  }

  w.iters++;
  w.bytesEnc += want.length;
  w.bytesDec += got.length;
  return true;
}

/** Opens this worker's own handles from the blobs the launcher sent. */
function openHandles(w: WorkerState, data: WorkerData): boolean {
  if (data.streamBlob !== null) {
    try {
      w.streamPipe = Pipeline.load(data.streamBlob);
    } catch (e) {
      workerFail(w, `g${w.id} iter 0: Load(${w.streamProfile}): ${statusDetail(e)}`);
      return false;
    }
    w.streamBlob = data.streamBlob;
  }
  if (data.msgBlob !== null) {
    try {
      w.msgPipe = Pipeline.load(data.msgBlob);
    } catch (e) {
      workerFail(w, `g${w.id} iter 0: Load(${w.msgProfile}): ${statusDetail(e)}`);
      return false;
    }
    w.msgBlob = data.msgBlob;
  }
  return true;
}

/**
 * The worker thread body: its own handles, one warmup iteration, the
 * warmup gate, then the main loop until a stop is requested or the
 * fixed per-worker iteration budget (warmup included) is spent. A
 * failing warmup still reports at the gate so the launcher never waits
 * on a worker that has already given up.
 *
 * Concurrency mode. This binding runs independent-handles: a worker
 * thread is a separate V8 isolate holding its own instance of the koffi
 * addon, only structured-cloneable data crosses the boundary, and the
 * binding's public surface has no entry that adopts an existing native
 * handle — so a handle cannot be shared and each worker loads its own
 * from the Init blob the launcher sent. --goroutines is the thread
 * count verbatim, never clamped.
 */
function workerMain(data: WorkerData): void {
  const shared = new Shared(data.cells);
  const cfg = data.cfg;
  const w = new WorkerState(data.id, cfg, shared);
  w.streamProfile = data.streamProfile;
  w.msgProfile = data.msgProfile;
  w.payloadMode = cfg.payloadMode;
  w.seeded = cfg.seed !== 0n;
  w.rng = seedWorker(cfg.seed, data.id);

  let ok = openHandles(w, data);
  if (ok) {
    // Allocation posture. The plaintext is allocated once per worker
    // and held for the whole run (rotating mode refills it in place);
    // the wire and round-trip buffers are the Buffers the binding
    // returns per call and V8 reclaims them when the iteration drops
    // them, and the pump loop drains through one reused slice and
    // concatenates once per direction. Under the default fixed CSPRNG
    // mode every worker's buffer is distinct, so cross-worker data
    // crossover is detectable; pattern modes trade that property for
    // content edge-case coverage.
    try {
      w.plaintext = Buffer.allocUnsafe(cfg.payload);
      w.rng = fillPayload(w.plaintext, cfg.payloadMode, w.seeded, w.rng);
    } catch (e) {
      workerFail(w, `g${w.id} iter 0: payload alloc: ${String(e)}`);
      ok = false;
    }
  }

  // Warmup iteration — counted in the totals; its completion feeds the
  // post-warmup baselines. Anything that escapes an iteration other
  // than a library status becomes a worker error rather than a lost
  // thread: the launcher waits for one warmup report per worker, so a
  // worker that unwound past it would leave the launcher waiting for a
  // rendezvous that can no longer happen.
  if (ok) {
    try {
      ok = iterate(w, 0);
    } catch (e) {
      workerFail(w, `g${w.id} iter 0: ${String(e)}`);
      ok = false;
    }
  }
  parentPort?.postMessage({ t: 'warmup' } satisfies WorkerMsg);
  shared.waitForRelease();

  if (ok) {
    let it = 1;
    for (;;) {
      if (cfg.iterations > 0 && it >= cfg.iterations) {
        break;
      }
      if (shared.stopRequested()) {
        break;
      }
      try {
        if (!iterate(w, it)) {
          break;
        }
        if (!workerMaintenance(w, it)) {
          break;
        }
      } catch (e) {
        workerFail(w, `g${w.id} iter ${it}: ${String(e)}`);
        break;
      }
      it++;
    }
  }

  const report: WorkerReport = {
    id: w.id,
    iters: w.iters,
    bytesEnc: w.bytesEnc,
    bytesDec: w.bytesDec,
    nanosEnc: w.nanosEnc,
    nanosDec: w.nanosDec,
    finishNs: nowNs(),
    failed: w.failed,
    error: w.error,
  };
  if (w.streamPipe !== null) {
    w.streamPipe.free();
  }
  if (w.msgPipe !== null) {
    w.msgPipe.free();
  }
  parentPort?.postMessage({ t: 'done', report } satisfies WorkerMsg);
}

if (!isMainThread) {
  workerMain(workerData as WorkerData);
}
