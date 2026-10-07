// The maintenance operations that mutate a live Pipeline handle
// between iterations: master rotation (--rekey-every) and blob reopen
// (--blob-cycle-every).

import { randomBytes } from 'node:crypto';
import { Pipeline } from '../src/index.js';
import { logLine, statusDetail, workerFail, type WorkerState } from './state.js';

/**
 * Byte length of each fresh master drawn for a rotation. Matches the
 * size Init auto-generates for both the parallax and the wrapper
 * master.
 */
const REKEY_MASTER_SIZE = 32;

const NO_MASTER = new Uint8Array(0);

/**
 * Master rotation. Rotates the parallax + wrapper masters on every
 * active Pipeline this worker owns and retains the refreshed blob for
 * subsequent blob reopens. Masters are drawn fresh from the OS CSPRNG
 * on every rotation regardless of --seed (master rotation is pipeline
 * keying, not plaintext content); a disabled layer passes no bytes,
 * which Rekey ignores. The eight inner seeds and the MAC key are
 * untouched by design — Rekey targets only the two outer-layer master
 * secrets.
 */
function rekeyPipes(w: WorkerState, it: number): boolean {
  const perm = w.cfg.parallax ? randomBytes(REKEY_MASTER_SIZE) : NO_MASTER;
  const wrap = w.cfg.wrapper ? randomBytes(REKEY_MASTER_SIZE) : NO_MASTER;

  if (w.streamPipe !== null) {
    try {
      w.streamBlob = w.streamPipe.rekey(perm, wrap);
    } catch (e) {
      workerFail(
        w,
        `g${w.id} iter ${it}: Rekey(${w.streamProfile}): ${statusDetail(e)}`,
      );
      return false;
    }
  }
  if (w.msgPipe !== null) {
    try {
      w.msgBlob = w.msgPipe.rekey(perm, wrap);
    } catch (e) {
      workerFail(w, `g${w.id} iter ${it}: Rekey(${w.msgProfile}): ${statusDetail(e)}`);
      return false;
    }
  }
  const n = w.shared.nextRekey();
  logLine(
    `rekey: g${w.id} iter ${it} rotated parallax + wrapper masters (rekey #${n})`,
  );
  return true;
}

/**
 * Blob reopen. Reopens every active Pipeline this worker owns from its
 * retained blob: a fresh handle is loaded from the blob, the running
 * handle is freed, and the fresh one is swapped in, so every later
 * iteration round-trips through seeds and masters that survived a blob
 * crossing. The input is the blob Init or the latest Rekey handed out,
 * not a fresh Save: that is what a receiver holds, and reopening from
 * it proves the handed-out bytes rather than the live state. The blob
 * carries the Pipeline's full shape, so no override reaches the reopen.
 * On a Load failure the running handle stays and the failure aborts the
 * run.
 */
function blobCyclePipes(w: WorkerState, it: number): boolean {
  if (w.streamPipe !== null) {
    let fresh: Pipeline;
    try {
      fresh = Pipeline.load(w.streamBlob);
    } catch (e) {
      workerFail(w, `g${w.id} iter ${it}: Load(${w.streamProfile}): ${statusDetail(e)}`);
      return false;
    }
    w.streamPipe.free();
    w.streamPipe = fresh;
  }
  if (w.msgPipe !== null) {
    let fresh: Pipeline;
    try {
      fresh = Pipeline.load(w.msgBlob);
    } catch (e) {
      workerFail(w, `g${w.id} iter ${it}: Load(${w.msgProfile}): ${statusDetail(e)}`);
      return false;
    }
    w.msgPipe.free();
    w.msgPipe = fresh;
  }
  const n = w.shared.nextBlobCycle();
  logLine(`blob-cycle: g${w.id} iter ${it} reopened from session blob (cycle #${n})`);
  return true;
}

/**
 * Handle mutation. Runs the periodic Pipeline-mutating operations after
 * a completed iteration: master rotation (--rekey-every) and blob
 * reopen (--blob-cycle-every). Both intervals count per-worker
 * iterations; the warmup iteration (iter 0) never triggers because the
 * worker loop calls this for iter >= 1 only. Rekey rewrites the
 * outer-layer keying of a live handle and a blob reopen replaces the
 * handle outright. A shared-handle binding guards both with a write
 * lock so in-flight cipher calls on other workers drain before anything
 * changes; this binding runs independent-handles, so the handles either
 * operation touches belong to the one worker that is between its own
 * iterations, no other thread can have a call in flight on them, and no
 * encrypt can be separated from its decrypt by either. The two counts
 * the log lines carry are still run-wide, so they go through the shared
 * cell. Returns false after recording a worker error.
 */
export function workerMaintenance(w: WorkerState, it: number): boolean {
  const cfg = w.cfg;
  if (cfg.rekeyEvery > 0 && it % cfg.rekeyEvery === 0) {
    if (!rekeyPipes(w, it)) {
      return false;
    }
  }
  if (cfg.blobCycleEvery > 0 && it % cfg.blobCycleEvery === 0) {
    if (!blobCyclePipes(w, it)) {
      return false;
    }
  }
  return true;
}
