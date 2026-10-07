// Shared declarations of the loop stress harness: the cipher-surface
// selectors, the concurrency mode this binding runs, the resolved
// configuration, the cross-thread cell the workers and the launcher
// share, and the output helpers every unit writes through.
//
// TypeScript-specific. An ES module is evaluated once on first import
// and the worker unit is also the worker thread's entry point, so the
// launcher cannot import it without running a worker body in the main
// thread. A declarations unit holding what both sides need is the same
// answer the C reference reaches with its header.

import { writeSync } from 'node:fs';
import koffi from 'koffi';
import { ItbError, type Pipeline } from '../src/index.js';

/* Cipher surfaces the --shape flag selects. */
export const SHAPE_STREAM = 0; // session pump: begin / write / read / end
export const SHAPE_MESSAGE = 1; // Single Message: one whole-buffer call
export const SHAPE_STREAM_ONE_SHOT = 2; // stream surface, one whole-buffer call
export const SHAPE_BOTH = 3; // all three, rotating by iteration number

export const SHAPE_NAMES: readonly string[] = [
  'stream',
  'message',
  'stream_one_shot',
  'both',
];

/**
 * --goroutines ceiling; the harness targets modest hosts and each
 * worker pins payload-sized buffers for the whole run.
 */
export const MAX_WORKERS = 10;

/**
 * Concurrency mode. This binding runs independent-handles: a worker
 * thread is a separate V8 isolate with its own instance of the koffi
 * addon, only structured-cloneable data crosses the boundary, and the
 * binding's public surface offers no entry that adopts an existing
 * native handle — `Pipeline`'s constructor is private and `init` /
 * `load` / `loadF` are the only paths to it. So every worker opens its
 * own handle from the Init blob and maintains it alone.
 */
export const CONCURRENCY = 'independent-handles';

/**
 * Largest slice fed to a stream session per write; the drain after
 * every write uses the same bound.
 */
export const PUMP_SLICE = 1 << 20;

export function shapeName(shape: number): string {
  return SHAPE_NAMES[shape]!;
}

export function parseShape(s: string): number | null {
  const i = SHAPE_NAMES.indexOf(s);
  return i < 0 ? null : i;
}

/** The resolved command line, as it crosses to every worker thread. */
export interface Config {
  /** Run duration in nanoseconds; ignored when iterations > 0. */
  durationNs: number;
  /** Per-worker count incl. warmup; 0 = duration-based. */
  iterations: number;
  /** The --goroutines value as given. */
  workersRequested: number;
  /** The effective worker count. */
  workers: number;
  shape: number;
  hash: string;
  mac: string;
  /** Plaintext bytes per iteration. */
  payload: number;
  /** Resolved bytes; the effective limit once shaped. */
  memlimit: number;
  /** --memlimit auto: cap only when the runtime has none. */
  memlimitAuto: boolean;
  /** 0 = leave the runtime default. */
  gogc: number;
  parallax: boolean;
  wrapper: boolean;

  /** Empty = shape-based profile pair. */
  profile: string;
  /** 0 = profile default. */
  keyBits: number;
  /** 0 = profile default. */
  nonceBits: number;
  /** Container floor sizing mode: 1 (per-region, default) | 2 (per-container). */
  blobMode: number;
  /** 0 = profile default. */
  chunkSize: number;
  /** 0 = profile default. */
  barrierFill: number;
  /** DRBG fill primitive; "" = profile default (auto tier). */
  drbg: string;
  /** 0 = inherit from the environment. */
  gomaxprocs: number;
  /** Per-worker iterations between rotations; 0 = never. */
  rekeyEvery: number;
  /** Per-worker iterations between reopens; 0 = never. */
  blobCycleEvery: number;
  payloadMode: number;
  /** 0 = OS CSPRNG plaintexts. */
  seed: bigint;
  jsonOutput: boolean;
  /** Empty = none. */
  memprofile: string;
}

export function newConfig(): Config {
  return {
    durationNs: 0,
    iterations: 0,
    workersRequested: 0,
    workers: 0,
    shape: SHAPE_STREAM,
    hash: '',
    mac: '',
    payload: 0,
    memlimit: 0,
    memlimitAuto: false,
    gogc: 0,
    parallax: true,
    wrapper: true,
    profile: '',
    keyBits: 0,
    nonceBits: 0,
    blobMode: 1,
    chunkSize: 0,
    barrierFill: 0,
    drbg: '',
    gomaxprocs: 0,
    rekeyEvery: 0,
    blobCycleEvery: 0,
    payloadMode: 0,
    seed: 0n,
    jsonOutput: false,
    memprofile: '',
  };
}

/* Slots of the shared Int32Array the launcher and the workers hold. */
const SLOT_STOP = 0;
const SLOT_RELEASE = 1;
const SLOT_REKEYS = 2;
const SLOT_BLOB_CYCLES = 3;
const SHARED_SLOTS = 4;

/**
 * The one piece of mutable state several threads touch: the stop
 * request, the warmup gate, and the two maintenance totals.
 *
 * TypeScript-specific. A worker sitting inside a synchronous foreign
 * call cannot service its message port, so a stop request delivered by
 * message would not arrive until the call had returned and the loop
 * was about to ask for it anyway. A SharedArrayBuffer read is what a
 * worker can do between iterations without yielding, and `Atomics` is
 * what makes the two maintenance totals one count across threads
 * rather than a count per thread.
 */
export class Shared {
  readonly cells: Int32Array;

  constructor(cells: Int32Array) {
    this.cells = cells;
  }

  static create(): Shared {
    return new Shared(new Int32Array(new SharedArrayBuffer(SHARED_SLOTS * 4)));
  }

  stopRequested(): boolean {
    return Atomics.load(this.cells, SLOT_STOP) !== 0;
  }

  requestStop(): void {
    Atomics.store(this.cells, SLOT_STOP, 1);
  }

  /** Opens the gate every worker waits at after its warmup iteration. */
  release(): void {
    Atomics.store(this.cells, SLOT_RELEASE, 1);
    Atomics.notify(this.cells, SLOT_RELEASE);
  }

  waitForRelease(): void {
    while (Atomics.load(this.cells, SLOT_RELEASE) === 0) {
      Atomics.wait(this.cells, SLOT_RELEASE, 0, 1000);
    }
  }

  /** Bumps and returns the run-wide rotation count. */
  nextRekey(): number {
    return Atomics.add(this.cells, SLOT_REKEYS, 1) + 1;
  }

  /** Bumps and returns the run-wide reopen count. */
  nextBlobCycle(): number {
    return Atomics.add(this.cells, SLOT_BLOB_CYCLES, 1) + 1;
  }

  rekeys(): number {
    return Atomics.load(this.cells, SLOT_REKEYS);
  }

  blobCycles(): number {
    return Atomics.load(this.cells, SLOT_BLOB_CYCLES);
  }
}

/** What a worker thread is handed when it starts. */
export interface WorkerData {
  id: number;
  cfg: Config;
  cells: Int32Array;
  streamProfile: string;
  msgProfile: string;
  streamBlob: Uint8Array | null;
  msgBlob: Uint8Array | null;
}

/** One worker's closing report. */
export interface WorkerReport {
  id: number;
  iters: number;
  bytesEnc: number;
  bytesDec: number;
  nanosEnc: bigint;
  nanosDec: bigint;
  finishNs: bigint;
  failed: boolean;
  error: string;
}

/** Messages a worker thread sends the launcher. */
export type WorkerMsg =
  | { t: 'warmup' }
  | { t: 'fatal'; code: number }
  | { t: 'done'; report: WorkerReport };

// ─── Output ────────────────────────────────────────────────────────

type LibcExit = (code: number) => void;
type LibcSignal = (sig: number, handler: null) => unknown;

let libcExit: LibcExit | null | undefined;

/**
 * Leaves the process on the spot with the given code, without
 * unwinding. Returns only when the entry could not be resolved.
 *
 * TypeScript-specific. `process.exit` in a worker thread ends that
 * thread alone, and in the main thread it still runs V8's teardown and
 * flushes streams the mismatch path must not touch; the libc entry
 * that ends a process without any of it is reached through the same
 * FFI mechanism the binding itself uses. Where it cannot be resolved
 * the caller's fallback applies — the launcher exits itself and a
 * worker asks the launcher to.
 */
export function hardExit(code: number): void {
  if (libcExit === undefined) {
    try {
      libcExit = koffi.load('libc.so.6').func('void _exit(int code)') as unknown as LibcExit;
    } catch {
      libcExit = null;
    }
  }
  if (libcExit !== null) {
    libcExit(code);
  }
}

/**
 * A consumer that stops reading ends the run. The default disposition
 * for SIGPIPE is restored so the process dies from the signal with
 * status 141 and prints nothing — the reference behaviour, and what
 * anyone piping into head or less expects. libuv installs SIG_IGN
 * before any user code runs and the failed write surfaces as an EPIPE
 * error instead, so restoring the default is an explicit step here
 * rather than something inherited; the runtime exposes no
 * signal-disposition API, so libc's own entry is called through the
 * same FFI mechanism the binding uses. Returns whether the disposition
 * was installed, so the fix can be stated rather than inferred from a
 * count of clean runs.
 */
export function restoreSigpipe(): boolean {
  try {
    const signal = koffi
      .load('libc.so.6')
      .func('void *signal(int sig, void *handler)') as unknown as LibcSignal;
    signal(13, null);
    return true;
  } catch {
    return false;
  }
}

/**
 * Writes the whole string to a descriptor, in as few write calls as
 * the descriptor allows, and leaves with 141 when the consumer has
 * gone.
 *
 * TypeScript-specific. A descriptor the runtime left in non-blocking
 * mode returns EAGAIN rather than blocking, so the write is retried;
 * and where the default SIGPIPE disposition could not be restored the
 * EPIPE return is all that is left of the signal, so it becomes the
 * status the signal would have produced, having printed nothing.
 */
function writeAll(fd: number, text: string): void {
  const buf = Buffer.from(text, 'utf8');
  let off = 0;
  while (off < buf.length) {
    try {
      off += writeSync(fd, buf, off, buf.length - off);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code === 'EAGAIN') {
        continue;
      }
      if (code === 'EPIPE') {
        hardExit(141);
        process.exit(141);
      }
      throw e;
    }
  }
}

/**
 * Prints one prefixed status line to stdout.
 *
 * The line is assembled with its newline and handed to one write call,
 * so a worker logging a maintenance line from another thread cannot
 * land between a text and the newline that terminates it.
 */
export function logLine(text: string): void {
  writeAll(1, `[loop] ${text}\n`);
}

/** Prints one prefixed diagnostic to stderr. */
export function errLine(text: string): void {
  writeAll(2, `loop: ${text}\n`);
}

/** Prints an already-composed block to stderr. */
export function errRaw(text: string): void {
  writeAll(2, text);
}

/** Prints an already-composed line to stdout. */
export function outRaw(text: string): void {
  writeAll(1, text);
}

export function onOff(b: boolean): string {
  return b ? 'on' : 'off';
}

/**
 * Renders an encoder policy env value for the summary: the raw string
 * when set, "default" when the shipped ladder applies.
 */
export function policyLabel(env: string | undefined): string {
  if (env === undefined) {
    return 'default';
  }
  const trimmed = env.replace(/^[ \t]+/, '');
  return trimmed === '' ? 'default' : trimmed;
}

/**
 * The sentence a failing call left behind, without the status prefix
 * the binding's error type puts in front of it. The composition is
 * undone here rather than the library asked a second time: the
 * diagnostic is process-global last-write-wins, so a second read could
 * already belong to another call.
 */
export function errorSentence(e: unknown): string {
  if (e instanceof ItbError) {
    const prefix = `itb: status=${e.status}: `;
    return e.message.startsWith(prefix) ? e.message.slice(prefix.length) : e.message;
  }
  return e instanceof Error ? e.message : String(e);
}

/**
 * The failure detail a log line carries: the numeric status the
 * binding's own surface exposes and the finished sentence the library
 * left behind. Nothing is composed here — the wording arrives whole
 * from the failing call.
 */
export function statusDetail(e: unknown): string {
  if (e instanceof ItbError) {
    return `status ${e.status}: ${errorSentence(e)}`;
  }
  return errorSentence(e);
}

/**
 * One worker's private state: the handles it owns, the blobs it
 * retains, its plaintext, its generator, its counters, and the error it
 * stopped on. Under independent-handles every field below belongs to
 * one thread alone; only `shared` is seen by another.
 */
export class WorkerState {
  readonly id: number;
  readonly cfg: Config;
  readonly shared: Shared;

  streamPipe: Pipeline | null = null;
  msgPipe: Pipeline | null = null;
  streamProfile = '';
  msgProfile = '';

  /**
   * The blob Init handed out, replaced by every rekey; the input of the
   * next blob reopen.
   */
  streamBlob: Uint8Array = new Uint8Array(0);
  msgBlob: Uint8Array = new Uint8Array(0);

  plaintext: Buffer = Buffer.alloc(0);
  payloadMode = 0;
  seeded = false;
  /** splitmix64 state when seeded. */
  rng = 0n;

  /* Counters the closing report carries back to the launcher. */
  iters = 0;
  bytesEnc = 0;
  bytesDec = 0;
  nanosEnc = 0n;
  nanosDec = 0n;

  failed = false;
  error = '';

  constructor(id: number, cfg: Config, shared: Shared) {
    this.id = id;
    this.cfg = cfg;
    this.shared = shared;
  }
}

/**
 * Records the worker's error text (first error wins) and requests a
 * stop of the whole run.
 */
export function workerFail(w: WorkerState, text: string): void {
  if (!w.failed) {
    w.error = text;
    w.failed = true;
  }
  w.shared.requestStop();
}
