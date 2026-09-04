// Handle-lifetime wrapper around the Triple Pipeline plus the
// profile-catalogue entries (inspect / register / lookup / profiles).

import {
  type Handle,
  ITB_Triple_Close,
  ITB_Triple_DecryptMessage,
  ITB_Triple_DecryptStream,
  ITB_Triple_EncryptMessage,
  ITB_Triple_EncryptStream,
  ITB_Triple_Free,
  ITB_Triple_Init,
  ITB_Triple_Inspect,
  ITB_Triple_Load,
  ITB_Triple_LoadF,
  ITB_Triple_Lookup,
  ITB_Triple_MaxWorkers,
  ITB_Triple_Profiles,
  ITB_Triple_Register,
  ITB_Triple_Rekey,
  ITB_Triple_Save,
  ITB_Triple_SaveF,
} from './ffi.js';
import { check } from './error.js';
import { Opts } from './opts.js';
import { Status } from './status.js';
import { DecryptStream, EncryptStream } from './stream.js';

/** Floor capacity for blob output buffers (Init / Save / Rekey). */
const BLOB_CAP = 64 * 1024;

/** Floor capacity for profile-JSON output buffers (Inspect / Lookup / Profiles). */
const JSON_CAP = 4 * 1024;

/**
 * Pre-allocation formula for Message / one-shot stream outputs:
 * `max(131072, payload * 5/4 + 131072)`.
 */
function outCap(payload: number): number {
  return Math.max(131_072, payload + (payload >>> 2) + 131_072);
}

/**
 * Single retry-once dispatch site for every variable-size output
 * buffer: pre-allocate `cap`, and on `BufferTooSmall` retry once with
 * the exact size the FFI reported through the length out-param.
 */
function retryOnce(
  cap: number,
  call: (buf: Uint8Array, len: [number | bigint]) => number,
): Buffer {
  let buf = new Uint8Array(cap);
  const len: [number | bigint] = [0];
  let rc = call(buf, len);
  // Retry only when the reported length strictly exceeds the current
  // capacity. Return a right-sized copy so the caller does not pin
  // the pre-allocation slack.
  if (rc === Status.BufferTooSmall && Number(len[0]) > cap) {
    buf = new Uint8Array(Number(len[0]));
    rc = call(buf, len);
  }
  check(rc);
  const n = Number(len[0]);
  return Buffer.from(buf.subarray(0, n));
}

function isZero(h: Handle): boolean {
  return h === 0 || h === 0n;
}

const finalizer = new FinalizationRegistry<Handle>((handle) => {
  try {
    if (!isZero(handle)) {
      ITB_Triple_Free(handle);
    }
  } catch {
    // Best-effort backstop; finalization runs at unspecified times.
  }
});

type CipherFn = (
  handle: Handle,
  src: Uint8Array | null,
  srcLen: number,
  out: Uint8Array,
  outCap: number,
  outLen: [number | bigint],
) => number;

/** Optional `(perm, wrap)` master pair for [Pipeline.load] / [Pipeline.loadF]. */
export interface Masters {
  perm: Uint8Array;
  wrap: Uint8Array;
}

/**
 * A Triple Pipeline session.
 *
 * [Pipeline.save] returns the serialised session blob the receiver
 * feeds to [Pipeline.load]; [Pipeline.rekey] refreshes it. Release
 * the handle deterministically via [Symbol.dispose] (`using`
 * declarations) or `free()`; a FinalizationRegistry backstop frees
 * on GC (libitb zeroes key material internally).
 *
 * Streaming-decrypt caveat: chunked Streaming AEAD verifies per
 * chunk, so plaintext of verified chunks is released before a later
 * chunk can fail authentication.
 */
export class Pipeline implements Disposable {
  /** @internal */
  _handle: Handle = 0;

  private constructor(handle: Handle) {
    this._handle = handle;
    finalizer.register(this, handle, this);
  }

  /**
   * Constructs a fresh Pipeline against the named profile. The
   * session blob is available through [Pipeline.save]. On a
   * blob-buffer retry the Init re-runs and yields a fresh session
   * (the undersized attempt is closed by libitb before returning).
   */
  static init(profile: string, opts: Opts = new Opts()): Pipeline {
    const optsStr = opts.build();
    const handle: [Handle] = [0];
    retryOnce(BLOB_CAP, (buf, len) =>
      ITB_Triple_Init(profile, optsStr, buf, buf.length, len, handle),
    );
    return new Pipeline(handle[0]!);
  }

  /**
   * Reconstructs a Pipeline from a blob produced by [Pipeline.save]
   * or [Pipeline.rekey]. The blob's embedded profile record is the
   * sole structural source — no profile name, no opts. `masters` is
   * undefined to use the blob-embedded masters, or `{ perm, wrap }`
   * to override them.
   */
  static load(blob: Uint8Array, masters?: Masters): Pipeline {
    const handle: [Handle] = [0];
    check(
      ITB_Triple_Load(
        blob.length > 0 ? blob : null,
        blob.length,
        masters ? masters.perm : null,
        masters ? masters.perm.length : 0,
        masters ? masters.wrap : null,
        masters ? masters.wrap.length : 0,
        masters ? 2 : 0,
        handle,
      ),
    );
    return new Pipeline(handle[0]!);
  }

  /**
   * [Pipeline.load] for a blob stored in a file; the file is read
   * inside the library.
   */
  static loadF(path: string, masters?: Masters): Pipeline {
    const handle: [Handle] = [0];
    check(
      ITB_Triple_LoadF(
        path,
        masters ? masters.perm : null,
        masters ? masters.perm.length : 0,
        masters ? masters.wrap : null,
        masters ? masters.wrap.length : 0,
        masters ? 2 : 0,
        handle,
      ),
    );
    return new Pipeline(handle[0]!);
  }

  /**
   * The current serialised session blob — the bytes `init` produced,
   * the bytes `load` re-marshalled, or the bytes of the latest
   * [rekey].
   */
  save(): Buffer {
    return retryOnce(BLOB_CAP, (buf, len) =>
      ITB_Triple_Save(this._handle, buf, buf.length, len),
    );
  }

  /**
   * Writes the current session blob to `path` inside the library
   * (mode 0600; the containing directory must exist).
   */
  saveF(path: string): void {
    check(ITB_Triple_SaveF(this._handle, path));
  }

  /**
   * Rotates the parallax + wrapper masters and returns the refreshed
   * session blob (also observable through [save]). Must not run
   * concurrently with cipher calls or open stream sessions on the
   * same Pipeline.
   */
  rekey(perm: Uint8Array, wrap: Uint8Array): Buffer {
    return retryOnce(BLOB_CAP, (buf, len) =>
      ITB_Triple_Rekey(
        this._handle,
        perm,
        perm.length,
        wrap,
        wrap.length,
        buf,
        buf.length,
        len,
      ),
    );
  }

  /**
   * Sets the worker cap for every subsequent cipher call. `n` is
   * clamped, never rejected: `n <= 0` selects auto (`runtime.NumCPU`),
   * `1..256` pins the cap, larger values are treated as 256. The cap
   * is per-machine tuning and is never written to the blob.
   */
  maxWorkers(n: number): void {
    check(ITB_Triple_MaxWorkers(this._handle, n));
  }

  /**
   * Zeroes the Pipeline's key material and marks it closed.
   * Idempotent; subsequent cipher calls fail with
   * [Status.TripleClosed].
   */
  close(): void {
    check(ITB_Triple_Close(this._handle));
  }

  /** Single Message encrypt: one call, one self-contained wire. */
  encryptMessage(plain: Uint8Array): Buffer {
    return this.cipher(ITB_Triple_EncryptMessage, plain);
  }

  /** Receive-side counterpart of [encryptMessage]. */
  decryptMessage(wire: Uint8Array): Buffer {
    return this.cipher(ITB_Triple_DecryptMessage, wire);
  }

  /**
   * One-shot stream encrypt for callers holding the whole plaintext
   * in memory. For bounded-memory streaming use [encryptStream] /
   * [encryptStreamPump].
   */
  encryptStreamOneShot(plain: Uint8Array): Buffer {
    return this.cipher(ITB_Triple_EncryptStream, plain);
  }

  /** Receive-side counterpart of [encryptStreamOneShot]. */
  decryptStreamOneShot(wire: Uint8Array): Buffer {
    return this.cipher(ITB_Triple_DecryptStream, wire);
  }

  /** Opens an incremental encrypt session (plaintext in, wire out). */
  encryptStream(): EncryptStream {
    return EncryptStream.begin(this);
  }

  /** Opens an incremental decrypt session (wire in, plaintext out). */
  decryptStream(): DecryptStream {
    return DecryptStream.begin(this);
  }

  /**
   * Pumps `chunks` through an encrypt session into `sink` with
   * bounded memory: feed a chunk, drain available wire, repeat; end +
   * final drain after the last chunk. The session is freed on return.
   */
  encryptStreamPump(chunks: Iterable<Uint8Array>, sink: (wire: Buffer) => void): void {
    const sess = this.encryptStream();
    try {
      sess.pump(chunks, sink);
    } finally {
      sess.free();
    }
  }

  /** Receive-side counterpart of [encryptStreamPump]. */
  decryptStreamPump(chunks: Iterable<Uint8Array>, sink: (plain: Buffer) => void): void {
    const sess = this.decryptStream();
    try {
      sess.pump(chunks, sink);
    } finally {
      sess.free();
    }
  }

  /**
   * Releases the handle (libitb closes the Pipeline first, zeroing
   * key material). Safe to call more than once.
   */
  free(): void {
    if (isZero(this._handle)) {
      return;
    }
    finalizer.unregister(this);
    ITB_Triple_Free(this._handle);
    this._handle = 0;
  }

  [Symbol.dispose](): void {
    this.free();
  }

  /** Shared body for the four buffer-in / buffer-out cipher entries. */
  private cipher(f: CipherFn, src: Uint8Array): Buffer {
    return retryOnce(outCap(src.length), (buf, len) =>
      f(this._handle, src.length > 0 ? src : null, src.length, buf, buf.length, len),
    );
  }
}

/**
 * Profile record — the JSON object libitb emits from [inspect] /
 * [lookup] and accepts in [register]. Keys: `name`, `mode`, `width`,
 * `hash`, `hashes`, `keybits`, `mac`, `tagstub`, `chunk`, `wrapper`,
 * `outer`, `parallax`, `palette`, `segment`; absent keys are optional
 * fields at their zero value.
 */
export interface Profile {
  name?: string;
  mode: string;
  width: number;
  hash?: string;
  hashes?: string[];
  keybits: number;
  mac?: string;
  tagstub?: number;
  chunk?: number;
  wrapper: boolean;
  outer?: string;
  parallax: boolean;
  palette?: string[];
  segment?: number;
}

/** Shared body for the JSON-returning catalogue entries. */
function jsonOut<T>(call: (buf: Uint8Array, len: [number | bigint]) => number): T {
  return JSON.parse(retryOnce(JSON_CAP, call).toString('utf8')) as T;
}

/**
 * Decodes the blob's embedded profile record without opening a
 * Pipeline. No registry read, no primitive probe — a primitive name
 * the local build lacks is returned unchanged.
 */
export function inspect(blob: Uint8Array): Profile {
  return jsonOut<Profile>((buf, len) =>
    ITB_Triple_Inspect(blob.length > 0 ? blob : null, blob.length, buf, buf.length, len),
  );
}

/**
 * Registers a profile record under `name` so subsequent
 * [Pipeline.init] / [lookup] calls resolve it. `profile` is the
 * record object (the shape [inspect] returns) or an already-encoded
 * JSON string; a `name` key inside it, if present, must be empty or
 * equal to `name`. Validation (name pattern, reserved prefixes, field
 * rules) is performed by libitb; a duplicate name fails with
 * [Status.ProfileExists].
 */
export function register(name: string, profile: Profile | string): void {
  const text = typeof profile === 'string' ? profile : JSON.stringify(profile);
  check(ITB_Triple_Register(name, text));
}

/**
 * The profile record registered under `name` (a shipped catalogue
 * entry or a prior [register]). An unknown name fails with
 * [Status.UnknownProfile].
 */
export function lookup(name: string): Profile {
  return jsonOut<Profile>((buf, len) => ITB_Triple_Lookup(name, buf, buf.length, len));
}

/** The sorted list of every registered profile name. */
export function profiles(): string[] {
  return jsonOut<string[]>((buf, len) => ITB_Triple_Profiles(buf, buf.length, len));
}
