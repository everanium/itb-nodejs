// Handle-lifetime wrapper around the Triple Pipeline.

import {
  type Handle,
  ITB_Triple_Close,
  ITB_Triple_DecryptMessage,
  ITB_Triple_DecryptStream,
  ITB_Triple_EncryptMessage,
  ITB_Triple_EncryptStream,
  ITB_Triple_Free,
  ITB_Triple_Init,
  ITB_Triple_Open,
  ITB_Triple_RegisterProfile,
  ITB_Triple_Rekey,
} from './ffi.js';
import { ItbError, check } from './error.js';
import { Opts } from './opts.js';
import { Status } from './status.js';
import { DecryptStream, EncryptStream } from './stream.js';

/** Floor capacity for blob output buffers (Init / Rekey). */
const BLOB_CAP = 64 * 1024;

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
  // capacity — pattern P1 in the fleet audit. Return a right-sized
  // copy so the caller does not pin the pre-allocation slack.
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

/**
 * A Triple Pipeline session plus its exported blob bytes.
 *
 * The blob carries the session bundle the receiver feeds to
 * [Pipeline.open]; [Pipeline.rekey] refreshes it. Release the handle
 * deterministically via [Symbol.dispose] (`using` declarations) or
 * `free()`; a FinalizationRegistry backstop frees on GC (libitb
 * zeroes key material internally).
 *
 * Streaming-decrypt caveat: chunked Streaming AEAD verifies per
 * chunk, so plaintext of verified chunks is released before a later
 * chunk can fail authentication.
 */
export class Pipeline implements Disposable {
  /** @internal */
  _handle: Handle = 0;
  private _blob: Buffer;

  private constructor(handle: Handle, blob: Buffer) {
    this._handle = handle;
    this._blob = blob;
    finalizer.register(this, handle, this);
  }

  /**
   * Constructs a fresh Pipeline against the named profile. On a
   * blob-buffer retry the Init re-runs and yields a fresh session
   * (the undersized attempt is closed by libitb before returning).
   */
  static init(profile: string, opts: Opts = new Opts()): Pipeline {
    const optsStr = opts.build();
    const handle: [Handle] = [0];
    const blob = retryOnce(BLOB_CAP, (buf, len) =>
      ITB_Triple_Init(profile, optsStr, buf, buf.length, len, handle),
    );
    return new Pipeline(handle[0]!, blob);
  }

  /**
   * Reconstructs a Pipeline from a blob produced by [Pipeline.init]
   * or [Pipeline.rekey]. `masters` is undefined to use the
   * blob-embedded masters, or `{ perm, wrap }` to override them.
   */
  static open(
    profile: string,
    blob: Uint8Array,
    opts: Opts = new Opts(),
    masters?: { perm: Uint8Array; wrap: Uint8Array },
  ): Pipeline {
    if (masters && (masters.perm.length === 0 || masters.wrap.length === 0)) {
      throw new ItbError(Status.BadInput, 'master overrides must be non-empty');
    }
    const optsStr = opts.build();
    const handle: [Handle] = [0];
    check(
      ITB_Triple_Open(
        profile,
        blob,
        blob.length,
        optsStr,
        masters ? masters.perm : null,
        masters ? masters.perm.length : 0,
        masters ? masters.wrap : null,
        masters ? masters.wrap.length : 0,
        masters ? 2 : 0,
        handle,
      ),
    );
    return new Pipeline(handle[0]!, Buffer.from(blob));
  }

  /** The exported session bundle bytes for the receiver side. */
  get blob(): Buffer {
    return this._blob;
  }

  /**
   * Rotates the parallax + wrapper masters and refreshes [blob].
   * Must not run concurrently with cipher calls or open stream
   * sessions on the same Pipeline.
   */
  rekey(perm: Uint8Array, wrap: Uint8Array): void {
    this._blob = retryOnce(Math.max(BLOB_CAP, this._blob.length), (buf, len) =>
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
 * Registers a user-defined Triple profile under `name` so subsequent
 * [Pipeline.init] / [Pipeline.open] calls resolve it. The opts follow
 * the register-profile grammar validated by Go (`mode`, `width`,
 * `innerHash` / `innerHashes`, `keyBits`, `macName`, `outerCipher`,
 * `parallaxPalette`, `parallaxSegmentSize`, `chunkSize`,
 * `parallaxOn`, `wrapperOn`) — build them with [Opts.withRaw] plus
 * the typed setters where key names coincide. A duplicate name fails
 * with [Status.ProfileExists].
 */
export function registerProfile(name: string, opts: Opts = new Opts()): void {
  check(ITB_Triple_RegisterProfile(name, opts.build()));
}
