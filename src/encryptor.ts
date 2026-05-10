// High-level Encryptor wrapper over the libitb C ABI.
//
// Mirrors the github.com/everanium/itb/easy Go sub-package: one
// constructor call replaces the lower-level seven-line setup ceremony
// (hash factory, three or seven seeds, MAC closure, container-config
// wiring) and returns an Encryptor instance that owns its own
// per-instance configuration. Two encryptors with different settings
// can be used in parallel without cross-contamination of the
// process-wide ITB configuration.
//
// Quick start (Single Ouroboros + HMAC-BLAKE3):
//
//   import { Encryptor } from './encryptor.js';
//   {
//     using enc = new Encryptor('blake3', 1024, 'hmac-blake3');
//     const ct = enc.encryptAuth(new TextEncoder().encode('hello world'));
//     const pt = enc.decryptAuth(ct);
//   }
//
// Triple Ouroboros (7 seeds, mode = 3):
//
//   {
//     using enc = new Encryptor('areion512', 2048, 'hmac-blake3', 3);
//     const ct = enc.encrypt(payload);
//     const pt = enc.decrypt(ct);
//   }
//
// Cross-process persistence (encrypt today / decrypt tomorrow):
//
//   const blob = enc.exportState();
//   // ... save blob to disk / KMS / wire ...
//   const cfg = Encryptor.peekConfig(blob);
//   {
//     using dec = new Encryptor(cfg.primitive, cfg.keyBits, cfg.macName, cfg.mode);
//     dec.importState(blob);
//     const pt = dec.decryptAuth(ct);
//   }
//
// Streaming. Chunking lives on the binding side: slice the plaintext
// into chunks of `chunkSize` bytes and call `encrypt` per chunk; on
// the decrypt side walk the concatenated stream by reading the chunk
// header, calling `parseChunkLen`, and feeding the chunk to
// `decrypt`. The encryptor's chunk-size knob (set via `setChunkSize`)
// is consumed only by the Go-side EncryptStream entry point; one-shot
// `encrypt` honours the container-cap heuristic in itb.ChunkSize.
//
// **Output buffer cache.** The cipher methods reuse a per-encryptor
// `Uint8Array` to skip the size-probe round-trip and avoid the
// per-call allocation cost; the buffer grows on demand (with a 1.25×
// upper-bound pre-allocation against the empirical ≤ 1.155 expansion
// factor) and survives between calls. Each cipher call returns a
// fresh `Uint8Array` view of the current result via `slice`, so the
// cache is never exposed to the caller — but the cached bytes (the
// most recent ciphertext or plaintext) sit in heap memory until the
// next cipher call overwrites them, until a grow event triggers the
// wipe-on-grow path, or until `close` / `free` / `Symbol.dispose`
// zeroes them. Callers handling sensitive plaintext under a heap-scan
// threat model should call `close` immediately after the last decrypt
// rather than relying on dispose-time zeroisation at end of scope.
//
// **Lifecycle.** Both `free` and `[Symbol.dispose]` release the
// underlying libitb handle; a `FinalizationRegistry` backstop runs
// the same release on GC if neither was called. Synchronous koffi
// calls cannot race the finalizer — the JS event loop is blocked for
// the duration of the FFI call, so finalizers cannot fire mid-call —
// therefore explicit reachability fences are not required for the
// synchronous shape of this binding.

import {
  check,
  errorFromStatus,
  ITBError,
  ITBStreamAfterFinalError,
  ITBStreamTruncatedError,
} from './errors.js';
import {
  ITB_Easy_Close,
  ITB_Easy_Decrypt,
  ITB_Easy_DecryptAuth,
  ITB_Easy_DecryptStreamAuth,
  ITB_Easy_Encrypt,
  ITB_Easy_EncryptAuth,
  ITB_Easy_EncryptStreamAuth,
  ITB_Easy_Export,
  ITB_Easy_Free,
  ITB_Easy_HasPRFKeys,
  ITB_Easy_HeaderSize,
  ITB_Easy_Import,
  ITB_Easy_IsMixed,
  ITB_Easy_KeyBits,
  ITB_Easy_MACKey,
  ITB_Easy_MACName,
  ITB_Easy_Mode,
  ITB_Easy_New,
  ITB_Easy_NewMixed,
  ITB_Easy_NewMixed3,
  ITB_Easy_NonceBits,
  ITB_Easy_ParseChunkLen,
  ITB_Easy_PeekConfig,
  ITB_Easy_PRFKey,
  ITB_Easy_Primitive,
  ITB_Easy_PrimitiveAt,
  ITB_Easy_SeedComponents,
  ITB_Easy_SeedCount,
  ITB_Easy_SetBarrierFill,
  ITB_Easy_SetBitSoup,
  ITB_Easy_SetChunkSize,
  ITB_Easy_SetLockSeed,
  ITB_Easy_SetLockSoup,
  ITB_Easy_SetNonceBits,
} from './native.js';
import {
  DEFAULT_CHUNK_SIZE as STREAM_DEFAULT_CHUNK_SIZE,
  STREAM_ID_LEN,
  generateStreamId as _generateStreamId,
} from './streams.js';
import type { Readable, Writable } from 'node:stream';
import { readString } from './read-string.js';
import { Status } from './status.js';

type Handle = bigint | number;

const ZERO: Handle = 0;

function isZero(h: Handle): boolean {
  return h === 0 || h === 0n;
}

const decoder = new TextDecoder('utf-8');

const encryptorFinalizer = new FinalizationRegistry<Handle>((handle) => {
  try {
    if (!isZero(handle)) {
      ITB_Easy_Free(handle);
    }
  } catch {
    // Best-effort; finalization runs at unspecified times.
  }
});

/**
 * Configuration tuple parsed out of a state blob by
 * {@link Encryptor.peekConfig}. The four fields mirror the JSON
 * payload's `primitive` / `key_bits` / `mode` / `mac` keys.
 */
export interface PeekedConfig {
  readonly primitive: string;
  readonly keyBits: number;
  readonly mode: number;
  readonly macName: string;
}

/**
 * High-level Encryptor over the libitb C ABI.
 *
 * Construction is the heavy step — generates fresh PRF keys, fresh
 * seed components, and a fresh MAC key from `/dev/urandom`. Reusing
 * one Encryptor instance across many encrypt / decrypt calls
 * amortises the cost across the lifetime of a session.
 *
 * Use under a `using` declaration for deterministic lifetime, or call
 * {@link Encryptor.free} explicitly to zero PRF / MAC / seed material
 * when the session ends. The {@link Encryptor.close} method is the
 * explicit zeroing entry point that does NOT release the handle slot;
 * {@link Encryptor.free} zeroes the cache and releases the handle in
 * one step.
 *
 * Thread-safety contract.
 * Cipher methods ({@link Encryptor.encrypt} / {@link Encryptor.decrypt}
 * / {@link Encryptor.encryptAuth} / {@link Encryptor.decryptAuth})
 * write into the per-instance output-buffer cache and are **not safe**
 * to invoke concurrently against the same encryptor. Node.js's main
 * thread is single-threaded by default, so the contract only matters
 * when the application uses worker threads or multiple async contexts
 * sharing one Encryptor handle. Per-instance configuration setters
 * ({@link Encryptor.setNonceBits} / {@link Encryptor.setBarrierFill}
 * / {@link Encryptor.setBitSoup} / {@link Encryptor.setLockSoup} /
 * {@link Encryptor.setLockSeed} / {@link Encryptor.setChunkSize}) and
 * state-serialisation methods ({@link Encryptor.exportState} /
 * {@link Encryptor.importState}) likewise require external
 * synchronisation when called against the same encryptor from multiple
 * worker threads. Distinct Encryptor instances, each owned by one
 * worker, run independently against the libitb worker pool.
 */
export class Encryptor implements Disposable {
  /** @internal */
  _handle: Handle = ZERO;
  /** @internal */
  _outputCache: Uint8Array | null = null;
  /**
   * Tracks the closed / freed state independently of the handle
   * field so the preflight in {@link Encryptor._checkOpen} can
   * surface `Status.EasyClosed` after {@link Encryptor.close} /
   * {@link Encryptor.free} without relying on the libitb-side
   * handle-id lookup (which would surface `Status.BadHandle` once
   * {@link Encryptor.free} has cleared the handle slot).
   *
   * @internal
   */
  _closed: boolean = false;

  /**
   * Constructs a fresh encryptor.
   *
   * @param primitive Canonical hash name from `listHashes()` —
   *   `"areion256"`, `"areion512"`, `"siphash24"`, `"aescmac"`,
   *   `"blake2b256"`, `"blake2b512"`, `"blake2s"`, `"blake3"`,
   *   `"chacha20"`. Pass an empty string is not accepted — use a
   *   non-empty hash name.
   * @param keyBits ITB key width in bits (512, 1024, 2048; multiple
   *   of the primitive's native hash width).
   * @param macName Canonical MAC name from `listMacs()` —
   *   `"kmac256"`, `"hmac-sha256"`, or `"hmac-blake3"`. Pass `null`
   *   or omit to select the binding default. **Binding-side default
   *   override:** when `macName` is `null`, the binding picks
   *   `"hmac-blake3"` rather than passing NULL through to libitb's
   *   own default. HMAC-BLAKE3 measures the lightest MAC overhead in
   *   the Easy Mode bench surface; routing the default through it
   *   gives the constructor-without-arguments path the lowest cost.
   * @param mode `1` (Single Ouroboros, 3 seeds — noise / data /
   *   start) or `3` (Triple Ouroboros, 7 seeds — noise + 3 pairs of
   *   data / start). The numeric value mirrors the security factor:
   *   Triple's seven-seed split delivers `P × 2^(3×keyBits)` versus
   *   Single's `P × 2^keyBits`. Other values raise
   *   `ITBError(Status.BadInput)` before the FFI call. Defaults to
   *   `1` (Single).
   */
  constructor(
    primitive: string,
    keyBits: number,
    macName: string | null = null,
    mode: number = 1,
  ) {
    const effectiveMac = macName ?? 'hmac-blake3';
    const out: [Handle] = [ZERO];
    const rc = ITB_Easy_New(primitive, keyBits | 0, effectiveMac, mode | 0, out);
    check(rc);
    this._handle = out[0]!;
    encryptorFinalizer.register(this, this._handle, this);
  }

  // ─── Mixed-mode constructors ──────────────────────────────────────

  /**
   * Constructs a Single-Ouroboros Encryptor with per-slot PRF
   * primitive selection.
   *
   * `primN` / `primD` / `primS` cover the noise / data / start slots;
   * `primL` (`null` for off) is the optional dedicated lockSeed
   * primitive — when provided, a 4th seed slot is allocated under
   * that primitive and BitSoup + LockSoup are auto-coupled on the
   * on-direction.
   *
   * All four primitive names must resolve to the same native hash
   * width via the libitb registry; mixed widths surface as
   * {@link ITBError} with the panic message captured in
   * {@link lastError}.
   *
   * **Default MAC override.** Same rule as the primary constructor:
   * when `macName` is `null`, the binding maps it to `"hmac-blake3"`.
   */
  static mixedSingle(
    primN: string,
    primD: string,
    primS: string,
    primL: string | null,
    keyBits: number,
    macName: string | null = null,
  ): Encryptor {
    const effectiveMac = macName ?? 'hmac-blake3';
    const lockArg = primL && primL.length > 0 ? primL : null;
    const out: [Handle] = [ZERO];
    const rc = ITB_Easy_NewMixed(
      primN,
      primD,
      primS,
      lockArg,
      keyBits | 0,
      effectiveMac,
      out,
    );
    check(rc);
    return Encryptor._adopt(out[0]!);
  }

  /**
   * Triple-Ouroboros counterpart of {@link Encryptor.mixedSingle}.
   * Accepts seven per-slot primitive names (noise + 3 data + 3
   * start) plus the optional `primL` lockSeed primitive. See
   * {@link Encryptor.mixedSingle} for the construction contract.
   */
  static mixedTriple(
    primN: string,
    primD1: string,
    primD2: string,
    primD3: string,
    primS1: string,
    primS2: string,
    primS3: string,
    primL: string | null,
    keyBits: number,
    macName: string | null = null,
  ): Encryptor {
    const effectiveMac = macName ?? 'hmac-blake3';
    const lockArg = primL && primL.length > 0 ? primL : null;
    const out: [Handle] = [ZERO];
    const rc = ITB_Easy_NewMixed3(
      primN,
      primD1,
      primD2,
      primD3,
      primS1,
      primS2,
      primS3,
      lockArg,
      keyBits | 0,
      effectiveMac,
      out,
    );
    check(rc);
    return Encryptor._adopt(out[0]!);
  }

  /** @internal */
  private static _adopt(handle: Handle): Encryptor {
    const inst = Object.create(Encryptor.prototype) as Encryptor;
    inst._handle = handle;
    inst._outputCache = null;
    inst._closed = false;
    encryptorFinalizer.register(inst, handle, inst);
    return inst;
  }

  /**
   * Preflight rejection for closed / freed encryptors. Throws
   * `ITBError(Status.EasyClosed)` before any libitb FFI call so
   * callers see the canonical "encryptor has been closed" code
   * regardless of whether the underlying handle slot has merely
   * been zeroed (post-{@link Encryptor.close}) or has been released
   * back to libitb (post-{@link Encryptor.free}).
   *
   * @internal
   */
  private _checkOpen(): void {
    if (this._closed || isZero(this._handle)) {
      throw new ITBError(Status.EasyClosed, 'encryptor has been closed');
    }
  }

  // ─── Per-slot primitive accessors ─────────────────────────────────

  /**
   * Returns the canonical hash primitive name bound to the given
   * seed slot index.
   *
   * Slot ordering is canonical — 0 = noiseSeed, then
   * dataSeed{,1..3}, then startSeed{,1..3}, with the optional
   * dedicated lockSeed at the trailing slot. For single-primitive
   * encryptors every slot returns the same {@link Encryptor.primitive}
   * value; for encryptors built via {@link Encryptor.mixedSingle} /
   * {@link Encryptor.mixedTriple} each slot returns its
   * independently-chosen primitive name.
   */
  primitiveAt(slot: number): string {
    this._checkOpen();
    const handle = this._handle;
    const { rc, value } = readString((buf, cap, outLen) =>
      ITB_Easy_PrimitiveAt(handle, slot | 0, buf, cap, outLen),
    );
    if (rc !== Status.Ok) {
      throw errorFromStatus(rc);
    }
    return value;
  }

  /**
   * `true` when the encryptor was constructed via
   * {@link Encryptor.mixedSingle} or {@link Encryptor.mixedTriple}
   * (per-slot primitive selection); `false` for single-primitive
   * encryptors built via the primary constructor.
   */
  get isMixed(): boolean {
    this._checkOpen();
    const st: [number] = [0];
    const v = ITB_Easy_IsMixed(this._handle, st);
    if (st[0] !== Status.Ok) {
      throw errorFromStatus(st[0]!);
    }
    return v !== 0;
  }

  // ─── Read-only field accessors ────────────────────────────────────

  /**
   * Opaque libitb handle id (uintptr). Useful for diagnostics and
   * FFI-level interop; bindings should not rely on its numerical
   * value.
   */
  get handle(): Handle {
    return this._handle;
  }

  /** Canonical primitive name bound at construction. */
  get primitive(): string {
    this._checkOpen();
    const handle = this._handle;
    const { rc, value } = readString((buf, cap, outLen) =>
      ITB_Easy_Primitive(handle, buf, cap, outLen),
    );
    if (rc !== Status.Ok) {
      throw errorFromStatus(rc);
    }
    return value;
  }

  /** ITB key width in bits. */
  get keyBits(): number {
    this._checkOpen();
    const st: [number] = [0];
    const v = ITB_Easy_KeyBits(this._handle, st);
    if (st[0] !== Status.Ok) {
      throw errorFromStatus(st[0]!);
    }
    return v;
  }

  /** 1 (Single Ouroboros) or 3 (Triple Ouroboros). */
  get mode(): number {
    this._checkOpen();
    const st: [number] = [0];
    const v = ITB_Easy_Mode(this._handle, st);
    if (st[0] !== Status.Ok) {
      throw errorFromStatus(st[0]!);
    }
    return v;
  }

  /** Canonical MAC name bound at construction. */
  get macName(): string {
    this._checkOpen();
    const handle = this._handle;
    const { rc, value } = readString((buf, cap, outLen) =>
      ITB_Easy_MACName(handle, buf, cap, outLen),
    );
    if (rc !== Status.Ok) {
      throw errorFromStatus(rc);
    }
    return value;
  }

  /**
   * Returns the nonce size in bits configured for this encryptor —
   * either the value from the most recent
   * {@link Encryptor.setNonceBits} call, or the process-wide
   * `getNonceBits()` reading at construction time when no
   * per-instance override has been issued. Reads the live
   * `cfg.NonceBits` via `ITB_Easy_NonceBits` so a setter call on the
   * Go side is reflected immediately.
   */
  get nonceBits(): number {
    this._checkOpen();
    const st: [number] = [0];
    const v = ITB_Easy_NonceBits(this._handle, st);
    if (st[0] !== Status.Ok) {
      throw errorFromStatus(st[0]!);
    }
    return v;
  }

  /**
   * Returns the per-instance ciphertext-chunk header size in bytes
   * (nonce + 2-byte width + 2-byte height).
   *
   * Tracks this encryptor's own {@link Encryptor.nonceBits}, NOT the
   * process-wide `headerSize()` reading — important when the
   * encryptor has called {@link Encryptor.setNonceBits} to override
   * the default. Use this when slicing a chunk header off the front
   * of a ciphertext stream produced by this encryptor or when sizing
   * a tamper region for an authenticated-decrypt test.
   */
  get headerSize(): number {
    this._checkOpen();
    const st: [number] = [0];
    const v = ITB_Easy_HeaderSize(this._handle, st);
    if (st[0] !== Status.Ok) {
      throw errorFromStatus(st[0]!);
    }
    return v;
  }

  /**
   * Per-instance counterpart of `parseChunkLen`. Inspects a chunk
   * header (the fixed-size `[nonce(N) || width(2) || height(2)]`
   * prefix where `N` comes from this encryptor's
   * {@link Encryptor.nonceBits}) and returns the total chunk length
   * on the wire.
   *
   * Use this when walking a concatenated chunk stream produced by
   * this encryptor: read {@link Encryptor.headerSize} bytes from the
   * wire, call `enc.parseChunkLen(buf.subarray(0, enc.headerSize))`,
   * read the remaining `chunkLen - headerSize` bytes, and feed the
   * full chunk to {@link Encryptor.decrypt} /
   * {@link Encryptor.decryptAuth}.
   *
   * The buffer must contain at least {@link Encryptor.headerSize}
   * bytes; only the header is consulted, the body bytes do not need
   * to be present. Surfaces `ITBError(Status.BadInput)` on too-short
   * buffer, zero dimensions, or width × height overflow against the
   * container pixel cap.
   */
  parseChunkLen(header: Uint8Array): number {
    this._checkOpen();
    if (!(header instanceof Uint8Array)) {
      throw new TypeError('header must be a Uint8Array');
    }
    const out: [number | bigint] = [0];
    const rc = ITB_Easy_ParseChunkLen(this._handle, header, header.length, out);
    check(rc);
    return Number(out[0]);
  }

  // ─── Cipher entry points ──────────────────────────────────────────

  /**
   * Encrypts plaintext using the encryptor's configured primitive /
   * keyBits / mode and per-instance Config snapshot.
   *
   * Plain mode — does not attach a MAC tag; for authenticated
   * encryption use {@link Encryptor.encryptAuth}.
   */
  encrypt(plaintext: Uint8Array): Uint8Array {
    if (!(plaintext instanceof Uint8Array)) {
      throw new TypeError('plaintext must be a Uint8Array');
    }
    return this._cipherCall(ITB_Easy_Encrypt, plaintext);
  }

  /**
   * Decrypts ciphertext produced by {@link Encryptor.encrypt} under
   * the same encryptor.
   */
  decrypt(ciphertext: Uint8Array): Uint8Array {
    if (!(ciphertext instanceof Uint8Array)) {
      throw new TypeError('ciphertext must be a Uint8Array');
    }
    return this._cipherCall(ITB_Easy_Decrypt, ciphertext);
  }

  /**
   * Encrypts plaintext and attaches a MAC tag using the encryptor's
   * bound MAC closure.
   */
  encryptAuth(plaintext: Uint8Array): Uint8Array {
    if (!(plaintext instanceof Uint8Array)) {
      throw new TypeError('plaintext must be a Uint8Array');
    }
    return this._cipherCall(ITB_Easy_EncryptAuth, plaintext);
  }

  /**
   * Verifies and decrypts ciphertext produced by
   * {@link Encryptor.encryptAuth}. Surfaces
   * `ITBError(Status.MacFailure)` on tampered ciphertext / wrong MAC
   * key.
   */
  decryptAuth(ciphertext: Uint8Array): Uint8Array {
    if (!(ciphertext instanceof Uint8Array)) {
      throw new TypeError('ciphertext must be a Uint8Array');
    }
    return this._cipherCall(ITB_Easy_DecryptAuth, ciphertext);
  }

  // ────────────────────────────────────────────────────────────────
  // Streaming AEAD entry points
  // ────────────────────────────────────────────────────────────────

  /**
   * Reads plaintext from `input` until end-of-stream, encrypts each
   * chunk under the Streaming AEAD construction bound to this
   * encryptor's seeds + MAC closure, and writes the concatenated
   * `streamId || chunk_0 || chunk_1 || ...` transcript to `output`.
   * Neither stream is closed by the helper.
   *
   * `chunkSize` defaults to `DEFAULT_CHUNK_SIZE` (16 MiB) when not
   * supplied; it must be positive. The 32-byte CSPRNG `streamId`
   * prefix is generated server-side per call; the running cumulative
   * pixel offset and the terminating chunk's `finalFlag = true` are
   * managed internally.
   *
   * Empty stream is permitted — emits the 32-byte prefix followed by
   * a single terminating chunk carrying zero plaintext bytes.
   */
  async encryptStreamAuth(
    input: Readable,
    output: Writable,
    chunkSize: number = STREAM_DEFAULT_CHUNK_SIZE,
  ): Promise<void> {
    this._checkOpen();
    if (chunkSize <= 0) {
      throw new ITBError(Status.BadInput, 'chunkSize must be positive');
    }
    const streamId = _generateStreamId();
    output.write(streamId);
    const headerSz = this.headerSize;
    let cumPixels = 0n;
    const buf: Uint8Array[] = [];
    let buffered = 0;
    let eof = false;
    // Fast-path skip: when `buf` holds a single Uint8Array, the
    // merged buffer is byte-identical to `buf[0]` — return the view
    // directly to elide the alloc + memcpy of the slow-path merge.
    // The fresh-allocation slow path is preserved verbatim for
    // multi-part input. The boolean tracks ownership so the wipe-side
    // path skips zeroing caller-provided source views.
    const consumeBuffer = (): { merged: Uint8Array; owned: boolean } => {
      if (buf.length === 1) {
        const merged = buf[0]!;
        buf.length = 0;
        buffered = 0;
        return { merged, owned: false };
      }
      const merged = new Uint8Array(buffered);
      let off = 0;
      for (const p of buf) {
        merged.set(p, off);
        off += p.length;
      }
      buf.length = 0;
      buffered = 0;
      return { merged, owned: true };
    };
    const emit = (pt: Uint8Array, finalFlag: boolean, owned: boolean) => {
      const ct = this._streamAuthEmit(pt, streamId, cumPixels, finalFlag);
      // Wipe the consumed plaintext only when `pt` is owned by the
      // helper (slow-path fresh allocation). On the fast path `pt`
      // is a view into a caller-supplied Uint8Array; zeroing it would
      // corrupt the caller's buffer.
      if (owned) {
        pt.fill(0);
      }
      output.write(ct);
      if (ct.length >= headerSz) {
        const w = (ct[headerSz - 4]! << 8) | ct[headerSz - 3]!;
        const h = (ct[headerSz - 2]! << 8) | ct[headerSz - 1]!;
        cumPixels += BigInt(w) * BigInt(h);
      }
    };
    const iter = input[Symbol.asyncIterator]();
    while (!eof) {
      while (buffered <= chunkSize && !eof) {
        const next = await iter.next();
        if (next.done) {
          eof = true;
          break;
        }
        let chunk = next.value;
        if (typeof chunk === 'string') {
          chunk = new TextEncoder().encode(chunk);
        } else if (!(chunk instanceof Uint8Array)) {
          throw new TypeError(
            'input stream emitted a non-Buffer / non-string chunk');
        }
        buf.push(chunk);
        buffered += chunk.length;
      }
      if (eof) {
        const { merged, owned } = consumeBuffer();
        emit(merged, true, owned);
        break;
      }
      const { merged, owned } = consumeBuffer();
      const chunkPt = merged.subarray(0, chunkSize);
      const tail = merged.subarray(chunkSize);
      emit(chunkPt, false, owned);
      if (tail.length > 0) {
        buf.push(tail);
        buffered += tail.length;
      }
    }
  }

  /**
   * Reads a Streaming AEAD transcript from `input` until end-of-stream
   * and writes the recovered plaintext to `output`. Surfaces
   * `ITBStreamTruncatedError` when the input exhausts without a
   * terminating chunk, `ITBStreamAfterFinalError` when bytes follow
   * the terminator, and `ITBError` with `Status.MacFailure` on any
   * per-chunk MAC mismatch.
   */
  async decryptStreamAuth(input: Readable, output: Writable): Promise<void> {
    this._checkOpen();
    const headerSz = this.headerSize;
    const streamId = new Uint8Array(STREAM_ID_LEN);
    let sidHave = 0;
    const buf: Uint8Array[] = [];
    let buffered = 0;
    let cumPixels = 0n;
    let seenFinal = false;
    const drainComplete = () => {
      while (true) {
        if (seenFinal) {
          if (buffered > 0) {
            throw new ITBStreamAfterFinalError(
              Status.StreamAfterFinal,
              'auth stream: trailing bytes after terminator');
          }
          return;
        }
        if (buffered < headerSz) {
          return;
        }
        // Fast-path skip: single-element buffer is byte-identical to
        // its sole part. Decrypt-side does not run a wipe pass on the
        // merged buffer (per the §7.1 carve-out — `Writable.write`
        // queues the reference until later flush), so the view-vs-copy
        // distinction is safe at every consumer site below.
        let merged: Uint8Array;
        if (buf.length === 1) {
          merged = buf[0]!;
        } else {
          merged = new Uint8Array(buffered);
          let off = 0;
          for (const p of buf) { merged.set(p, off); off += p.length; }
        }
        const chunkLen = this.parseChunkLen(merged.subarray(0, headerSz));
        if (merged.length < chunkLen) {
          buf.length = 0;
          buf.push(merged);
          buffered = merged.length;
          return;
        }
        const w = (merged[headerSz - 4]! << 8) | merged[headerSz - 3]!;
        const h = (merged[headerSz - 2]! << 8) | merged[headerSz - 1]!;
        const pixels = BigInt(w) * BigInt(h);
        const chunk = merged.subarray(0, chunkLen);
        const tail = merged.subarray(chunkLen);
        const { pt, finalFlag } = this._streamAuthConsume(
          chunk, streamId, cumPixels);
        output.write(pt);
        cumPixels += pixels;
        buf.length = 0;
        if (tail.length > 0) {
          buf.push(tail);
          buffered = tail.length;
        } else {
          buffered = 0;
        }
        if (finalFlag) {
          seenFinal = true;
        }
      }
    };
    for await (const raw of input) {
      let chunk: Uint8Array;
      if (raw instanceof Uint8Array) {
        chunk = raw;
      } else if (typeof raw === 'string') {
        chunk = new TextEncoder().encode(raw);
      } else {
        throw new TypeError('input stream emitted a non-Buffer / non-string chunk');
      }
      let off = 0;
      if (sidHave < STREAM_ID_LEN) {
        const need = STREAM_ID_LEN - sidHave;
        const take = Math.min(need, chunk.length);
        streamId.set(chunk.subarray(0, take), sidHave);
        sidHave += take;
        off = take;
      }
      if (off < chunk.length) {
        const tail = chunk.subarray(off);
        buf.push(tail);
        buffered += tail.length;
      }
      if (sidHave === STREAM_ID_LEN) {
        drainComplete();
      }
    }
    if (sidHave < STREAM_ID_LEN) {
      throw new ITBStreamTruncatedError(
        Status.StreamTruncated, 'auth stream: prefix never observed');
    }
    drainComplete();
    if (!seenFinal) {
      throw new ITBStreamTruncatedError(
        Status.StreamTruncated, 'auth stream: terminator never observed');
    }
  }

  /** @internal */
  private _streamAuthEmit(
    plaintext: Uint8Array,
    streamId: Uint8Array,
    cumPixels: bigint,
    finalFlag: boolean,
  ): Uint8Array {
    const ff = finalFlag ? 1 : 0;
    const ptArg = plaintext.length > 0 ? plaintext : new Uint8Array(0);
    // koffi typed-pointer signature for `_Out_ size_t *outLen` accepts a
    // `[number | bigint]` 1-tuple uniformly across the Easy Mode call
    // surface; the wider element type avoids the per-call workaround
    // cast that a strict `[bigint]` declaration would otherwise force.
    const outLen: [number | bigint] = [0n];
    // Formula+retry-once: shares the 1.25× upper bound + 128 KiB
    // headroom shape with `_cipherCall` and the low-level
    // `cipher.ts` / `streams.ts` helpers. The Easy Stream-AEAD ABI
    // shares the "compute-internally-then-return-BUFFER_TOO_SMALL"
    // contract with the Single Message Easy ABI, so probing with a null
    // out-buffer pays the per-chunk crypto twice; pre-allocating from
    // the formula collapses that to one call in the hot path.
    //
    // Reuses the per-encryptor `_outputCache` (Bonus 1 in
    // .NEXTBIND.md §7.1) — same scope as the Single Message
    // `_cipherCall` path — so the streaming hot loop amortises the
    // allocation across every chunk just like the Single Message Easy
    // Mode path does. Returns `_outputCache.slice(...)` (eager copy)
    // so subsequent chunk calls may safely overwrite the cache while
    // the prior chunk's bytes remain queued in the consumer's
    // `Writable`.
    const cache = this._ensureOutputCache(plaintext.length);
    let rc = ITB_Easy_EncryptStreamAuth(
      this._handle as bigint, ptArg, BigInt(plaintext.length),
      streamId, cumPixels, ff,
      cache, BigInt(cache.length), outLen,
    );
    if (rc === Status.BufferTooSmall) {
      const need = Number(outLen[0]);
      this._wipeAndReplaceCache(need);
      const grown = this._outputCache!;
      rc = ITB_Easy_EncryptStreamAuth(
        this._handle as bigint, ptArg, BigInt(plaintext.length),
        streamId, cumPixels, ff,
        grown, BigInt(grown.length), outLen,
      );
    }
    if (rc !== Status.Ok) {
      throw errorFromStatus(rc);
    }
    return this._outputCache!.slice(0, Number(outLen[0]));
  }

  /** @internal */
  private _streamAuthConsume(
    ciphertext: Uint8Array,
    streamId: Uint8Array,
    cumPixels: bigint,
  ): { pt: Uint8Array; finalFlag: boolean } {
    const ctArg = ciphertext.length > 0 ? ciphertext : new Uint8Array(0);
    const outLen: [number | bigint] = [0n];
    const ff: [number] = [0];
    // Decrypt-side plaintext is bounded above by ciphertext length;
    // the same 1.25× + 128 KiB headroom formula covers every libitb
    // sizing. Retry-once is the safety net for any future
    // barrier-fill / nonce-bits combination outside the measured
    // matrix.
    //
    // Reuses the per-encryptor `_outputCache` (Bonus 1 in
    // .NEXTBIND.md §7.1) — same scope as the Single Message
    // `_cipherCall` path. The eager `slice` copy below detaches the
    // returned plaintext from the cache so the next chunk's call may
    // safely overwrite the cache while the prior chunk's bytes remain
    // queued in the consumer's `Writable`.
    const cache = this._ensureOutputCache(ciphertext.length);
    let rc = ITB_Easy_DecryptStreamAuth(
      this._handle as bigint, ctArg, BigInt(ciphertext.length),
      streamId, cumPixels,
      cache, BigInt(cache.length), outLen, ff,
    );
    if (rc === Status.BufferTooSmall) {
      const need = Number(outLen[0]);
      this._wipeAndReplaceCache(need);
      const grown = this._outputCache!;
      rc = ITB_Easy_DecryptStreamAuth(
        this._handle as bigint, ctArg, BigInt(ciphertext.length),
        streamId, cumPixels,
        grown, BigInt(grown.length), outLen, ff,
      );
    }
    if (rc !== Status.Ok) {
      throw errorFromStatus(rc);
    }
    return {
      pt: this._outputCache!.slice(0, Number(outLen[0])),
      finalFlag: ff[0] !== 0,
    };
  }

  /**
   * Direct-call buffer-convention dispatcher with a per-encryptor
   * output cache. Skips the size-probe round-trip the lower-level
   * cipher helpers use: pre-allocates output capacity from a 1.25×
   * upper bound (the empirical ITB ciphertext-expansion factor
   * measured at ≤ 1.155 across every primitive / mode / nonce /
   * payload-size combination) and falls through to an explicit
   * grow-and-retry only on the rare under-shoot. Reuses the buffer
   * across calls; `close` / `free` / `[Symbol.dispose]` wipe it
   * before drop.
   *
   * The current `Easy_Encrypt` / `Easy_Decrypt` C ABI does the full
   * crypto on every call regardless of out-buffer capacity (it
   * computes the result internally, then returns BUFFER_TOO_SMALL
   * without exposing the work) — so the pre-allocation here avoids
   * paying for a duplicate encrypt / decrypt on each Node call.
   *
   * @internal
   */
  private _cipherCall(
    fn: (
      handle: Handle,
      input: Uint8Array,
      inLen: number,
      out: Uint8Array,
      outCap: number,
      outLen: [number | bigint],
    ) => number,
    payload: Uint8Array,
  ): Uint8Array {
    this._checkOpen();
    const payloadLen = payload.length;
    const cache = this._ensureOutputCache(payloadLen);

    const outLen: [number | bigint] = [0];
    let rc = fn(this._handle, payload, payloadLen, cache, cache.length, outLen);
    if (rc === Status.BufferTooSmall) {
      // Pre-allocation was too tight (extremely rare given the 1.25×
      // safety margin) — grow exactly to the required size and retry.
      // The first call already paid for the underlying crypto via the
      // current C ABI's full-encrypt-on-every-call contract, so the
      // retry runs the work again; this is strictly the fallback path
      // and not the hot loop.
      const need = Number(outLen[0]);
      this._wipeAndReplaceCache(need);
      const grown = this._outputCache!;
      rc = fn(this._handle, payload, payloadLen, grown, grown.length, outLen);
    }
    if (rc !== Status.Ok) {
      throw errorFromStatus(rc);
    }
    const written = Number(outLen[0]);
    // Detach the result from the reusable cache via slice — `subarray`
    // would alias and the next cipher call would mutate the previous
    // call's return value.
    return this._outputCache!.slice(0, written);
  }

  /**
   * Lazily allocates the per-encryptor output buffer cache and grows
   * it on demand. The growth threshold is `max(131072, payloadLen ×
   * 5/4 + 131072)` — the 1.25× multiplier plus a 128 KiB headroom
   * that absorbs the residual expansion from non-default
   * barrier-fill values up to 32, where the absolute ratio reaches
   * ~1.346 around the 1 MiB payload region; the 128 KiB constant
   * also acts as the floor for very-small payloads (Triple +
   * auth-MAC + bf=32 at ptlen=1 expands to ~35 KiB).
   *
   * **Wipe-on-grow.** When the cache already exists but is too
   * small, the previous buffer is zeroed before the reference is
   * dropped. Without this step, the previous-call ciphertext /
   * plaintext would linger in heap garbage between cipher calls
   * until GC collects it, which contradicts the
   * wipe-before-drop contract advertised on the cipher methods'
   * documentation.
   *
   * @internal
   */
  private _ensureOutputCache(payloadLen: number): Uint8Array {
    const need = Math.max(131072, Math.floor((payloadLen * 5) / 4) + 131072);
    const current = this._outputCache;
    if (current !== null && current.length >= need) {
      return current;
    }
    this._wipeAndReplaceCache(need);
    return this._outputCache!;
  }

  /**
   * Wipes the existing cache (when present) and replaces it with a
   * fresh zero-initialised buffer of `size` bytes.
   *
   * @internal
   */
  private _wipeAndReplaceCache(size: number): void {
    const old = this._outputCache;
    if (old !== null) {
      old.fill(0);
    }
    this._outputCache = new Uint8Array(size);
  }

  // ─── Per-instance configuration setters ───────────────────────────

  /**
   * Override the nonce size for this encryptor's subsequent encrypt
   * / decrypt calls. Valid values: 128, 256, 512.
   *
   * Mutates only this encryptor's Config copy; process-wide
   * `setNonceBits()` is unaffected. The
   * {@link Encryptor.nonceBits} / {@link Encryptor.headerSize}
   * accessors read through to the live Go-side `cfg.NonceBits`, so
   * they reflect the new value automatically on the next access.
   */
  setNonceBits(n: number): void {
    this._checkOpen();
    check(ITB_Easy_SetNonceBits(this._handle, n | 0));
  }

  /**
   * Override the CSPRNG barrier-fill margin for this encryptor.
   * Valid values: 1, 2, 4, 8, 16, 32. Asymmetric — receiver does not
   * need the same value as sender.
   */
  setBarrierFill(n: number): void {
    this._checkOpen();
    check(ITB_Easy_SetBarrierFill(this._handle, n | 0));
  }

  /**
   * 0 = byte-level split (default); non-zero = bit-level Bit Soup
   * split. **Mode-dependent overlay engagement:** in Single Ouroboros
   * (mode = 1), enabling bit-soup activates the lock-soup overlay at
   * encrypt time even though `cfg.LockSoup` stays 0 (Go-side
   * `splitForSingle` engages overlay if either flag is set). In
   * Triple Ouroboros (mode = 3), bit-soup operates independently of
   * lock-soup.
   */
  setBitSoup(mode: number): void {
    this._checkOpen();
    check(ITB_Easy_SetBitSoup(this._handle, mode | 0));
  }

  /**
   * 0 = off (default); non-zero = on. **Auto-couples `BitSoup=1`** on
   * this encryptor for both Single and Triple Ouroboros — the
   * Go-side `easy/` package (itb/easy/config.go
   * `Encryptor.SetLockSoup`) engages bit-soup unconditionally as a
   * precondition for lock-soup, and the binding faithfully reflects
   * that contract. The overlay-off-while-lockSeed-active guard
   * additionally coerces `mode == 0` to `1` while
   * `setLockSeed(1)` remains active; drop the dedicated lockSeed via
   * `setLockSeed(0)` first to fully disengage.
   */
  setLockSoup(mode: number): void {
    this._checkOpen();
    check(ITB_Easy_SetLockSoup(this._handle, mode | 0));
  }

  /**
   * 0 = off; 1 = on (allocates a dedicated lockSeed and routes the
   * bit-permutation overlay through it; **auto-couples `LockSoup=1`
   * + `BitSoup=1`** on this encryptor). Calling after the first
   * encrypt surfaces `ITBError(Status.EasyLockSeedAfterEncrypt)`.
   */
  setLockSeed(mode: number): void {
    this._checkOpen();
    check(ITB_Easy_SetLockSeed(this._handle, mode | 0));
  }

  /**
   * Per-instance streaming chunk-size override (0 = auto-detect via
   * `itb.ChunkSize` on the Go side).
   */
  setChunkSize(n: number): void {
    this._checkOpen();
    check(ITB_Easy_SetChunkSize(this._handle, n | 0));
  }

  // ─── Material getters (defensive copies) ──────────────────────────

  /**
   * Number of seed slots: 3 (Single without LockSeed),
   * 4 (Single with LockSeed), 7 (Triple without LockSeed),
   * 8 (Triple with LockSeed).
   */
  get seedCount(): number {
    this._checkOpen();
    const st: [number] = [0];
    const v = ITB_Easy_SeedCount(this._handle, st);
    if (st[0] !== Status.Ok) {
      throw errorFromStatus(st[0]!);
    }
    return v;
  }

  /**
   * Returns the uint64 components of one seed slot (defensive copy).
   *
   * Slot index follows the canonical ordering: Single =
   * `[noise, data, start]`; Triple = `[noise, data1, data2, data3,
   * start1, start2, start3]`; the dedicated lockSeed slot, when
   * present, is appended at the trailing index (index 3 for Single,
   * index 7 for Triple). Bindings can consult
   * {@link Encryptor.seedCount} to determine the valid slot range
   * for the active mode + lockSeed configuration.
   */
  seedComponents(slot: number): bigint[] {
    this._checkOpen();
    const probe: [number] = [0];
    let rc = ITB_Easy_SeedComponents(this._handle, slot | 0, null, 0, probe);
    if (rc === Status.Ok) {
      return [];
    }
    if (rc !== Status.BufferTooSmall) {
      throw errorFromStatus(rc);
    }
    const n = probe[0]!;
    const buf = new BigUint64Array(n);
    const filled: [number] = [0];
    rc = ITB_Easy_SeedComponents(this._handle, slot | 0, buf, n, filled);
    if (rc !== Status.Ok) {
      throw errorFromStatus(rc);
    }
    return Array.from(buf.subarray(0, filled[0]!));
  }

  /**
   * `true` when the encryptor's primitive uses fixed PRF keys per
   * seed slot (every shipped primitive except `siphash24`).
   */
  get hasPRFKeys(): boolean {
    this._checkOpen();
    const st: [number] = [0];
    const v = ITB_Easy_HasPRFKeys(this._handle, st);
    if (st[0] !== Status.Ok) {
      throw errorFromStatus(st[0]!);
    }
    return v !== 0;
  }

  /**
   * Returns the fixed PRF key bytes for one seed slot (defensive
   * copy). Surfaces `ITBError(Status.BadInput)` when the primitive
   * has no fixed PRF keys (`siphash24` — caller should consult
   * {@link Encryptor.hasPRFKeys} first) or when `slot` is out of
   * range.
   */
  prfKey(slot: number): Uint8Array {
    this._checkOpen();
    const probe: [number | bigint] = [0];
    let rc = ITB_Easy_PRFKey(this._handle, slot | 0, null, 0, probe);
    // Probe pattern: zero-length key → STATUS_OK + outLen=0
    // (e.g. siphash24); non-zero length → STATUS_BUFFER_TOO_SMALL
    // with outLen carrying the required size. STATUS_BAD_INPUT is
    // reserved for out-of-range slot or no-fixed-key primitive.
    if (rc === Status.Ok && Number(probe[0]) === 0) {
      return new Uint8Array(0);
    }
    if (rc !== Status.BufferTooSmall) {
      throw errorFromStatus(rc);
    }
    const n = Number(probe[0]);
    const buf = new Uint8Array(n);
    const filled: [number | bigint] = [0];
    rc = ITB_Easy_PRFKey(this._handle, slot | 0, buf, n, filled);
    if (rc !== Status.Ok) {
      throw errorFromStatus(rc);
    }
    return buf.subarray(0, Number(filled[0]));
  }

  /**
   * Defensive copy of the encryptor's bound MAC fixed key. Save
   * these bytes alongside the seed material for cross-process
   * restore via {@link Encryptor.exportState} /
   * {@link Encryptor.importState}.
   */
  get macKey(): Uint8Array {
    this._checkOpen();
    const probe: [number | bigint] = [0];
    let rc = ITB_Easy_MACKey(this._handle, null, 0, probe);
    if (rc === Status.Ok && Number(probe[0]) === 0) {
      return new Uint8Array(0);
    }
    if (rc !== Status.BufferTooSmall) {
      throw errorFromStatus(rc);
    }
    const n = Number(probe[0]);
    const buf = new Uint8Array(n);
    const filled: [number | bigint] = [0];
    rc = ITB_Easy_MACKey(this._handle, buf, n, filled);
    if (rc !== Status.Ok) {
      throw errorFromStatus(rc);
    }
    return buf.subarray(0, Number(filled[0]));
  }

  // ─── State serialization ──────────────────────────────────────────

  /**
   * Serialises the encryptor's full state (PRF keys, seed
   * components, MAC key, dedicated lockSeed material when active)
   * as a JSON blob. The caller saves the bytes as it sees fit
   * (disk, KMS, wire) and later passes them back to
   * {@link Encryptor.importState} on a fresh encryptor to
   * reconstruct the exact state.
   *
   * Per-instance configuration knobs (NonceBits, BarrierFill,
   * BitSoup, LockSoup, ChunkSize) are NOT carried in the v1 blob —
   * both sides communicate them via deployment config. LockSeed is
   * carried because activating it changes the structural seed
   * count.
   */
  exportState(): Uint8Array {
    this._checkOpen();
    const probe: [number | bigint] = [0];
    let rc = ITB_Easy_Export(this._handle, null, 0, probe);
    if (rc === Status.Ok) {
      return new Uint8Array(0);
    }
    if (rc !== Status.BufferTooSmall) {
      throw errorFromStatus(rc);
    }
    const need = Number(probe[0]);
    const buf = new Uint8Array(need);
    const filled: [number | bigint] = [0];
    rc = ITB_Easy_Export(this._handle, buf, need, filled);
    if (rc !== Status.Ok) {
      throw errorFromStatus(rc);
    }
    return buf.subarray(0, Number(filled[0]));
  }

  /**
   * Replaces the encryptor's PRF keys, seed components, MAC key,
   * and (optionally) dedicated lockSeed material with the values
   * carried in a JSON blob produced by a prior
   * {@link Encryptor.exportState} call.
   *
   * On any failure the encryptor's pre-import state is unchanged
   * (the underlying Go-side `Encryptor.Import` is transactional).
   * Mismatch on primitive / keyBits / mode / mac surfaces as
   * {@link ITBEasyMismatchError} carrying the offending JSON field
   * name on its `.field` property.
   */
  importState(blob: Uint8Array): void {
    this._checkOpen();
    if (!(blob instanceof Uint8Array)) {
      throw new TypeError('blob must be a Uint8Array');
    }
    const rc = ITB_Easy_Import(this._handle, blob, blob.length);
    check(rc);
  }

  /**
   * Parses a state blob's metadata (primitive, keyBits, mode,
   * macName) without performing full validation, allowing a caller
   * to inspect a saved blob before constructing a matching
   * encryptor.
   *
   * Returns the parsed config on success; surfaces
   * `ITBError(Status.EasyMalformed)` on JSON parse failure / kind
   * mismatch / too-new version / unknown mode value. (The
   * `peekConfig` path does not differentiate too-new-version from
   * malformed framing — use {@link Encryptor.importState} on a
   * suitably-constructed encryptor to discriminate.)
   */
  static peekConfig(blob: Uint8Array): PeekedConfig {
    if (!(blob instanceof Uint8Array)) {
      throw new TypeError('blob must be a Uint8Array');
    }
    // Probe both string sizes first. The size-out-params for the
    // primitive and MAC strings double as in/out — pass a fresh
    // tuple per call.
    const primLen: [number | bigint] = [0];
    const macLen: [number | bigint] = [0];
    const kbOut: [number] = [0];
    const modeOut: [number] = [0];
    let rc = ITB_Easy_PeekConfig(
      blob,
      blob.length,
      null,
      0,
      primLen,
      kbOut,
      modeOut,
      null,
      0,
      macLen,
    );
    if (rc !== Status.Ok && rc !== Status.BufferTooSmall) {
      throw errorFromStatus(rc);
    }
    const primCap = Number(primLen[0]);
    const macCap = Number(macLen[0]);
    const primBuf = new Uint8Array(primCap);
    const macBuf = new Uint8Array(macCap);
    rc = ITB_Easy_PeekConfig(
      blob,
      blob.length,
      primBuf,
      primCap,
      primLen,
      kbOut,
      modeOut,
      macBuf,
      macCap,
      macLen,
    );
    if (rc !== Status.Ok) {
      throw errorFromStatus(rc);
    }
    const primN = Math.max(0, Number(primLen[0]) - 1);
    const macN = Math.max(0, Number(macLen[0]) - 1);
    return {
      primitive: decoder.decode(primBuf.subarray(0, primN)),
      keyBits: kbOut[0]!,
      mode: modeOut[0]!,
      macName: decoder.decode(macBuf.subarray(0, macN)),
    };
  }

  // ─── Lifecycle ────────────────────────────────────────────────────

  /**
   * Zeroes the encryptor's PRF keys, MAC key, and seed components,
   * and marks the encryptor as closed. Idempotent — subsequent
   * {@link Encryptor.close} calls return without raising. Also
   * wipes the per-encryptor output cache so the last ciphertext /
   * plaintext does not linger in heap memory after the encryptor's
   * working set has been zeroed on the Go side.
   *
   * Distinct from {@link Encryptor.free}: `close` zeroes the working
   * set without releasing the libitb handle slot — subsequent calls
   * surface `ITBError(Status.EasyClosed)`. Call `close` to scrub
   * material early when the handle slot must remain in scope (e.g.
   * a long-lived service holding a reference for diagnostic
   * purposes); call `free` (or use `using`) to release the slot in
   * one step.
   */
  close(): void {
    // Wipe the cached output buffer regardless of close state —
    // repeated close calls keep the cache wiped without racing the
    // Go-side close.
    this._wipeOutputCache();
    if (this._closed || isZero(this._handle)) {
      // Idempotent — already closed.
      this._closed = true;
      return;
    }
    const rc = ITB_Easy_Close(this._handle);
    this._closed = true;
    // Close is documented as idempotent on the Go side; treat any
    // non-OK return after close as a bug.
    check(rc);
  }

  /**
   * Releases the underlying libitb handle slot. Wipes the
   * per-encryptor output cache before release (so the last
   * ciphertext / plaintext is zeroed out of heap memory) and then
   * deletes the FFI handle. Subsequent method calls on this
   * instance surface `ITBError(Status.EasyClosed)` — the binding-side
   * preflight in {@link Encryptor._checkOpen} short-circuits the
   * libitb call after the handle slot has been cleared.
   *
   * Idempotent: calling `free` on an already-freed encryptor
   * returns silently.
   */
  free(): void {
    this._wipeOutputCache();
    if (isZero(this._handle)) {
      this._closed = true;
      return;
    }
    const h = this._handle;
    this._handle = ZERO;
    this._closed = true;
    encryptorFinalizer.unregister(this);
    const rc = ITB_Easy_Free(h);
    check(rc);
  }

  /** `using` declaration / explicit-disposal entry point. */
  [Symbol.dispose](): void {
    this.free();
  }

  /**
   * Wipes the per-encryptor output cache in place and releases the
   * reference. Called from `close` and `free` so the last cipher
   * call's bytes are zeroed before the encryptor's working set
   * disappears from this instance.
   *
   * @internal
   */
  private _wipeOutputCache(): void {
    if (this._outputCache !== null) {
      this._outputCache.fill(0);
      this._outputCache = null;
    }
  }
}

/**
 * Module-level alias for `Encryptor.peekConfig`. The static method on
 * `Encryptor` remains the canonical entry point; this free-function
 * alias lets callers inspect a blob's bound configuration without
 * naming the class.
 */
export const peekConfig = Encryptor.peekConfig;
