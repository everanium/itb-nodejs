// File-like streaming wrappers over the Single Message ITB Encrypt /
// Decrypt API.
//
// ITB ciphertexts cap at ~64 MB plaintext per chunk (the underlying
// container size limit). Streaming larger payloads simply means
// slicing the input into chunks at the binding layer, encrypting
// each chunk through the regular FFI path, and concatenating the
// results. The reverse operation walks a concatenated chunk stream
// by reading the chunk header, calling `parseChunkLen` to learn the
// chunk's body length, reading that many bytes, and decrypting the
// single chunk.
//
// Both class-based wrappers (`StreamEncryptor` / `StreamDecryptor`
// and their Triple-Ouroboros counterparts `StreamEncryptorTriple` /
// `StreamDecryptorTriple`) and the convenience helpers
// (`encryptStream` / `decryptStream` plus the Triple variants) are
// provided. Memory peak per call is bounded by `chunkSize` (default
// 16 MiB — see `DEFAULT_CHUNK_SIZE`), regardless of the total
// payload length.
//
// The Triple-Ouroboros (7-seed) variants share the same I/O
// contract and only differ in the seed list passed to the
// constructor.
//
// Threading caveat. Do not call `setNonceBits` between writes on
// the same stream. The chunks are encrypted under the active
// nonce-size at the moment each chunk is flushed; switching
// nonce-bits mid-stream produces a chunk header layout the paired
// decryptor (which snapshots `headerSize` at construction) cannot
// parse.
//
// Lifecycle. Stream wrappers do NOT take ownership of the wrapped
// `Readable` / `Writable`. The caller retains responsibility for
// closing / disposing the wrapped stream after the wrapper is
// itself closed.

import type { Readable, Writable } from 'node:stream';

import {
  decrypt as lowDecrypt,
  decryptTriple as lowDecryptTriple,
  encrypt as lowEncrypt,
  encryptTriple as lowEncryptTriple,
} from './cipher.js';
import {
  ITBError,
  ITBStreamAfterFinalError,
  ITBStreamTruncatedError,
  check,
} from './errors.js';
import { headerSize, parseChunkLen } from './library.js';
import type { MAC as Mac } from './mac.js';
import type { Seed } from './seed.js';
import { Status } from './status.js';
import {
  ITB_DecryptStreamAuthenticated128,
  ITB_DecryptStreamAuthenticated256,
  ITB_DecryptStreamAuthenticated512,
  ITB_DecryptStreamAuthenticated3x128,
  ITB_DecryptStreamAuthenticated3x256,
  ITB_DecryptStreamAuthenticated3x512,
  ITB_EncryptStreamAuthenticated128,
  ITB_EncryptStreamAuthenticated256,
  ITB_EncryptStreamAuthenticated512,
  ITB_EncryptStreamAuthenticated3x128,
  ITB_EncryptStreamAuthenticated3x256,
  ITB_EncryptStreamAuthenticated3x512,
  ITB_FreeSeed,
  ITB_GetSeedHashKey,
  ITB_NewSeedFromComponents,
} from './native.js';

/**
 * Default chunk size — matches `itb.DefaultChunkSize` on the Go
 * side (16 MiB), the size at which ITB's barrier-encoded container
 * layout stays well within the per-chunk pixel cap.
 */
export const DEFAULT_CHUNK_SIZE = 16 * 1024 * 1024;

function asUint8(buf: Uint8Array | Buffer): Uint8Array {
  if (buf instanceof Uint8Array) {
    // Buffer is a Uint8Array subclass; the cast preserves the
    // underlying memory view without an extra copy.
    return buf;
  }
  throw new TypeError('chunk must be a Uint8Array or Buffer');
}

function concatU8(parts: readonly Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// ──────────────────────────────────────────────────────────────────
// Single Ouroboros — chunked writer.
// ──────────────────────────────────────────────────────────────────

/**
 * Chunked encrypt writer over a Single Ouroboros seed trio. Buffers
 * plaintext until at least `chunkSize` bytes are available, then
 * encrypts and emits one chunk to the wrapped output stream. The
 * trailing partial buffer is flushed as a final chunk on `close`,
 * so the on-the-wire chunk count is `ceil(total / chunkSize)`.
 *
 * Usage:
 *
 *     const enc = new StreamEncryptor(noise, data, start, output);
 *     enc.write(chunkA);
 *     enc.write(chunkB);
 *     enc.close();
 *
 * The wrapped `Writable` is NOT ended when this writer is closed;
 * the caller retains ownership of the stream's lifecycle.
 *
 * @remarks
 * The buffer-and-emit state machine is not safe to invoke
 * concurrently from multiple call sites. Sharing one
 * `StreamEncryptor` across async tasks requires external
 * serialisation.
 */
export class StreamEncryptor {
  private readonly noise: Seed;
  private readonly data: Seed;
  private readonly start: Seed;
  private readonly output: Writable;
  private readonly chunkSize: number;
  private buf: Uint8Array[] = [];
  private buffered = 0;
  private closed = false;

  constructor(
    noise: Seed,
    data: Seed,
    start: Seed,
    output: Writable,
    chunkSize: number = DEFAULT_CHUNK_SIZE,
  ) {
    if (chunkSize <= 0) {
      throw new ITBError(Status.BadInput, 'chunkSize must be positive');
    }
    this.noise = noise;
    this.data = data;
    this.start = start;
    this.output = output;
    this.chunkSize = chunkSize;
  }

  /**
   * Appends `data` to the internal buffer, encrypting and emitting
   * every full `chunkSize`-sized slice that becomes available.
   * Returns the number of bytes consumed (always equal to
   * `data.length` on success).
   */
  write(data: Uint8Array | Buffer): number {
    if (this.closed) {
      throw new ITBError(Status.EasyClosed, 'write on closed StreamEncryptor');
    }
    const view = asUint8(data);
    this.buf.push(view);
    this.buffered += view.length;
    while (this.buffered >= this.chunkSize) {
      const merged = concatU8(this.buf, this.buffered);
      const chunk = merged.subarray(0, this.chunkSize);
      const tail = merged.subarray(this.chunkSize);
      const ct = lowEncrypt(this.noise, this.data, this.start, chunk);
      this.output.write(ct);
      // Zero the consumed plaintext slice in the shared backing
      // buffer; the tail subarray covers a disjoint range and is
      // unaffected.
      chunk.fill(0);
      this.buf = tail.length > 0 ? [tail] : [];
      this.buffered = tail.length;
    }
    return view.length;
  }

  /**
   * Encrypts and emits any remaining buffered bytes as the final
   * chunk. Idempotent — a second call is a no-op.
   */
  close(): void {
    if (this.closed) {
      return;
    }
    if (this.buffered > 0) {
      const merged = concatU8(this.buf, this.buffered);
      const ct = lowEncrypt(this.noise, this.data, this.start, merged);
      this.output.write(ct);
      merged.fill(0);
      this.buf = [];
      this.buffered = 0;
    }
    this.closed = true;
  }

  [Symbol.dispose](): void {
    this.close();
  }
}

// ──────────────────────────────────────────────────────────────────
// Single Ouroboros — chunked reader.
// ──────────────────────────────────────────────────────────────────

/**
 * Chunked decrypt writer: accumulates ciphertext bytes via `feed`
 * until a full chunk (header + body) is available, then decrypts
 * the chunk and writes the plaintext to the output sink. Multiple
 * full chunks in one feed call are processed sequentially.
 *
 * Usage:
 *
 *     const dec = new StreamDecryptor(noise, data, start, output);
 *     dec.feed(ciphertextPart1);
 *     dec.feed(ciphertextPart2);
 *     dec.close();
 *
 * The wrapped `Writable` is NOT ended when this reader is closed;
 * the caller retains ownership of the stream's lifecycle.
 */
export class StreamDecryptor {
  private readonly noise: Seed;
  private readonly data: Seed;
  private readonly start: Seed;
  private readonly output: Writable;
  private buf: Uint8Array[] = [];
  private buffered = 0;
  private closed = false;
  private readonly headerSize: number;

  constructor(noise: Seed, data: Seed, start: Seed, output: Writable) {
    this.noise = noise;
    this.data = data;
    this.start = start;
    this.output = output;
    // Snapshot at construction so the decryptor uses the same
    // header layout the matching encryptor saw. Changing
    // setNonceBits mid-stream would break decoding anyway.
    this.headerSize = headerSize();
  }

  /**
   * Appends `data` to the internal buffer and drains every
   * complete chunk that has become available, writing decrypted
   * plaintext to the output sink.
   */
  feed(data: Uint8Array | Buffer): number {
    if (this.closed) {
      throw new ITBError(Status.EasyClosed, 'feed on closed StreamDecryptor');
    }
    const view = asUint8(data);
    this.buf.push(view);
    this.buffered += view.length;
    this.drain();
    return view.length;
  }

  private drain(): void {
    for (;;) {
      if (this.buffered < this.headerSize) {
        return;
      }
      const merged = concatU8(this.buf, this.buffered);
      const chunkLen = parseChunkLen(merged.subarray(0, this.headerSize));
      if (merged.length < chunkLen) {
        // Re-pack as one contiguous buffer so the next iteration
        // does not pay the concat cost again.
        this.buf = [merged];
        this.buffered = merged.length;
        return;
      }
      const chunk = merged.subarray(0, chunkLen);
      const tail = merged.subarray(chunkLen);
      const pt = lowDecrypt(this.noise, this.data, this.start, chunk);
      this.output.write(pt);
      this.buf = tail.length > 0 ? [tail] : [];
      this.buffered = tail.length;
    }
  }

  /**
   * Finalises the decryptor. Throws when leftover bytes do not
   * form a complete chunk — streaming ITB ciphertext cannot have
   * a half-chunk tail.
   */
  close(): void {
    if (this.closed) {
      return;
    }
    if (this.buffered > 0) {
      const trailing = this.buffered;
      this.buf = [];
      this.buffered = 0;
      this.closed = true;
      throw new ITBError(
        Status.BadInput,
        `StreamDecryptor: trailing ${trailing} bytes do not form a complete chunk`,
      );
    }
    this.closed = true;
  }

  [Symbol.dispose](): void {
    // Mark closed without raising on partial input — `Symbol.dispose`
    // is invoked unconditionally by `using` declarations and has no
    // path to surface a half-chunk tail through the ergonomic exit.
    // Callers that need to detect a half-chunk tail must call
    // `close()` explicitly.
    this.closed = true;
  }
}

// ──────────────────────────────────────────────────────────────────
// Triple Ouroboros — chunked writer.
// ──────────────────────────────────────────────────────────────────

/**
 * Triple-Ouroboros (7-seed) counterpart of `StreamEncryptor`.
 *
 * @remarks
 * Same threading caveat as `StreamEncryptor` — do not call
 * `setNonceBits` between writes on the same stream.
 */
export class StreamEncryptorTriple {
  private readonly noise: Seed;
  private readonly data1: Seed;
  private readonly data2: Seed;
  private readonly data3: Seed;
  private readonly start1: Seed;
  private readonly start2: Seed;
  private readonly start3: Seed;
  private readonly output: Writable;
  private readonly chunkSize: number;
  private buf: Uint8Array[] = [];
  private buffered = 0;
  private closed = false;

  constructor(
    noise: Seed,
    data1: Seed,
    data2: Seed,
    data3: Seed,
    start1: Seed,
    start2: Seed,
    start3: Seed,
    output: Writable,
    chunkSize: number = DEFAULT_CHUNK_SIZE,
  ) {
    if (chunkSize <= 0) {
      throw new ITBError(Status.BadInput, 'chunkSize must be positive');
    }
    this.noise = noise;
    this.data1 = data1;
    this.data2 = data2;
    this.data3 = data3;
    this.start1 = start1;
    this.start2 = start2;
    this.start3 = start3;
    this.output = output;
    this.chunkSize = chunkSize;
  }

  write(data: Uint8Array | Buffer): number {
    if (this.closed) {
      throw new ITBError(Status.EasyClosed, 'write on closed StreamEncryptorTriple');
    }
    const view = asUint8(data);
    this.buf.push(view);
    this.buffered += view.length;
    while (this.buffered >= this.chunkSize) {
      const merged = concatU8(this.buf, this.buffered);
      const chunk = merged.subarray(0, this.chunkSize);
      const tail = merged.subarray(this.chunkSize);
      const ct = lowEncryptTriple(
        this.noise,
        this.data1,
        this.data2,
        this.data3,
        this.start1,
        this.start2,
        this.start3,
        chunk,
      );
      this.output.write(ct);
      chunk.fill(0);
      this.buf = tail.length > 0 ? [tail] : [];
      this.buffered = tail.length;
    }
    return view.length;
  }

  close(): void {
    if (this.closed) {
      return;
    }
    if (this.buffered > 0) {
      const merged = concatU8(this.buf, this.buffered);
      const ct = lowEncryptTriple(
        this.noise,
        this.data1,
        this.data2,
        this.data3,
        this.start1,
        this.start2,
        this.start3,
        merged,
      );
      this.output.write(ct);
      merged.fill(0);
      this.buf = [];
      this.buffered = 0;
    }
    this.closed = true;
  }

  [Symbol.dispose](): void {
    this.close();
  }
}

// ──────────────────────────────────────────────────────────────────
// Triple Ouroboros — chunked reader.
// ──────────────────────────────────────────────────────────────────

/**
 * Triple-Ouroboros (7-seed) counterpart of `StreamDecryptor`.
 */
export class StreamDecryptorTriple {
  private readonly noise: Seed;
  private readonly data1: Seed;
  private readonly data2: Seed;
  private readonly data3: Seed;
  private readonly start1: Seed;
  private readonly start2: Seed;
  private readonly start3: Seed;
  private readonly output: Writable;
  private buf: Uint8Array[] = [];
  private buffered = 0;
  private closed = false;
  private readonly headerSize: number;

  constructor(
    noise: Seed,
    data1: Seed,
    data2: Seed,
    data3: Seed,
    start1: Seed,
    start2: Seed,
    start3: Seed,
    output: Writable,
  ) {
    this.noise = noise;
    this.data1 = data1;
    this.data2 = data2;
    this.data3 = data3;
    this.start1 = start1;
    this.start2 = start2;
    this.start3 = start3;
    this.output = output;
    this.headerSize = headerSize();
  }

  feed(data: Uint8Array | Buffer): number {
    if (this.closed) {
      throw new ITBError(Status.EasyClosed, 'feed on closed StreamDecryptorTriple');
    }
    const view = asUint8(data);
    this.buf.push(view);
    this.buffered += view.length;
    this.drain();
    return view.length;
  }

  private drain(): void {
    for (;;) {
      if (this.buffered < this.headerSize) {
        return;
      }
      const merged = concatU8(this.buf, this.buffered);
      const chunkLen = parseChunkLen(merged.subarray(0, this.headerSize));
      if (merged.length < chunkLen) {
        this.buf = [merged];
        this.buffered = merged.length;
        return;
      }
      const chunk = merged.subarray(0, chunkLen);
      const tail = merged.subarray(chunkLen);
      const pt = lowDecryptTriple(
        this.noise,
        this.data1,
        this.data2,
        this.data3,
        this.start1,
        this.start2,
        this.start3,
        chunk,
      );
      this.output.write(pt);
      this.buf = tail.length > 0 ? [tail] : [];
      this.buffered = tail.length;
    }
  }

  close(): void {
    if (this.closed) {
      return;
    }
    if (this.buffered > 0) {
      const trailing = this.buffered;
      this.buf = [];
      this.buffered = 0;
      this.closed = true;
      throw new ITBError(
        Status.BadInput,
        `StreamDecryptorTriple: trailing ${trailing} bytes do not form a complete chunk`,
      );
    }
    this.closed = true;
  }

  [Symbol.dispose](): void {
    this.closed = true;
  }
}

// ──────────────────────────────────────────────────────────────────
// Functional convenience wrappers.
// ──────────────────────────────────────────────────────────────────

async function* iterateReadable(
  input: Readable,
): AsyncGenerator<Uint8Array, void, void> {
  for await (const chunk of input) {
    if (chunk instanceof Uint8Array) {
      yield chunk;
    } else if (typeof chunk === 'string') {
      yield new TextEncoder().encode(chunk);
    } else {
      const kind: string = chunk == null
        ? String(chunk)
        : ((chunk as { constructor?: { name?: string } })?.constructor?.name ?? typeof chunk);
      throw new TypeError(
        `input stream emitted a non-Buffer / non-string chunk (got ${kind}); ` +
          'streams in object-mode are not supported',
      );
    }
  }
}

/**
 * Reads plaintext from `input` until end-of-stream, encrypts in
 * chunks of `chunkSize`, and writes concatenated ITB chunks to
 * `output`. The wrapped streams are NOT closed by the helper —
 * lifecycle ownership stays with the caller.
 *
 * Error semantics on the upstream-failure path. When `input` errors
 * mid-pipeline, the catch arm flushes the buffered partial chunk
 * (via `enc.close()`) before re-raising the original error. The
 * `output` may therefore receive one final partial-plaintext chunk
 * representing data that was already drawn from `input` but did
 * not span the full `chunkSize`. The original error is preserved
 * (encoder-side `close()` is non-throwing); the trailing chunk is
 * a behavioural quirk of the cleanup path, valid ITB ciphertext
 * but representing truncated plaintext on subsequent decrypt.
 */
export async function encryptStream(
  noise: Seed,
  data: Seed,
  start: Seed,
  input: Readable,
  output: Writable,
  chunkSize: number = DEFAULT_CHUNK_SIZE,
): Promise<void> {
  const enc = new StreamEncryptor(noise, data, start, output, chunkSize);
  try {
    for await (const chunk of iterateReadable(input)) {
      enc.write(chunk);
    }
    enc.close();
  } catch (err) {
    enc.close();
    throw err;
  }
}

/**
 * Reads concatenated ITB chunks from `input` until end-of-stream
 * and writes the recovered plaintext to `output`. Throws when the
 * trailing input does not form a complete chunk.
 */
export async function decryptStream(
  noise: Seed,
  data: Seed,
  start: Seed,
  input: Readable,
  output: Writable,
): Promise<void> {
  const dec = new StreamDecryptor(noise, data, start, output);
  try {
    for await (const chunk of iterateReadable(input)) {
      dec.feed(chunk);
    }
    dec.close();
  } catch (err) {
    // Symbol.dispose silently absorbs a trailing-bytes condition by
    // design (the underlying error is what the caller cares about);
    // calling close() in the catch would re-raise the trailing-bytes
    // error and mask the original failure.
    dec[Symbol.dispose]();
    throw err;
  }
}

/**
 * Triple-Ouroboros (7-seed) counterpart of `encryptStream`.
 */
export async function encryptStreamTriple(
  noise: Seed,
  data1: Seed,
  data2: Seed,
  data3: Seed,
  start1: Seed,
  start2: Seed,
  start3: Seed,
  input: Readable,
  output: Writable,
  chunkSize: number = DEFAULT_CHUNK_SIZE,
): Promise<void> {
  const enc = new StreamEncryptorTriple(
    noise, data1, data2, data3, start1, start2, start3, output, chunkSize,
  );
  try {
    for await (const chunk of iterateReadable(input)) {
      enc.write(chunk);
    }
    enc.close();
  } catch (err) {
    enc.close();
    throw err;
  }
}

/**
 * Triple-Ouroboros (7-seed) counterpart of `decryptStream`.
 */
export async function decryptStreamTriple(
  noise: Seed,
  data1: Seed,
  data2: Seed,
  data3: Seed,
  start1: Seed,
  start2: Seed,
  start3: Seed,
  input: Readable,
  output: Writable,
): Promise<void> {
  const dec = new StreamDecryptorTriple(
    noise, data1, data2, data3, start1, start2, start3, output,
  );
  try {
    for await (const chunk of iterateReadable(input)) {
      dec.feed(chunk);
    }
    dec.close();
  } catch (err) {
    // See decryptStream — Symbol.dispose absorbs trailing-bytes;
    // close() would mask the upstream failure.
    dec[Symbol.dispose]();
    throw err;
  }
}

// ──────────────────────────────────────────────────────────────────
// Authenticated streaming (Streaming AEAD)
// ──────────────────────────────────────────────────────────────────
//
// Streaming AEAD wrappers built on top of the per-chunk
// ITB_*StreamAuthenticated* ABI exports. The on-wire transcript
// carries a 32-byte CSPRNG `streamId` prefix once at stream start,
// followed by a sequence of authenticated chunks each bound to the
// running `(streamId, cumulativePixelOffset, finalFlag)` tuple
// inside the MAC closure.
//
// Failure surfaces:
//
//   - Chunk reorder / replay / cross-stream replay → `ITBError` with
//     `Status.MacFailure`.
//   - Incomplete 32-byte stream-id prefix at `close()` → `ITBError`
//     with `Status.BadInput` (wire-level malformation).
//   - Truncate-tail (drop terminating chunk after a fully observed
//     prefix) → `ITBStreamTruncatedError`.
//   - Extra bytes past the terminating chunk →
//     `ITBStreamAfterFinalError`.
//   - Stream-prefix tamper → `ITBError` with `Status.MacFailure` on
//     chunk 0.
//
// The MAC handle (one per stream, allocated via `Mac`) is reused
// across every chunk; the helper does not free it. Closed-state
// preflight surfaces `Status.EasyClosed` on any post-close call.
//
// Sync-only FFI: koffi.lib.func() blocks the V8 main thread for the
// duration of every per-chunk call, so `FinalizationRegistry` cannot
// fire mid-FFI. The wrappers retain Seed / Mac references on
// instance fields throughout the streaming lifetime; no explicit
// `keepAlive` is required.

export const STREAM_ID_LEN = 32;

/**
 * Generates a CSPRNG-fresh 32-byte Streaming AEAD anchor by
 * piggybacking on libitb's own CSPRNG. Mirrors the C reference
 * helper `generate_stream_id` in `bindings/c/src/streams.c`.
 *
 * @internal exported so the Encryptor's Streaming AEAD methods can
 * reuse the same CSPRNG-anchor logic without duplication.
 */
export function generateStreamId(): Uint8Array {
  const comps = new BigUint64Array([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n]);
  const handleOut: [bigint] = [0n];
  let rc = ITB_NewSeedFromComponents(
    'blake3',
    new Uint8Array(comps.buffer, comps.byteOffset, comps.byteLength),
    8,
    null,
    0,
    handleOut,
  );
  check(rc);
  const handle = handleOut[0];
  const out = new Uint8Array(STREAM_ID_LEN);
  const outLen: [bigint] = [0n];
  rc = ITB_GetSeedHashKey(handle, out, BigInt(STREAM_ID_LEN), outLen);
  const freeRc = ITB_FreeSeed(handle);
  check(rc);
  check(freeRc);
  if (Number(outLen[0]) !== STREAM_ID_LEN) {
    throw new ITBError(Status.Internal,
      'streamId CSPRNG draw returned wrong byte count');
  }
  return out;
}

function readBe16(buf: Uint8Array, off: number): number {
  return (buf[off]! << 8) | buf[off + 1]!;
}

// Pre-allocation formula shared with `Encryptor._cipherCall` and
// `cipher.ts`: 1.25× upper bound + 128 KiB headroom that absorbs the
// barrier-fill expansion (up to bf=32, ~1.346 absolute ratio at the
// 1 MiB region) plus the small-payload Triple+auth-MAC fixed overhead
// (Triple Ouroboros + auth-MAC + bf=32 at ptlen=1 expands to ~35 KiB).
// Replaces the probe-then-write pattern that paid the full crypto
// twice per chunk through the Stream-AEAD ABI's
// "compute-internally-then-return-BUFFER_TOO_SMALL" contract.
function preallocStreamCap(payloadLen: number): number {
  return Math.max(131072, Math.floor((payloadLen * 5) / 4) + 131072);
}

/**
 * Per-stream output buffer cache for the Streaming AEAD per-chunk
 * dispatchers. Mirrors the per-encryptor `_outputCache` field on
 * {@link Encryptor} but lives on the streaming class instance —
 * Bonus 1b in .NEXTBIND.md §7.1. The cache grows on demand with the
 * same wipe-on-grow + 1.25× + 128 KiB envelope shape as
 * `Encryptor._cipherCall`.
 *
 * The class is not thread-safe; each
 * {@link StreamEncryptorAuth} / {@link StreamDecryptorAuth} instance
 * (Single + Triple) owns one cache, and a streaming class instance
 * is single-writer / single-feeder by construction.
 *
 * @internal
 */
interface StreamAuthCache {
  buf: Uint8Array | null;
}

/**
 * Grow-on-demand + wipe-on-grow helper for {@link StreamAuthCache}.
 * Mirrors `Encryptor._wipeAndReplaceCache`'s shape: zeroes the OLD
 * contents before reassigning so the previous-chunk ciphertext /
 * plaintext does not linger in heap garbage waiting for V8 GC.
 *
 * @internal
 */
function ensureStreamCache(cache: StreamAuthCache, need: number): Uint8Array {
  const current = cache.buf;
  if (current !== null && current.length >= need) {
    return current;
  }
  if (current !== null) {
    current.fill(0);
  }
  cache.buf = new Uint8Array(need);
  return cache.buf;
}

function emitChunkAuthSingle(
  width: number,
  noise: Seed, data: Seed, start: Seed, mac: Mac,
  plaintext: Uint8Array,
  streamId: Uint8Array,
  cumPixels: bigint,
  finalFlag: boolean,
  cache?: StreamAuthCache,
): Uint8Array {
  const fn = ((): typeof ITB_EncryptStreamAuthenticated128 => {
    switch (width) {
      case 128: return ITB_EncryptStreamAuthenticated128;
      case 256: return ITB_EncryptStreamAuthenticated256;
      case 512: return ITB_EncryptStreamAuthenticated512;
      default:
        throw new ITBError(Status.SeedWidthMix,
          `unsupported native hash width ${width}`);
    }
  })();
  const ff = finalFlag ? 1 : 0;
  const ptArg = plaintext.length > 0 ? plaintext : new Uint8Array(0);
  const outLen: [bigint] = [0n];
  const cap = preallocStreamCap(plaintext.length);
  // When `cache` is provided (object-based stream class call sites),
  // the per-stream buffer is reused instead of allocating a fresh
  // Uint8Array per chunk (Bonus 1b in .NEXTBIND.md §7.1). When
  // omitted, falls back to the per-call allocation — preserves any
  // forward-compatibility call site that has no stream-class cache
  // to attach.
  let buf = cache !== undefined
    ? ensureStreamCache(cache, cap)
    : new Uint8Array(cap);
  let rc = fn(
    noise.handle as bigint, data.handle as bigint, start.handle as bigint,
    mac.handle as bigint,
    ptArg, BigInt(plaintext.length),
    streamId, cumPixels, ff,
    buf, BigInt(buf.length), outLen,
  );
  if (rc === Status.BufferTooSmall) {
    const need = Number(outLen[0]);
    buf = cache !== undefined
      ? ensureStreamCache(cache, need)
      : new Uint8Array(need);
    rc = fn(
      noise.handle as bigint, data.handle as bigint, start.handle as bigint,
      mac.handle as bigint,
      ptArg, BigInt(plaintext.length),
      streamId, cumPixels, ff,
      buf, BigInt(buf.length), outLen,
    );
  }
  check(rc);
  // Eager `slice` copy when routing through the per-stream cache: the
  // returned bytes detach from the cache so the next chunk's call may
  // safely overwrite the cache while the prior chunk's bytes remain
  // queued in the consumer's `Writable`.
  const written = Number(outLen[0]);
  return cache !== undefined ? buf.slice(0, written) : buf.subarray(0, written);
}

function emitChunkAuthTriple(
  width: number,
  noise: Seed,
  data1: Seed, data2: Seed, data3: Seed,
  start1: Seed, start2: Seed, start3: Seed,
  mac: Mac,
  plaintext: Uint8Array,
  streamId: Uint8Array,
  cumPixels: bigint,
  finalFlag: boolean,
  cache?: StreamAuthCache,
): Uint8Array {
  const fn = ((): typeof ITB_EncryptStreamAuthenticated3x128 => {
    switch (width) {
      case 128: return ITB_EncryptStreamAuthenticated3x128;
      case 256: return ITB_EncryptStreamAuthenticated3x256;
      case 512: return ITB_EncryptStreamAuthenticated3x512;
      default:
        throw new ITBError(Status.SeedWidthMix,
          `unsupported native hash width ${width}`);
    }
  })();
  const ff = finalFlag ? 1 : 0;
  const ptArg = plaintext.length > 0 ? plaintext : new Uint8Array(0);
  const outLen: [bigint] = [0n];
  const cap = preallocStreamCap(plaintext.length);
  // See `emitChunkAuthSingle` for the cache-routing rationale.
  let buf = cache !== undefined
    ? ensureStreamCache(cache, cap)
    : new Uint8Array(cap);
  let rc = fn(
    noise.handle as bigint,
    data1.handle as bigint, data2.handle as bigint, data3.handle as bigint,
    start1.handle as bigint, start2.handle as bigint, start3.handle as bigint,
    mac.handle as bigint,
    ptArg, BigInt(plaintext.length),
    streamId, cumPixels, ff,
    buf, BigInt(buf.length), outLen,
  );
  if (rc === Status.BufferTooSmall) {
    const need = Number(outLen[0]);
    buf = cache !== undefined
      ? ensureStreamCache(cache, need)
      : new Uint8Array(need);
    rc = fn(
      noise.handle as bigint,
      data1.handle as bigint, data2.handle as bigint, data3.handle as bigint,
      start1.handle as bigint, start2.handle as bigint, start3.handle as bigint,
      mac.handle as bigint,
      ptArg, BigInt(plaintext.length),
      streamId, cumPixels, ff,
      buf, BigInt(buf.length), outLen,
    );
  }
  check(rc);
  const written = Number(outLen[0]);
  return cache !== undefined ? buf.slice(0, written) : buf.subarray(0, written);
}

function consumeChunkAuthSingle(
  width: number,
  noise: Seed, data: Seed, start: Seed, mac: Mac,
  ciphertext: Uint8Array,
  streamId: Uint8Array,
  cumPixels: bigint,
  cache?: StreamAuthCache,
): { pt: Uint8Array; finalFlag: boolean } {
  const fn = ((): typeof ITB_DecryptStreamAuthenticated128 => {
    switch (width) {
      case 128: return ITB_DecryptStreamAuthenticated128;
      case 256: return ITB_DecryptStreamAuthenticated256;
      case 512: return ITB_DecryptStreamAuthenticated512;
      default:
        throw new ITBError(Status.SeedWidthMix,
          `unsupported native hash width ${width}`);
    }
  })();
  const ctArg = ciphertext.length > 0 ? ciphertext : new Uint8Array(0);
  const outLen: [bigint] = [0n];
  const ff: [number] = [0];
  // Decrypt-side plaintext is bounded above by ciphertext length, so
  // the same 1.25× + 128 KiB headroom formula comfortably covers
  // every container sizing from libitb. Retry-once is the safety net.
  // See `emitChunkAuthSingle` for the cache-routing rationale.
  const cap = preallocStreamCap(ciphertext.length);
  let buf = cache !== undefined
    ? ensureStreamCache(cache, cap)
    : new Uint8Array(cap);
  let rc = fn(
    noise.handle as bigint, data.handle as bigint, start.handle as bigint,
    mac.handle as bigint,
    ctArg, BigInt(ciphertext.length),
    streamId, cumPixels,
    buf, BigInt(buf.length), outLen, ff,
  );
  if (rc === Status.BufferTooSmall) {
    const need = Number(outLen[0]);
    buf = cache !== undefined
      ? ensureStreamCache(cache, need)
      : new Uint8Array(need);
    rc = fn(
      noise.handle as bigint, data.handle as bigint, start.handle as bigint,
      mac.handle as bigint,
      ctArg, BigInt(ciphertext.length),
      streamId, cumPixels,
      buf, BigInt(buf.length), outLen, ff,
    );
  }
  check(rc);
  const written = Number(outLen[0]);
  // Eager `slice` copy when routing through the per-stream cache: the
  // returned plaintext detaches from the cache so the next chunk's
  // call may safely overwrite the cache while the prior chunk's
  // bytes remain queued in the consumer's `Writable` (the §7.1
  // carve-out: `Writable.write` queues the reference until later
  // flush — overwriting cache bytes mid-queue would corrupt the
  // queued chunk).
  return {
    pt: cache !== undefined ? buf.slice(0, written) : buf.subarray(0, written),
    finalFlag: ff[0] !== 0,
  };
}

function consumeChunkAuthTriple(
  width: number,
  noise: Seed,
  data1: Seed, data2: Seed, data3: Seed,
  start1: Seed, start2: Seed, start3: Seed,
  mac: Mac,
  ciphertext: Uint8Array,
  streamId: Uint8Array,
  cumPixels: bigint,
  cache?: StreamAuthCache,
): { pt: Uint8Array; finalFlag: boolean } {
  const fn = ((): typeof ITB_DecryptStreamAuthenticated3x128 => {
    switch (width) {
      case 128: return ITB_DecryptStreamAuthenticated3x128;
      case 256: return ITB_DecryptStreamAuthenticated3x256;
      case 512: return ITB_DecryptStreamAuthenticated3x512;
      default:
        throw new ITBError(Status.SeedWidthMix,
          `unsupported native hash width ${width}`);
    }
  })();
  const ctArg = ciphertext.length > 0 ? ciphertext : new Uint8Array(0);
  const outLen: [bigint] = [0n];
  const ff: [number] = [0];
  // See `emitChunkAuthSingle` and `consumeChunkAuthSingle` for the
  // cache-routing rationale.
  const cap = preallocStreamCap(ciphertext.length);
  let buf = cache !== undefined
    ? ensureStreamCache(cache, cap)
    : new Uint8Array(cap);
  let rc = fn(
    noise.handle as bigint,
    data1.handle as bigint, data2.handle as bigint, data3.handle as bigint,
    start1.handle as bigint, start2.handle as bigint, start3.handle as bigint,
    mac.handle as bigint,
    ctArg, BigInt(ciphertext.length),
    streamId, cumPixels,
    buf, BigInt(buf.length), outLen, ff,
  );
  if (rc === Status.BufferTooSmall) {
    const need = Number(outLen[0]);
    buf = cache !== undefined
      ? ensureStreamCache(cache, need)
      : new Uint8Array(need);
    rc = fn(
      noise.handle as bigint,
      data1.handle as bigint, data2.handle as bigint, data3.handle as bigint,
      start1.handle as bigint, start2.handle as bigint, start3.handle as bigint,
      mac.handle as bigint,
      ctArg, BigInt(ciphertext.length),
      streamId, cumPixels,
      buf, BigInt(buf.length), outLen, ff,
    );
  }
  check(rc);
  const written = Number(outLen[0]);
  return {
    pt: cache !== undefined ? buf.slice(0, written) : buf.subarray(0, written),
    finalFlag: ff[0] !== 0,
  };
}

/**
 * Authenticated chunked-encrypt writer (Single Ouroboros + MAC).
 * Buffers plaintext until at least `chunkSize` bytes are available,
 * then drains one full chunk per FFI call. Each chunk is bound to
 * the running `(streamId, cumulativePixelOffset, finalFlag)` tuple
 * inside the MAC closure. The 32-byte CSPRNG `streamId` prefix is
 * generated at construction and emitted on the first `write` /
 * `close` call.
 */
export class StreamEncryptorAuth {
  private readonly noise: Seed;
  private readonly data: Seed;
  private readonly start: Seed;
  private readonly mac: Mac;
  private readonly output: Writable;
  private readonly chunkSize: number;
  private readonly width: number;
  private readonly headerSize: number;
  private readonly streamId: Uint8Array;
  private buf: Uint8Array[] = [];
  private buffered = 0;
  private cumPixels = 0n;
  private closed = false;
  private prefixEmitted = false;
  /**
   * Per-stream output buffer cache. Grows on demand; `close` /
   * `[Symbol.dispose]` wipe it before drop. Same Bonus 1b shape as
   * the per-encryptor `_outputCache` on {@link Encryptor} — the
   * streaming class owns its own cache because the
   * {@link emitChunkAuthSingle} helper has no encryptor instance to
   * attach to (.NEXTBIND.md §7.1).
   *
   * @internal
   */
  private _outBuf: StreamAuthCache = { buf: null };

  constructor(
    noise: Seed,
    data: Seed,
    start: Seed,
    mac: Mac,
    output: Writable,
    chunkSize: number = DEFAULT_CHUNK_SIZE,
  ) {
    if (chunkSize <= 0) {
      throw new ITBError(Status.BadInput, 'chunkSize must be positive');
    }
    this.noise = noise;
    this.data = data;
    this.start = start;
    this.mac = mac;
    this.output = output;
    this.chunkSize = chunkSize;
    this.width = noise.width;
    this.headerSize = headerSize();
    this.streamId = generateStreamId();
  }

  private emitPrefix(): void {
    if (!this.prefixEmitted) {
      this.output.write(this.streamId);
      this.prefixEmitted = true;
    }
  }

  private emitOne(ptLen: number, finalFlag: boolean): void {
    // Fast-path skip: when `buf` holds a single Uint8Array (the
    // common case for callers passing a chunkSize-aligned source),
    // the merged buffer is byte-identical to `buf[0]` — return the
    // view directly to elide the alloc + memcpy of the slow-path
    // merge. The wipe pass is skipped on the fast path because `buf[0]`
    // is a caller-owned view; zeroing it would corrupt the caller's
    // buffer (semantic-preserving against the slow-path baseline,
    // which fresh-allocates and only wipes its private copy).
    let merged: Uint8Array;
    let owned: boolean;
    if (this.buf.length === 1) {
      merged = this.buf[0]!;
      owned = false;
    } else {
      merged = concatU8(this.buf, this.buffered);
      owned = true;
    }
    const chunkPt = merged.subarray(0, ptLen);
    const tail = merged.subarray(ptLen);
    const ct = emitChunkAuthSingle(
      this.width, this.noise, this.data, this.start, this.mac,
      chunkPt, this.streamId, this.cumPixels, finalFlag,
      this._outBuf,
    );
    if (owned) {
      chunkPt.fill(0);
    }
    if (ct.length >= this.headerSize) {
      const w = readBe16(ct, this.headerSize - 4);
      const h = readBe16(ct, this.headerSize - 2);
      this.cumPixels += BigInt(w) * BigInt(h);
    }
    this.output.write(ct);
    this.buf = tail.length > 0 ? [tail] : [];
    this.buffered = tail.length;
  }

  /**
   * Zeroes and drops the per-stream output cache. Called from
   * `close` and `[Symbol.dispose]` so the last chunk's ciphertext
   * does not linger in heap memory after the stream finalises.
   *
   * @internal
   */
  private _wipeOutBuf(): void {
    if (this._outBuf.buf !== null) {
      this._outBuf.buf.fill(0);
      this._outBuf.buf = null;
    }
  }

  write(data: Uint8Array | Buffer): number {
    if (this.closed) {
      throw new ITBError(Status.EasyClosed, 'write on closed StreamEncryptorAuth');
    }
    this.emitPrefix();
    const view = asUint8(data);
    this.buf.push(view);
    this.buffered += view.length;
    // Keep at least one chunk's worth buffered until close() so the
    // deferred-final pattern can decide whether to emit
    // finalFlag = true.
    while (this.buffered > this.chunkSize) {
      this.emitOne(this.chunkSize, false);
    }
    return view.length;
  }

  close(): void {
    if (this.closed) {
      this._wipeOutBuf();
      return;
    }
    this.emitPrefix();
    this.emitOne(this.buffered, true);
    this.closed = true;
    this._wipeOutBuf();
  }

  [Symbol.dispose](): void {
    this.close();
  }
}

/**
 * Authenticated chunked-decrypt writer (Single Ouroboros + MAC).
 * Reads the 32-byte `streamId` prefix once, then drains every
 * complete chunk available in the internal buffer.
 */
export class StreamDecryptorAuth {
  private readonly noise: Seed;
  private readonly data: Seed;
  private readonly start: Seed;
  private readonly mac: Mac;
  private readonly output: Writable;
  private readonly width: number;
  private readonly headerSize: number;
  private readonly streamId = new Uint8Array(STREAM_ID_LEN);
  private sidHave = 0;
  private buf: Uint8Array[] = [];
  private buffered = 0;
  private cumPixels = 0n;
  private seenFinal = false;
  private closed = false;
  /**
   * Per-stream output buffer cache. Same Bonus 1b shape as the
   * encrypt-side counterpart; reused across every chunk's decrypt
   * dispatch instead of a fresh `Uint8Array` per chunk
   * (.NEXTBIND.md §7.1).
   *
   * @internal
   */
  private _outBuf: StreamAuthCache = { buf: null };

  constructor(
    noise: Seed,
    data: Seed,
    start: Seed,
    mac: Mac,
    output: Writable,
  ) {
    this.noise = noise;
    this.data = data;
    this.start = start;
    this.mac = mac;
    this.output = output;
    this.width = noise.width;
    this.headerSize = headerSize();
  }

  private drain(): void {
    for (;;) {
      if (this.seenFinal) {
        if (this.buffered > 0) {
          throw new ITBStreamAfterFinalError(
            Status.StreamAfterFinal,
            'auth stream: trailing bytes after terminator');
        }
        return;
      }
      if (this.buffered < this.headerSize) {
        return;
      }
      // Fast-path skip: single-element buffer is byte-identical to
      // its sole part. Decrypt-side does not wipe the merged buffer
      // (§7.1 carve-out — `Writable.write` queues the reference), so
      // returning the view is safe.
      const merged = this.buf.length === 1
        ? this.buf[0]!
        : concatU8(this.buf, this.buffered);
      const chunkLen = parseChunkLen(merged.subarray(0, this.headerSize));
      if (merged.length < chunkLen) {
        this.buf = [merged];
        this.buffered = merged.length;
        return;
      }
      const w = readBe16(merged, this.headerSize - 4);
      const h = readBe16(merged, this.headerSize - 2);
      const pixels = BigInt(w) * BigInt(h);
      const chunk = merged.subarray(0, chunkLen);
      const tail = merged.subarray(chunkLen);
      const { pt, finalFlag } = consumeChunkAuthSingle(
        this.width, this.noise, this.data, this.start, this.mac,
        chunk, this.streamId, this.cumPixels,
        this._outBuf,
      );
      this.output.write(pt);
      this.cumPixels += pixels;
      this.buf = tail.length > 0 ? [tail] : [];
      this.buffered = tail.length;
      if (finalFlag) {
        this.seenFinal = true;
      }
    }
  }

  /**
   * Zeroes and drops the per-stream output cache. Called from
   * `close` and `[Symbol.dispose]` so the last chunk's plaintext
   * does not linger in heap memory after the stream finalises.
   *
   * @internal
   */
  private _wipeOutBuf(): void {
    if (this._outBuf.buf !== null) {
      this._outBuf.buf.fill(0);
      this._outBuf.buf = null;
    }
  }

  feed(data: Uint8Array | Buffer): number {
    if (this.closed) {
      throw new ITBError(Status.EasyClosed, 'feed on closed StreamDecryptorAuth');
    }
    const view = asUint8(data);
    let off = 0;
    if (this.sidHave < STREAM_ID_LEN) {
      const need = STREAM_ID_LEN - this.sidHave;
      const take = Math.min(need, view.length);
      this.streamId.set(view.subarray(0, take), this.sidHave);
      this.sidHave += take;
      off = take;
    }
    if (off < view.length) {
      const tail = view.subarray(off);
      this.buf.push(tail);
      this.buffered += tail.length;
    }
    if (this.sidHave === STREAM_ID_LEN) {
      this.drain();
    }
    return view.length;
  }

  close(): void {
    if (this.closed) {
      this._wipeOutBuf();
      return;
    }
    if (this.sidHave < STREAM_ID_LEN) {
      this.closed = true;
      this._wipeOutBuf();
      // Incomplete prefix is a wire-level malformation (header
      // never finished arriving), distinct from "chunks observed
      // but no terminator chunk among them" which is the
      // truncate-tail signal.
      throw new ITBError(
        Status.BadInput, 'auth stream: prefix never observed');
    }
    this.drain();
    this.closed = true;
    this._wipeOutBuf();
    if (!this.seenFinal) {
      throw new ITBStreamTruncatedError(
        Status.StreamTruncated, 'auth stream: terminator never observed');
    }
  }

  [Symbol.dispose](): void {
    // Mark closed without raising on partial input.
    this.closed = true;
    this._wipeOutBuf();
  }
}

/**
 * Triple-Ouroboros (7-seed) counterpart of `StreamEncryptorAuth`.
 */
export class StreamEncryptorAuthTriple {
  private readonly noise: Seed;
  private readonly data1: Seed;
  private readonly data2: Seed;
  private readonly data3: Seed;
  private readonly start1: Seed;
  private readonly start2: Seed;
  private readonly start3: Seed;
  private readonly mac: Mac;
  private readonly output: Writable;
  private readonly chunkSize: number;
  private readonly width: number;
  private readonly headerSize: number;
  private readonly streamId: Uint8Array;
  private buf: Uint8Array[] = [];
  private buffered = 0;
  private cumPixels = 0n;
  private closed = false;
  private prefixEmitted = false;
  /**
   * Per-stream output buffer cache. Same Bonus 1b shape as
   * {@link StreamEncryptorAuth._outBuf}; reused across every chunk's
   * encrypt dispatch (.NEXTBIND.md §7.1).
   *
   * @internal
   */
  private _outBuf: StreamAuthCache = { buf: null };

  constructor(
    noise: Seed,
    data1: Seed,
    data2: Seed,
    data3: Seed,
    start1: Seed,
    start2: Seed,
    start3: Seed,
    mac: Mac,
    output: Writable,
    chunkSize: number = DEFAULT_CHUNK_SIZE,
  ) {
    if (chunkSize <= 0) {
      throw new ITBError(Status.BadInput, 'chunkSize must be positive');
    }
    this.noise = noise;
    this.data1 = data1;
    this.data2 = data2;
    this.data3 = data3;
    this.start1 = start1;
    this.start2 = start2;
    this.start3 = start3;
    this.mac = mac;
    this.output = output;
    this.chunkSize = chunkSize;
    this.width = noise.width;
    this.headerSize = headerSize();
    this.streamId = generateStreamId();
  }

  private emitPrefix(): void {
    if (!this.prefixEmitted) {
      this.output.write(this.streamId);
      this.prefixEmitted = true;
    }
  }

  private emitOne(ptLen: number, finalFlag: boolean): void {
    // Fast-path skip: when `buf` holds a single Uint8Array, the
    // merged buffer is byte-identical to `buf[0]` — return the view
    // directly to elide the alloc + memcpy of the slow-path merge.
    // Wipe is skipped on the fast path because `buf[0]` is a
    // caller-owned view; zeroing it would corrupt the caller's
    // buffer.
    let merged: Uint8Array;
    let owned: boolean;
    if (this.buf.length === 1) {
      merged = this.buf[0]!;
      owned = false;
    } else {
      merged = concatU8(this.buf, this.buffered);
      owned = true;
    }
    const chunkPt = merged.subarray(0, ptLen);
    const tail = merged.subarray(ptLen);
    const ct = emitChunkAuthTriple(
      this.width, this.noise,
      this.data1, this.data2, this.data3,
      this.start1, this.start2, this.start3,
      this.mac,
      chunkPt, this.streamId, this.cumPixels, finalFlag,
      this._outBuf,
    );
    if (owned) {
      chunkPt.fill(0);
    }
    if (ct.length >= this.headerSize) {
      const w = readBe16(ct, this.headerSize - 4);
      const h = readBe16(ct, this.headerSize - 2);
      this.cumPixels += BigInt(w) * BigInt(h);
    }
    this.output.write(ct);
    this.buf = tail.length > 0 ? [tail] : [];
    this.buffered = tail.length;
  }

  /**
   * Zeroes and drops the per-stream output cache. Called from
   * `close` and `[Symbol.dispose]` so the last chunk's ciphertext
   * does not linger in heap memory after the stream finalises.
   *
   * @internal
   */
  private _wipeOutBuf(): void {
    if (this._outBuf.buf !== null) {
      this._outBuf.buf.fill(0);
      this._outBuf.buf = null;
    }
  }

  write(data: Uint8Array | Buffer): number {
    if (this.closed) {
      throw new ITBError(Status.EasyClosed,
        'write on closed StreamEncryptorAuthTriple');
    }
    this.emitPrefix();
    const view = asUint8(data);
    this.buf.push(view);
    this.buffered += view.length;
    while (this.buffered > this.chunkSize) {
      this.emitOne(this.chunkSize, false);
    }
    return view.length;
  }

  close(): void {
    if (this.closed) {
      this._wipeOutBuf();
      return;
    }
    this.emitPrefix();
    this.emitOne(this.buffered, true);
    this.closed = true;
    this._wipeOutBuf();
  }

  [Symbol.dispose](): void {
    this.close();
  }
}

/**
 * Triple-Ouroboros (7-seed) counterpart of `StreamDecryptorAuth`.
 */
export class StreamDecryptorAuthTriple {
  private readonly noise: Seed;
  private readonly data1: Seed;
  private readonly data2: Seed;
  private readonly data3: Seed;
  private readonly start1: Seed;
  private readonly start2: Seed;
  private readonly start3: Seed;
  private readonly mac: Mac;
  private readonly output: Writable;
  private readonly width: number;
  private readonly headerSize: number;
  private readonly streamId = new Uint8Array(STREAM_ID_LEN);
  private sidHave = 0;
  private buf: Uint8Array[] = [];
  private buffered = 0;
  private cumPixels = 0n;
  private seenFinal = false;
  private closed = false;
  /**
   * Per-stream output buffer cache. Same Bonus 1b shape as
   * {@link StreamDecryptorAuth._outBuf}; reused across every chunk's
   * decrypt dispatch (.NEXTBIND.md §7.1).
   *
   * @internal
   */
  private _outBuf: StreamAuthCache = { buf: null };

  constructor(
    noise: Seed,
    data1: Seed,
    data2: Seed,
    data3: Seed,
    start1: Seed,
    start2: Seed,
    start3: Seed,
    mac: Mac,
    output: Writable,
  ) {
    this.noise = noise;
    this.data1 = data1;
    this.data2 = data2;
    this.data3 = data3;
    this.start1 = start1;
    this.start2 = start2;
    this.start3 = start3;
    this.mac = mac;
    this.output = output;
    this.width = noise.width;
    this.headerSize = headerSize();
  }

  private drain(): void {
    for (;;) {
      if (this.seenFinal) {
        if (this.buffered > 0) {
          throw new ITBStreamAfterFinalError(
            Status.StreamAfterFinal,
            'auth stream: trailing bytes after terminator');
        }
        return;
      }
      if (this.buffered < this.headerSize) {
        return;
      }
      // Fast-path skip: single-element buffer is byte-identical to
      // its sole part. Decrypt-side does not wipe the merged buffer
      // (§7.1 carve-out), so returning the view is safe.
      const merged = this.buf.length === 1
        ? this.buf[0]!
        : concatU8(this.buf, this.buffered);
      const chunkLen = parseChunkLen(merged.subarray(0, this.headerSize));
      if (merged.length < chunkLen) {
        this.buf = [merged];
        this.buffered = merged.length;
        return;
      }
      const w = readBe16(merged, this.headerSize - 4);
      const h = readBe16(merged, this.headerSize - 2);
      const pixels = BigInt(w) * BigInt(h);
      const chunk = merged.subarray(0, chunkLen);
      const tail = merged.subarray(chunkLen);
      const { pt, finalFlag } = consumeChunkAuthTriple(
        this.width, this.noise,
        this.data1, this.data2, this.data3,
        this.start1, this.start2, this.start3,
        this.mac,
        chunk, this.streamId, this.cumPixels,
        this._outBuf,
      );
      this.output.write(pt);
      this.cumPixels += pixels;
      this.buf = tail.length > 0 ? [tail] : [];
      this.buffered = tail.length;
      if (finalFlag) {
        this.seenFinal = true;
      }
    }
  }

  /**
   * Zeroes and drops the per-stream output cache. Called from
   * `close` and `[Symbol.dispose]` so the last chunk's plaintext
   * does not linger in heap memory after the stream finalises.
   *
   * @internal
   */
  private _wipeOutBuf(): void {
    if (this._outBuf.buf !== null) {
      this._outBuf.buf.fill(0);
      this._outBuf.buf = null;
    }
  }

  feed(data: Uint8Array | Buffer): number {
    if (this.closed) {
      throw new ITBError(Status.EasyClosed,
        'feed on closed StreamDecryptorAuthTriple');
    }
    const view = asUint8(data);
    let off = 0;
    if (this.sidHave < STREAM_ID_LEN) {
      const need = STREAM_ID_LEN - this.sidHave;
      const take = Math.min(need, view.length);
      this.streamId.set(view.subarray(0, take), this.sidHave);
      this.sidHave += take;
      off = take;
    }
    if (off < view.length) {
      const tail = view.subarray(off);
      this.buf.push(tail);
      this.buffered += tail.length;
    }
    if (this.sidHave === STREAM_ID_LEN) {
      this.drain();
    }
    return view.length;
  }

  close(): void {
    if (this.closed) {
      this._wipeOutBuf();
      return;
    }
    if (this.sidHave < STREAM_ID_LEN) {
      this.closed = true;
      this._wipeOutBuf();
      // Incomplete prefix is a wire-level malformation (header
      // never finished arriving), distinct from "chunks observed
      // but no terminator chunk among them" which is the
      // truncate-tail signal.
      throw new ITBError(
        Status.BadInput, 'auth stream: prefix never observed');
    }
    this.drain();
    this.closed = true;
    this._wipeOutBuf();
    if (!this.seenFinal) {
      throw new ITBStreamTruncatedError(
        Status.StreamTruncated, 'auth stream: terminator never observed');
    }
  }

  [Symbol.dispose](): void {
    this.closed = true;
    this._wipeOutBuf();
  }
}

/**
 * Reads plaintext from `input` until end-of-stream, encrypts each
 * chunk under the Streaming AEAD construction, and writes the
 * concatenated `streamId || chunk_0 || chunk_1 || ...` transcript
 * to `output`. Neither stream is closed by the helper.
 */
export async function encryptStreamAuth(
  noise: Seed,
  data: Seed,
  start: Seed,
  mac: Mac,
  input: Readable,
  output: Writable,
  chunkSize: number = DEFAULT_CHUNK_SIZE,
): Promise<void> {
  const enc = new StreamEncryptorAuth(noise, data, start, mac, output, chunkSize);
  try {
    for await (const chunk of iterateReadable(input)) {
      enc.write(chunk);
    }
    enc.close();
  } catch (err) {
    enc.close();
    throw err;
  }
}

/**
 * Reads a Streaming AEAD transcript from `input` until end-of-stream
 * and writes the recovered plaintext to `output`. Surfaces `ITBError`
 * with `Status.BadInput` when the input exhausts mid-prefix
 * (incomplete 32-byte stream-id header), `ITBStreamTruncatedError`
 * when the prefix is fully observed but no terminating chunk arrives,
 * `ITBStreamAfterFinalError` when bytes follow the terminator, and
 * `ITBError` with `Status.MacFailure` on any per-chunk MAC mismatch.
 */
export async function decryptStreamAuth(
  noise: Seed,
  data: Seed,
  start: Seed,
  mac: Mac,
  input: Readable,
  output: Writable,
): Promise<void> {
  const dec = new StreamDecryptorAuth(noise, data, start, mac, output);
  try {
    for await (const chunk of iterateReadable(input)) {
      dec.feed(chunk);
    }
    dec.close();
  } catch (err) {
    dec[Symbol.dispose]();
    throw err;
  }
}

/**
 * Triple-Ouroboros (7-seed) counterpart of `encryptStreamAuth`.
 */
export async function encryptStreamAuthTriple(
  noise: Seed,
  data1: Seed,
  data2: Seed,
  data3: Seed,
  start1: Seed,
  start2: Seed,
  start3: Seed,
  mac: Mac,
  input: Readable,
  output: Writable,
  chunkSize: number = DEFAULT_CHUNK_SIZE,
): Promise<void> {
  const enc = new StreamEncryptorAuthTriple(
    noise, data1, data2, data3, start1, start2, start3, mac, output, chunkSize,
  );
  try {
    for await (const chunk of iterateReadable(input)) {
      enc.write(chunk);
    }
    enc.close();
  } catch (err) {
    enc.close();
    throw err;
  }
}

/**
 * Triple-Ouroboros (7-seed) counterpart of `decryptStreamAuth`.
 */
export async function decryptStreamAuthTriple(
  noise: Seed,
  data1: Seed,
  data2: Seed,
  data3: Seed,
  start1: Seed,
  start2: Seed,
  start3: Seed,
  mac: Mac,
  input: Readable,
  output: Writable,
): Promise<void> {
  const dec = new StreamDecryptorAuthTriple(
    noise, data1, data2, data3, start1, start2, start3, mac, output,
  );
  try {
    for await (const chunk of iterateReadable(input)) {
      dec.feed(chunk);
    }
    dec.close();
  } catch (err) {
    dec[Symbol.dispose]();
    throw err;
  }
}
