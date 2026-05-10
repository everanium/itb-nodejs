// Format-deniability wrapper for ITB ciphertext.
//
// TypeScript-idiomatic surface over the 12 ``ITB_Wrap*`` /
// ``ITB_Unwrap*`` / ``ITB_WrapStream*`` / ``ITB_UnwrapStream*`` /
// ``ITB_WrapperKeySize`` / ``ITB_WrapperNonceSize`` exports in
// ``cmd/cshared/main.go``. Wraps an ITB ciphertext under one of three
// outer keystream ciphers (AES-128-CTR / ChaCha20 / SipHash-2-4 in CTR
// mode) so the on-wire bytes carry no ITB-specific format pattern (W /
// H / container layout for Non-AEAD; 32-byte streamID prefix +
// per-chunk metadata for Streaming AEAD). The wrap exists for
// format-deniability ONLY — ITB already provides content-deniability
// and the AEAD path already provides integrity.
//
// Quick start — Single Message wrap / unwrap (immutable):
//
//     import { wrap, unwrap, generateKey, Cipher } from 'itb';
//     const key = generateKey(Cipher.Aes128Ctr);
//     const wire = wrap(Cipher.Aes128Ctr, key, blob);
//     const recovered = unwrap(Cipher.Aes128Ctr, key, wire);
//
// Quick start — Single Message in-place mutation (zero-allocation
// steady state):
//
//     import { wrapInPlace, unwrapInPlace } from 'itb';
//     const buf = Buffer.from(blob);
//     const nonce = wrapInPlace(Cipher.ChaCha20, key, buf);
//     // emit `nonce || buf` to the wire.
//     const wireBuf = Buffer.concat([nonce, buf]);
//     const body = unwrapInPlace(Cipher.ChaCha20, key, wireBuf);
//     // body aliases wireBuf.subarray(nonceSize(...))
//
// Streaming wrap (caller-side framing through one keystream so length
// prefixes also XOR through):
//
//     using ww = new WrapStreamWriter(Cipher.SipHash24, key);
//     const c1 = ww.update(Buffer.from('chunk-1'));
//     const c2 = ww.update(Buffer.from('chunk-2'));
//     const wire = Buffer.concat([ww.nonce, c1, c2]);
//
// The ``Cipher`` enum selects one of three outer ciphers:
//
//   - ``Cipher.Aes128Ctr`` (`"aes"`) — AES-128-CTR with a 16-byte key
//     + 16-byte nonce. AES-NI accelerated.
//   - ``Cipher.ChaCha20`` (`"chacha"`) — ChaCha20 (RFC8439) with a
//     32-byte key + 12-byte nonce.
//   - ``Cipher.SipHash24`` (`"siphash"`) — SipHash-2-4 in CTR mode
//     with a 16-byte key + 16-byte nonce. Custom CTR construction
//     over the SipHash-2-4 PRF.
//
// Threading. Each ``WrapStreamWriter`` / ``UnwrapStreamReader``
// instance owns one libitb stream handle and is single-feeder by
// construction; multiple instances run independently. The free
// functions (``wrap`` / ``unwrap`` / ``wrapInPlace`` /
// ``unwrapInPlace``) are thread-safe — each call allocates its own
// outer cipher handle internally and the underlying libitb keystream
// constructor draws a fresh CSPRNG nonce per call.

import { randomBytes } from 'node:crypto';

import { ITBError, errorFromStatus } from './errors.js';
import {
  ITB_Unwrap,
  ITB_UnwrapInPlace,
  ITB_UnwrapStreamReader_Free,
  ITB_UnwrapStreamReader_Init,
  ITB_UnwrapStreamReader_Update,
  ITB_Wrap,
  ITB_WrapInPlace,
  ITB_WrapStreamWriter_Free,
  ITB_WrapStreamWriter_Init,
  ITB_WrapStreamWriter_Update,
  ITB_WrapperKeySize,
  ITB_WrapperNonceSize,
} from './native.js';
import { Status } from './status.js';

/**
 * Canonical outer cipher names accepted by the wrap surface. Match
 * the ``CipherAES128CTR`` / ``CipherChaCha20`` / ``CipherSipHash24``
 * constants in ``github.com/everanium/itb/wrapper``.
 */
export const Cipher = {
  Aes128Ctr: 'aes',
  ChaCha20: 'chacha',
  SipHash24: 'siphash',
} as const;

/** String-literal type of a supported wrapper cipher name. */
export type CipherName = typeof Cipher[keyof typeof Cipher];

/** Iteration order of every supported outer cipher. */
export const CIPHER_NAMES: readonly CipherName[] = [
  Cipher.Aes128Ctr,
  Cipher.ChaCha20,
  Cipher.SipHash24,
];

// ── Typed errors ───────────────────────────────────────────────────

/** Base class for every wrapper-side typed exception. */
export class WrapperError extends ITBError {
  constructor(code: number, message?: string) {
    super(code, message);
    this.name = 'WrapperError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Raised when ``cipher`` is not one of the canonical
 * {@link Cipher.Aes128Ctr} / {@link Cipher.ChaCha20} /
 * {@link Cipher.SipHash24} values. Carries
 * {@link Status.BadInput}.
 */
export class InvalidCipherError extends WrapperError {
  constructor(name: string) {
    super(
      Status.BadInput,
      `unknown wrapper cipher ${JSON.stringify(name)} ` +
        `(expected one of ${JSON.stringify(CIPHER_NAMES)})`,
    );
    this.name = 'InvalidCipherError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Raised when the supplied key length does not match the cipher's
 * expected key size. Carries {@link Status.BadInput}.
 */
export class InvalidKeyError extends WrapperError {
  constructor(cipher: string, expected: number, actual: number) {
    super(
      Status.BadInput,
      `${JSON.stringify(cipher)}: key must be ${expected} bytes, got ${actual}`,
    );
    this.name = 'InvalidKeyError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Raised when an inbound nonce / wire prefix is not the expected
 * length for the selected cipher. Carries {@link Status.BadInput}.
 */
export class InvalidNonceError extends WrapperError {
  constructor(message: string) {
    super(Status.BadInput, message);
    this.name = 'InvalidNonceError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Raised when a streaming {@link WrapStreamWriter.update} /
 * {@link UnwrapStreamReader.update} call follows
 * {@link WrapStreamWriter.close} / {@link UnwrapStreamReader.close}.
 * Carries {@link Status.BadHandle}.
 */
export class WrapperHandleClosedError extends WrapperError {
  constructor() {
    super(Status.BadHandle, 'wrapper stream handle has been closed');
    this.name = 'WrapperHandleClosedError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ── Internal helpers ───────────────────────────────────────────────

type Handle = bigint | number;

const ZERO_HANDLE: Handle = 0;

function isZeroHandle(h: Handle): boolean {
  return h === 0 || h === 0n;
}

function validateCipher(name: string): CipherName {
  if (
    name !== Cipher.Aes128Ctr &&
    name !== Cipher.ChaCha20 &&
    name !== Cipher.SipHash24
  ) {
    throw new InvalidCipherError(name);
  }
  return name as CipherName;
}

function ensureBuffer(value: unknown, label: string): Buffer {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value instanceof Uint8Array) {
    // koffi accepts Uint8Array views directly; wrapping into Buffer
    // is zero-copy on Node and yields a uniform mutable type.
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new TypeError(`${label} must be a Buffer or Uint8Array`);
}

function validateKey(cipher: CipherName, key: Buffer): void {
  const expected = keySize(cipher);
  if (key.length !== expected) {
    throw new InvalidKeyError(cipher, expected, key.length);
  }
}

function checkRc(rc: number): void {
  if (rc !== Status.Ok) {
    throw errorFromStatus(rc);
  }
}

// ── Library-level metadata ─────────────────────────────────────────

/**
 * Returns the byte length of the keystream-cipher key for the named
 * outer cipher (16 / 32 / 16 for `"aes"` / `"chacha"` / `"siphash"`).
 *
 * Raises {@link InvalidCipherError} on an unknown cipher name.
 */
export function keySize(cipher: CipherName): number {
  const cn = validateCipher(cipher);
  const out: [number | bigint] = [0];
  const rc = ITB_WrapperKeySize(cn, out);
  checkRc(rc);
  return Number(out[0]);
}

/**
 * Returns the on-wire nonce length the named outer cipher emits per
 * stream (16 / 12 / 16 for `"aes"` / `"chacha"` / `"siphash"`).
 *
 * Raises {@link InvalidCipherError} on an unknown cipher name.
 */
export function nonceSize(cipher: CipherName): number {
  const cn = validateCipher(cipher);
  const out: [number | bigint] = [0];
  const rc = ITB_WrapperNonceSize(cn, out);
  checkRc(rc);
  return Number(out[0]);
}

/**
 * Returns a fresh CSPRNG key of the size required by ``cipher`` (16
 * / 32 / 16 bytes for `"aes"` / `"chacha"` / `"siphash"`). Uses
 * Node's {@link randomBytes}. The returned key is opaque bytes; the
 * caller stores or shares it out-of-band.
 */
export function generateKey(cipher: CipherName): Buffer {
  return randomBytes(keySize(cipher));
}

// ── Single Message helpers ────────────────────────────────────────────

/**
 * Single Message wrap. Seals ``blob`` under ``cipher`` with a fresh
 * per-call CSPRNG nonce; returns a fresh wire buffer
 * `nonce || keystream-XOR(blob)`.
 *
 * Allocates a fresh output buffer of size
 * ``nonceSize(cipher) + blob.length`` per call. For zero-allocation
 * steady state on the hot path use {@link wrapInPlace}.
 */
export function wrap(cipher: CipherName, key: Buffer, blob: Buffer): Buffer {
  const cn = validateCipher(cipher);
  const keyB = ensureBuffer(key, 'key');
  validateKey(cn, keyB);
  const blobB = ensureBuffer(blob, 'blob');
  const nlen = nonceSize(cn);
  const cap = nlen + blobB.length;
  const out = Buffer.alloc(cap);
  const outLen: [number | bigint] = [0];
  const rc = ITB_Wrap(
    cn,
    keyB,
    keyB.length,
    blobB,
    blobB.length,
    out,
    out.length,
    outLen,
  );
  checkRc(rc);
  return out.subarray(0, Number(outLen[0]));
}

/**
 * Single Message unwrap. Reads the leading ``nonceSize(cipher)`` bytes
 * of ``wire`` as the per-stream nonce, XOR-decrypts the remainder
 * under ``(key, nonce)`` and returns the recovered blob.
 *
 * Allocates a fresh output buffer of size ``wire.length -
 * nonceSize(cipher)`` per call. For zero-allocation steady state use
 * {@link unwrapInPlace}.
 */
export function unwrap(cipher: CipherName, key: Buffer, wire: Buffer): Buffer {
  const cn = validateCipher(cipher);
  const keyB = ensureBuffer(key, 'key');
  validateKey(cn, keyB);
  const wireB = ensureBuffer(wire, 'wire');
  const nlen = nonceSize(cn);
  if (wireB.length < nlen) {
    throw new InvalidNonceError(
      `${JSON.stringify(cipher)}: wire shorter than nonce ` +
        `(${wireB.length} < ${nlen})`,
    );
  }
  const cap = wireB.length - nlen;
  // Allocate at least one byte — koffi rejects zero-length pointer
  // args even when the underlying capacity argument is zero.
  const out = Buffer.alloc(Math.max(cap, 1));
  const outLen: [number | bigint] = [0];
  const rc = ITB_Unwrap(
    cn,
    keyB,
    keyB.length,
    wireB,
    wireB.length,
    out,
    cap,
    outLen,
  );
  checkRc(rc);
  return out.subarray(0, Number(outLen[0]));
}

/**
 * In-place Single Message wrap. XORs ``blob`` under a fresh per-call
 * CSPRNG nonce; returns the per-stream nonce as a fresh
 * {@link Buffer}.
 *
 * The input ``blob`` is **MUTATED**. The caller is expected to emit
 * ``nonce || blob`` to the wire (or compose a single buffer
 * themselves).
 *
 * Suitable for hot paths where the caller has just produced an ITB
 * ciphertext and will not re-read it (the typical case for buffered
 * write-to-wire). For an immutable plaintext path use {@link wrap}.
 */
export function wrapInPlace(
  cipher: CipherName,
  key: Buffer,
  blob: Buffer,
): Buffer {
  const cn = validateCipher(cipher);
  const keyB = ensureBuffer(key, 'key');
  validateKey(cn, keyB);
  const blobB = ensureBuffer(blob, 'blob');
  const nlen = nonceSize(cn);
  const nonce = Buffer.alloc(nlen);
  const rc = ITB_WrapInPlace(
    cn,
    keyB,
    keyB.length,
    blobB,
    blobB.length,
    nonce,
    nonce.length,
  );
  checkRc(rc);
  return nonce;
}

/**
 * In-place Single Message unwrap. Strips the leading
 * ``nonceSize(cipher)`` bytes from ``wire`` and XOR-decrypts the
 * remainder under ``(key, nonce)`` directly into the caller's
 * buffer.
 *
 * The input ``wire`` is **MUTATED**. Returns a sub-view aliased to
 * ``wire.subarray(nonceSize(cipher))`` containing the recovered
 * blob; the leading nonce prefix is left unchanged.
 *
 * For an immutable wire input use {@link unwrap}.
 */
export function unwrapInPlace(
  cipher: CipherName,
  key: Buffer,
  wire: Buffer,
): Buffer {
  const cn = validateCipher(cipher);
  const keyB = ensureBuffer(key, 'key');
  validateKey(cn, keyB);
  const wireB = ensureBuffer(wire, 'wire');
  const nlen = nonceSize(cn);
  if (wireB.length < nlen) {
    throw new InvalidNonceError(
      `${JSON.stringify(cipher)}: wire shorter than nonce ` +
        `(${wireB.length} < ${nlen})`,
    );
  }
  const rc = ITB_UnwrapInPlace(
    cn,
    keyB,
    keyB.length,
    wireB,
    wireB.length,
  );
  checkRc(rc);
  return wireB.subarray(nlen);
}

// ── Streaming helpers ──────────────────────────────────────────────

const writerFinalizer = new FinalizationRegistry<Handle>((handle) => {
  try {
    if (!isZeroHandle(handle)) {
      ITB_WrapStreamWriter_Free(handle);
    }
  } catch {
    // Best-effort; finalization runs at unspecified times.
  }
});

const readerFinalizer = new FinalizationRegistry<Handle>((handle) => {
  try {
    if (!isZeroHandle(handle)) {
      ITB_UnwrapStreamReader_Free(handle);
    }
  } catch {
    // Best-effort.
  }
});

/**
 * Streaming wrap-encrypt handle.
 *
 * Allocated as a fresh-nonce / fresh-keystream session. The
 * constructor draws a CSPRNG nonce, opens a libitb wrap-stream
 * handle bound to ``(key, nonce)``, and exposes the nonce on the
 * {@link WrapStreamWriter.nonce} accessor so the caller can emit it
 * once at stream start (typically as the wire prefix). Subsequent
 * {@link WrapStreamWriter.update} calls XOR caller plaintext through
 * the keystream and return the encrypted bytes; the keystream
 * counter advances monotonically across calls.
 *
 * Pair every {@link WrapStreamWriter} with an
 * {@link UnwrapStreamReader} keyed by the same ``cipher`` / ``key``
 * and the nonce read off the wire.
 *
 * Thread-safety: the writer is single-feeder by construction. Do
 * not interleave {@link WrapStreamWriter.update} calls from multiple
 * threads on the same writer — the underlying libitb keystream is
 * stateful.
 *
 * Use under a ``using`` declaration for deterministic lifetime, or
 * call {@link WrapStreamWriter.close} explicitly when the stream
 * ends. The handle is released back to libitb on close; subsequent
 * {@link WrapStreamWriter.update} raises
 * {@link WrapperHandleClosedError}. A {@link FinalizationRegistry}
 * backstop runs the same release on GC if neither was called.
 */
export class WrapStreamWriter implements Disposable {
  /** @internal */
  private _handle: Handle = ZERO_HANDLE;
  /** @internal */
  private _nonce: Buffer;
  /** @internal */
  private _cipher: CipherName;
  /** @internal */
  private _closed: boolean = false;

  constructor(cipher: CipherName, key: Buffer) {
    const cn = validateCipher(cipher);
    const keyB = ensureBuffer(key, 'key');
    validateKey(cn, keyB);
    const nlen = nonceSize(cn);
    const nonce = Buffer.alloc(nlen);
    const out: [Handle] = [ZERO_HANDLE];
    const rc = ITB_WrapStreamWriter_Init(
      cn,
      keyB,
      keyB.length,
      nonce,
      nonce.length,
      out,
    );
    checkRc(rc);
    this._handle = out[0]!;
    this._nonce = nonce;
    this._cipher = cn;
    writerFinalizer.register(this, this._handle, this);
  }

  /**
   * The per-stream CSPRNG nonce. The caller emits this once at
   * stream start (typically as the wire prefix) so the matching
   * {@link UnwrapStreamReader} can be constructed against it.
   */
  get nonce(): Buffer {
    return this._nonce;
  }

  /** The outer cipher selected at construction. */
  get cipher(): CipherName {
    return this._cipher;
  }

  /** Opaque libitb handle id (uintptr). Useful for diagnostics. */
  get handle(): Handle {
    return this._handle;
  }

  /**
   * XOR-encrypts ``src`` through the keystream and returns the
   * result as a fresh {@link Buffer}. The keystream counter advances
   * by ``src.length`` bytes.
   *
   * Raises {@link WrapperHandleClosedError} if the writer has been
   * closed.
   */
  update(src: Buffer): Buffer {
    if (this._closed || isZeroHandle(this._handle)) {
      throw new WrapperHandleClosedError();
    }
    const srcB = ensureBuffer(src, 'src');
    if (srcB.length === 0) {
      return Buffer.alloc(0);
    }
    const dst = Buffer.alloc(srcB.length);
    const rc = ITB_WrapStreamWriter_Update(
      this._handle,
      srcB,
      srcB.length,
      dst,
      dst.length,
    );
    checkRc(rc);
    return dst;
  }

  /**
   * In-place variant of {@link WrapStreamWriter.update}. XORs
   * ``buf`` directly through the keystream; the buffer is
   * **MUTATED**. The keystream counter advances by ``buf.length``
   * bytes.
   *
   * Raises {@link WrapperHandleClosedError} if the writer has been
   * closed.
   */
  updateInPlace(buf: Buffer): void {
    if (this._closed || isZeroHandle(this._handle)) {
      throw new WrapperHandleClosedError();
    }
    const b = ensureBuffer(buf, 'buf');
    if (b.length === 0) {
      return;
    }
    const rc = ITB_WrapStreamWriter_Update(
      this._handle,
      b,
      b.length,
      b,
      b.length,
    );
    checkRc(rc);
  }

  /**
   * Releases the underlying libitb wrap-stream handle. Idempotent;
   * a second call is a no-op.
   */
  close(): void {
    if (this._closed || isZeroHandle(this._handle)) {
      this._closed = true;
      this._handle = ZERO_HANDLE;
      return;
    }
    const handle = this._handle;
    this._handle = ZERO_HANDLE;
    this._closed = true;
    writerFinalizer.unregister(this);
    const rc = ITB_WrapStreamWriter_Free(handle);
    checkRc(rc);
  }

  [Symbol.dispose](): void {
    this.close();
  }
}

/**
 * Streaming unwrap-decrypt handle. Counterpart of
 * {@link WrapStreamWriter}.
 *
 * Constructed against the per-stream nonce read off the wire
 * (typically the leading ``nonceSize(cipher)`` bytes). The libitb
 * wrap-stream handle is keyed by ``(cipher, key, wireNonce)``;
 * subsequent {@link UnwrapStreamReader.update} calls XOR-decrypt
 * caller-supplied wire bytes into recovered plaintext.
 *
 * Thread-safety: the reader is single-feeder by construction. Do
 * not interleave {@link UnwrapStreamReader.update} calls from
 * multiple threads on the same reader.
 *
 * Use under a ``using`` declaration for deterministic lifetime, or
 * call {@link UnwrapStreamReader.close} explicitly when the stream
 * ends.
 */
export class UnwrapStreamReader implements Disposable {
  /** @internal */
  private _handle: Handle = ZERO_HANDLE;
  /** @internal */
  private _cipher: CipherName;
  /** @internal */
  private _closed: boolean = false;

  constructor(cipher: CipherName, key: Buffer, wireNonce: Buffer) {
    const cn = validateCipher(cipher);
    const keyB = ensureBuffer(key, 'key');
    validateKey(cn, keyB);
    const nonceB = ensureBuffer(wireNonce, 'wireNonce');
    const nlen = nonceSize(cn);
    if (nonceB.length !== nlen) {
      throw new InvalidNonceError(
        `${JSON.stringify(cipher)}: nonce must be ${nlen} bytes, ` +
          `got ${nonceB.length}`,
      );
    }
    const out: [Handle] = [ZERO_HANDLE];
    const rc = ITB_UnwrapStreamReader_Init(
      cn,
      keyB,
      keyB.length,
      nonceB,
      nonceB.length,
      out,
    );
    checkRc(rc);
    this._handle = out[0]!;
    this._cipher = cn;
    readerFinalizer.register(this, this._handle, this);
  }

  /** The outer cipher selected at construction. */
  get cipher(): CipherName {
    return this._cipher;
  }

  /** Opaque libitb handle id (uintptr). Useful for diagnostics. */
  get handle(): Handle {
    return this._handle;
  }

  /**
   * XOR-decrypts ``src`` through the keystream and returns the
   * recovered plaintext bytes as a fresh {@link Buffer}. The
   * keystream counter advances by ``src.length`` bytes.
   *
   * Raises {@link WrapperHandleClosedError} if the reader has been
   * closed.
   */
  update(src: Buffer): Buffer {
    if (this._closed || isZeroHandle(this._handle)) {
      throw new WrapperHandleClosedError();
    }
    const srcB = ensureBuffer(src, 'src');
    if (srcB.length === 0) {
      return Buffer.alloc(0);
    }
    const dst = Buffer.alloc(srcB.length);
    const rc = ITB_UnwrapStreamReader_Update(
      this._handle,
      srcB,
      srcB.length,
      dst,
      dst.length,
    );
    checkRc(rc);
    return dst;
  }

  /**
   * In-place variant of {@link UnwrapStreamReader.update}. XORs
   * ``buf`` directly through the keystream; the buffer is
   * **MUTATED**. The keystream counter advances by ``buf.length``
   * bytes.
   *
   * Raises {@link WrapperHandleClosedError} if the reader has been
   * closed.
   */
  updateInPlace(buf: Buffer): void {
    if (this._closed || isZeroHandle(this._handle)) {
      throw new WrapperHandleClosedError();
    }
    const b = ensureBuffer(buf, 'buf');
    if (b.length === 0) {
      return;
    }
    const rc = ITB_UnwrapStreamReader_Update(
      this._handle,
      b,
      b.length,
      b,
      b.length,
    );
    checkRc(rc);
  }

  /**
   * Releases the underlying libitb wrap-stream handle. Idempotent;
   * a second call is a no-op.
   */
  close(): void {
    if (this._closed || isZeroHandle(this._handle)) {
      this._closed = true;
      this._handle = ZERO_HANDLE;
      return;
    }
    const handle = this._handle;
    this._handle = ZERO_HANDLE;
    this._closed = true;
    readerFinalizer.unregister(this);
    const rc = ITB_UnwrapStreamReader_Free(handle);
    checkRc(rc);
  }

  [Symbol.dispose](): void {
    this.close();
  }
}
