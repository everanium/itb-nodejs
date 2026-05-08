// Native-Blob wrapper over the libitb C ABI.
//
// Mirrors the github.com/everanium/itb Blob128 / Blob256 / Blob512 Go
// types: a width-specific container that packs the low-level
// encryptor material (per-seed hash key + components + optional
// dedicated lockSeed + optional MAC key + name) plus the captured
// process-wide configuration into one self-describing JSON blob.
// Intended for the low-level encrypt / decrypt path where each seed
// slot may carry a different primitive — the high-level `Encryptor`
// wraps a narrower one-primitive-per-encryptor surface (see
// `./encryptor.js`).
//
// Quick start (sender, Single Ouroboros + Areion-SoEM-512 + HMAC-BLAKE3):
//
//     import { Seed, MAC, Blob512, encryptAuth, BlobSlot, BlobExportOpts } from 'itb';
//     import { randomBytes } from 'node:crypto';
//
//     using ns = new Seed('areion512', 2048);
//     using ds = new Seed('areion512', 2048);
//     using ss = new Seed('areion512', 2048);
//     const macKey = new Uint8Array(randomBytes(32));
//     using mac = new MAC('hmac-blake3', macKey);
//     const ct = encryptAuth(ns, ds, ss, mac, payload);
//     using b = new Blob512();
//     b.setKey(BlobSlot.N, ns.hashKey); b.setComponents(BlobSlot.N, ns.components);
//     b.setKey(BlobSlot.D, ds.hashKey); b.setComponents(BlobSlot.D, ds.components);
//     b.setKey(BlobSlot.S, ss.hashKey); b.setComponents(BlobSlot.S, ss.components);
//     b.setMacKey(macKey); b.setMacName('hmac-blake3');
//     const blobBytes = b.export(BlobExportOpts.Mac);
//     // ... persist blobBytes ...
//
// Receiver:
//
//     using b2 = new Blob512();
//     b2.import(blobBytes);
//     // Components and hash keys round-trip back into the receiver.
//     using ns2 = Seed.fromComponents('areion512', b2.getComponents(BlobSlot.N), b2.getKey(BlobSlot.N));
//     // ... wire ds2, ss2 the same way; rebuild MAC; decryptAuth ...
//
// The blob is mode-discriminated: `export` packs Single material,
// `exportTriple` packs Triple material; `import` and
// `importTriple` are the corresponding receivers. A blob built
// under one mode rejects the wrong importer with
// `ITBBlobModeMismatchError`.
//
// Globals (NonceBits / BarrierFill / BitSoup / LockSoup) are captured
// into the blob at `export` / `exportTriple` time and applied
// process-wide on `import` / `importTriple` via the existing
// `setNonceBits` / `setBarrierFill` / `setBitSoup` / `setLockSoup`
// setters. The worker count and the global LockSeed flag are not
// serialised — the former is a deployment knob, the latter is
// irrelevant on the native path which consults `Seed.attachLockSeed`
// directly.

import { check, errorFromStatus } from './errors.js';
import {
  ITB_Blob128_New,
  ITB_Blob256_New,
  ITB_Blob512_New,
  ITB_Blob_Export,
  ITB_Blob_Export3,
  ITB_Blob_Free,
  ITB_Blob_GetComponents,
  ITB_Blob_GetKey,
  ITB_Blob_GetMACKey,
  ITB_Blob_GetMACName,
  ITB_Blob_Import,
  ITB_Blob_Import3,
  ITB_Blob_Mode,
  ITB_Blob_SetComponents,
  ITB_Blob_SetKey,
  ITB_Blob_SetMACKey,
  ITB_Blob_SetMACName,
  ITB_Blob_Width,
} from './native.js';
import { readString } from './read-string.js';
import { Status } from './status.js';

type Handle = bigint | number;

const ZERO: Handle = 0;

function isZero(h: Handle): boolean {
  return h === 0 || h === 0n;
}

// ──────────────────────────────────────────────────────────────────
// Slot identifiers — must mirror the BlobSlot* constants in
// cmd/cshared/internal/capi/blob_handles.go.
// ──────────────────────────────────────────────────────────────────

/**
 * Slot identifier map for `Blob.setKey` / `Blob.getKey` /
 * `Blob.setComponents` / `Blob.getComponents`. The numeric values are
 * stable and match the libitb `BlobSlot*` C ABI constants.
 */
export const BlobSlot = {
  /** Noise seed (Single Ouroboros). */
  N: 0,
  /** Data seed (Single Ouroboros). */
  D: 1,
  /** Start seed (Single Ouroboros). */
  S: 2,
  /** Dedicated lockSeed. */
  L: 3,
  /** Triple Ouroboros — data seed 1. */
  D1: 4,
  /** Triple Ouroboros — data seed 2. */
  D2: 5,
  /** Triple Ouroboros — data seed 3. */
  D3: 6,
  /** Triple Ouroboros — start seed 1. */
  S1: 7,
  /** Triple Ouroboros — start seed 2. */
  S2: 8,
  /** Triple Ouroboros — start seed 3. */
  S3: 9,
} as const;

export type BlobSlotValue = typeof BlobSlot[keyof typeof BlobSlot];

const SLOT_NAMES: Record<string, BlobSlotValue> = {
  n: BlobSlot.N,
  d: BlobSlot.D,
  s: BlobSlot.S,
  l: BlobSlot.L,
  d1: BlobSlot.D1,
  d2: BlobSlot.D2,
  d3: BlobSlot.D3,
  s1: BlobSlot.S1,
  s2: BlobSlot.S2,
  s3: BlobSlot.S3,
};

/**
 * Resolves a slot identifier — accepts either an integer (already a
 * `BlobSlot` numeric value) or a case-insensitive string from the
 * canonical `{"n","d","s","l","d1","d2","d3","s1","s2","s3"}` set.
 */
function resolveSlot(slot: BlobSlotValue | number | string): number {
  if (typeof slot === 'number') {
    return slot | 0;
  }
  if (typeof slot === 'string') {
    const key = slot.toLowerCase();
    if (Object.prototype.hasOwnProperty.call(SLOT_NAMES, key)) {
      return SLOT_NAMES[key]!;
    }
  }
  throw new TypeError(`invalid blob slot: ${String(slot)}`);
}

// ──────────────────────────────────────────────────────────────────
// Export option bitmask — must mirror BlobOpt* in blob_handles.go.
// ──────────────────────────────────────────────────────────────────

/**
 * Export-time option bitmask for `Blob.export` /
 * `Blob.exportTriple`. Bitwise-OR multiple flags together; the
 * raw `number` is forwarded to libitb so any extra bits will trip
 * `Status.BlobTooManyOpts`.
 */
export const BlobExportOpts = {
  /** No optional sections. */
  None: 0,
  /** Emit the `l` slot's lockSeed material (KeyL + components). */
  LockSeed: 1 << 0,
  /** Emit the MAC key + name. Both must be non-empty on the handle. */
  Mac: 1 << 1,
} as const;

export type BlobExportOptsValue = typeof BlobExportOpts[keyof typeof BlobExportOpts];

// ──────────────────────────────────────────────────────────────────
// Lifecycle — finalisation registry as a backstop for a missing
// `using` / explicit `free()`.
// ──────────────────────────────────────────────────────────────────

const blobFinalizer = new FinalizationRegistry<Handle>((handle) => {
  try {
    if (!isZero(handle)) {
      ITB_Blob_Free(handle);
    }
  } catch {
    // Best-effort; finalization runs at unspecified times.
  }
});

// ──────────────────────────────────────────────────────────────────
// Width-agnostic Blob handle wrapper. Width-pinned subclasses
// `Blob128` / `Blob256` / `Blob512` provide the constructor entry
// point; every other operation goes through the shared `ITB_Blob_*`
// FFI surface.
// ──────────────────────────────────────────────────────────────────

abstract class BlobBase implements Disposable {
  /** @internal */
  protected _handle: Handle = ZERO;

  protected constructor(allocate: (out: [Handle]) => number) {
    const out: [Handle] = [ZERO];
    check(allocate(out));
    this._handle = out[0]!;
    blobFinalizer.register(this, this._handle, this);
  }

  /**
   * Opaque libitb handle id (uintptr). Useful for diagnostics;
   * consumers should not rely on its numerical value.
   */
  get handle(): Handle {
    return this._handle;
  }

  /**
   * Native hash width — 128, 256, or 512. Pinned at construction
   * time and stable for the lifetime of the handle.
   */
  get width(): number {
    const st: [number] = [0];
    const v = ITB_Blob_Width(this._handle, st);
    if (st[0] !== Status.Ok) {
      throw errorFromStatus(st[0]);
    }
    return v;
  }

  /**
   * Blob mode field — `0` = unset (freshly constructed handle),
   * `1` = Single Ouroboros, `3` = Triple Ouroboros. Updated by
   * `import` / `importTriple` from the parsed blob's mode
   * discriminator.
   */
  get mode(): number {
    const st: [number] = [0];
    const v = ITB_Blob_Mode(this._handle, st);
    if (st[0] !== Status.Ok) {
      throw errorFromStatus(st[0]);
    }
    return v;
  }

  // ─── Slot setters ─────────────────────────────────────────────

  /**
   * Stores the hash key bytes for the given slot. The 256 / 512
   * widths require exactly 32 / 64 bytes; the 128 width accepts
   * variable lengths (empty for siphash24 — no internal fixed key —
   * or 16 bytes for aescmac).
   */
  setKey(slot: BlobSlotValue | number | string, key: Uint8Array): void {
    if (!(key instanceof Uint8Array)) {
      throw new TypeError('key must be a Uint8Array');
    }
    const sl = resolveSlot(slot);
    const ptr = key.length > 0 ? key : null;
    check(ITB_Blob_SetKey(this._handle, sl, ptr, key.length));
  }

  /**
   * Stores the seed components (sequence of unsigned 64-bit
   * integers) for the given slot. Component count must satisfy the
   * 8..MaxKeyBits/64 multiple-of-8 invariants — same rules as
   * `Seed.fromComponents`. Validation is deferred to `export`
   * / `import` time.
   */
  setComponents(
    slot: BlobSlotValue | number | string,
    comps: readonly bigint[],
  ): void {
    const sl = resolveSlot(slot);
    const buf = BigUint64Array.from(comps);
    const ptr = buf.length > 0 ? buf : null;
    check(ITB_Blob_SetComponents(this._handle, sl, ptr, buf.length));
  }

  /**
   * Stores the optional MAC key bytes. Pass `null` or an empty
   * `Uint8Array` to clear a previously-set key. The MAC section is
   * only emitted by `export` / `exportTriple` when the
   * `BlobExportOpts.Mac` flag is set AND the MAC key on the handle
   * is non-empty.
   */
  setMacKey(key: Uint8Array | null): void {
    if (key === null) {
      check(ITB_Blob_SetMACKey(this._handle, null, 0));
      return;
    }
    if (!(key instanceof Uint8Array)) {
      throw new TypeError('MAC key must be a Uint8Array');
    }
    const ptr = key.length > 0 ? key : null;
    check(ITB_Blob_SetMACKey(this._handle, ptr, key.length));
  }

  /**
   * Stores the optional MAC name on the handle (e.g. `"kmac256"`,
   * `"hmac-blake3"`). Pass `null` or an empty string to clear a
   * previously-set name.
   */
  setMacName(name: string | null): void {
    if (name === null || name.length === 0) {
      check(ITB_Blob_SetMACName(this._handle, null, 0));
      return;
    }
    const buf = new TextEncoder().encode(name);
    check(ITB_Blob_SetMACName(this._handle, buf, buf.length));
  }

  // ─── Slot getters ─────────────────────────────────────────────

  /**
   * Returns a fresh copy of the hash key bytes from the given slot.
   * Returns an empty `Uint8Array` for an unset slot or siphash24's
   * no-internal-key path (callers distinguish by `length === 0` and
   * the slot they queried).
   */
  getKey(slot: BlobSlotValue | number | string): Uint8Array {
    const sl = resolveSlot(slot);
    const probe: [number | bigint] = [0];
    let rc = ITB_Blob_GetKey(this._handle, sl, null, 0, probe);
    if (rc !== Status.Ok && rc !== Status.BufferTooSmall) {
      throw errorFromStatus(rc);
    }
    const n = Number(probe[0]);
    if (n === 0) {
      return new Uint8Array(0);
    }
    const buf = new Uint8Array(n);
    const filled: [number | bigint] = [0];
    rc = ITB_Blob_GetKey(this._handle, sl, buf, n, filled);
    if (rc !== Status.Ok) {
      throw errorFromStatus(rc);
    }
    return buf.subarray(0, Number(filled[0]));
  }

  /**
   * Returns the seed components (array of unsigned 64-bit `bigint`s)
   * stored at the given slot. Returns an empty array for an unset
   * slot.
   */
  getComponents(slot: BlobSlotValue | number | string): bigint[] {
    const sl = resolveSlot(slot);
    const probe: [number | bigint] = [0];
    let rc = ITB_Blob_GetComponents(this._handle, sl, null, 0, probe);
    if (rc !== Status.Ok && rc !== Status.BufferTooSmall) {
      throw errorFromStatus(rc);
    }
    const n = Number(probe[0]);
    if (n === 0) {
      return [];
    }
    const buf = new BigUint64Array(n);
    const filled: [number | bigint] = [0];
    rc = ITB_Blob_GetComponents(this._handle, sl, buf, n, filled);
    if (rc !== Status.Ok) {
      throw errorFromStatus(rc);
    }
    return Array.from(buf.subarray(0, Number(filled[0])));
  }

  /**
   * Returns a fresh copy of the MAC key bytes from the handle, or
   * an empty `Uint8Array` if no MAC is associated.
   */
  getMacKey(): Uint8Array {
    const probe: [number | bigint] = [0];
    let rc = ITB_Blob_GetMACKey(this._handle, null, 0, probe);
    if (rc !== Status.Ok && rc !== Status.BufferTooSmall) {
      throw errorFromStatus(rc);
    }
    const n = Number(probe[0]);
    if (n === 0) {
      return new Uint8Array(0);
    }
    const buf = new Uint8Array(n);
    const filled: [number | bigint] = [0];
    rc = ITB_Blob_GetMACKey(this._handle, buf, n, filled);
    if (rc !== Status.Ok) {
      throw errorFromStatus(rc);
    }
    return buf.subarray(0, Number(filled[0]));
  }

  /**
   * Returns the MAC name from the handle, or an empty string if no
   * MAC is associated.
   */
  getMacName(): string {
    const handle = this._handle;
    const { rc, value } = readString((out, cap, outLen) =>
      ITB_Blob_GetMACName(handle, out, cap, outLen),
    );
    if (rc !== Status.Ok) {
      throw errorFromStatus(rc);
    }
    return value;
  }

  // ─── Export / Import ──────────────────────────────────────────

  /**
   * Serialises the handle's Single-Ouroboros state into a JSON
   * blob. The optional `opts` bitmask flips on the matching
   * sections: `BlobExportOpts.LockSeed` emits the `l` slot's KeyL +
   * components; `BlobExportOpts.Mac` emits the MAC key + name (both
   * must be non-empty on the handle). Multiple flags combine via
   * bitwise OR.
   */
  export(opts: number = BlobExportOpts.None): Uint8Array {
    return this.runExport(opts | 0, false);
  }

  /**
   * Serialises the handle's Triple-Ouroboros state into a JSON
   * blob. See `export` for the `opts` bitmask semantics.
   */
  exportTriple(opts: number = BlobExportOpts.None): Uint8Array {
    return this.runExport(opts | 0, true);
  }

  /**
   * Parses a Single-Ouroboros JSON blob, populates the handle's
   * slots, and applies the captured globals via the process-wide
   * setters.
   *
   * Raises `ITBBlobModeMismatchError` when the blob is Triple-mode,
   * `ITBBlobMalformedError` on parse / shape failure,
   * `ITBBlobVersionTooNewError` on a version field higher than this
   * build supports.
   */
  import(blob: Uint8Array): void {
    if (!(blob instanceof Uint8Array)) {
      throw new TypeError('blob must be a Uint8Array');
    }
    const ptr = blob.length > 0 ? blob : null;
    check(ITB_Blob_Import(this._handle, ptr, blob.length));
  }

  /**
   * Triple-Ouroboros counterpart of `import`. Same error
   * contract.
   */
  importTriple(blob: Uint8Array): void {
    if (!(blob instanceof Uint8Array)) {
      throw new TypeError('blob must be a Uint8Array');
    }
    const ptr = blob.length > 0 ? blob : null;
    check(ITB_Blob_Import3(this._handle, ptr, blob.length));
  }

  // ─── Lifecycle ────────────────────────────────────────────────

  /**
   * Releases the underlying libitb handle. Idempotent — the handle
   * field is zeroed after the first call so a second `free()` is a
   * no-op rather than a double-free panic. Mirrors `Seed.free` /
   * `MAC.free`: a non-OK status (typically `Status.BadHandle` if
   * the handle was already invalidated by a sibling thread) is
   * raised as `ITBError` rather than silently swallowed.
   */
  free(): void {
    if (isZero(this._handle)) {
      return;
    }
    const h = this._handle;
    this._handle = ZERO;
    blobFinalizer.unregister(this);
    check(ITB_Blob_Free(h));
  }

  [Symbol.dispose](): void {
    this.free();
  }

  // ─── Internal helpers ─────────────────────────────────────────

  private runExport(opts: number, triple: boolean): Uint8Array {
    const fn = triple ? ITB_Blob_Export3 : ITB_Blob_Export;
    const probe: [number | bigint] = [0];
    let rc = fn(this._handle, opts, null, 0, probe);
    if (rc !== Status.Ok && rc !== Status.BufferTooSmall) {
      throw errorFromStatus(rc);
    }
    const cap = Number(probe[0]);
    if (cap === 0) {
      return new Uint8Array(0);
    }
    const buf = new Uint8Array(cap);
    const filled: [number | bigint] = [0];
    rc = fn(this._handle, opts, buf, cap, filled);
    if (rc !== Status.Ok) {
      throw errorFromStatus(rc);
    }
    return buf.subarray(0, Number(filled[0]));
  }
}

// ──────────────────────────────────────────────────────────────────
// Width-typed wrapper classes.
// ──────────────────────────────────────────────────────────────────

/**
 * 128-bit width Blob — covers `siphash24` and `aescmac` primitives.
 * Hash key length is variable: empty for siphash24 (no internal
 * fixed key), 16 bytes for aescmac. The 128-bit width is reserved
 * for testing and below-spec stress controls; for production traffic
 * prefer `Blob256` or `Blob512`.
 */
export class Blob128 extends BlobBase {
  constructor() {
    super((out) => ITB_Blob128_New(out));
  }
}

/**
 * 256-bit width Blob — covers `areion256`, `blake2s`, `blake2b256`,
 * `blake3`, `chacha20`. Hash key length is fixed at 32 bytes.
 */
export class Blob256 extends BlobBase {
  constructor() {
    super((out) => ITB_Blob256_New(out));
  }
}

/**
 * 512-bit width Blob — covers `areion512` (via the SoEM-512
 * construction) and `blake2b512`. Hash key length is fixed at 64
 * bytes.
 */
export class Blob512 extends BlobBase {
  constructor() {
    super((out) => ITB_Blob512_New(out));
  }
}
