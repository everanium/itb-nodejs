// Handle to one ITB seed.
//
// Provides a thin wrapper over `ITB_NewSeed` / `ITB_FreeSeed` plus
// the introspection accessors and the deterministic-rebuild path
// `Seed.fromComponents`. The libitb handle is owned by the wrapper
// and released via [Symbol.dispose] / .free() or, as a backstop, by
// a FinalizationRegistry cleanup callback when the wrapper becomes
// unreachable. Prefer `using` declarations for deterministic
// lifetime; FinalizationRegistry runs at unspecified times and is
// best-effort only.
//
// Lock-seed lifecycle. `attachLockSeed` records the lock seed
// pointer on the noise seed but does not transfer ownership.
// Releasing the lock seed via `lockSeed.free()` (or letting it fall
// out of scope under `using`) before the noise seed has finished
// its useful lifetime invalidates the bit-permutation overlay
// derivation; subsequent encrypt calls panic via
// `ErrLockSeedOverlayOff` or use zeroed components. Standard
// pairing: keep the lock seed alive at least as long as the
// noise seed.

import { check, errorFromStatus } from './errors.js';
import {
  ITB_AttachLockSeed,
  ITB_FreeSeed,
  ITB_GetSeedComponents,
  ITB_GetSeedHashKey,
  ITB_NewSeed,
  ITB_NewSeedFromComponents,
  ITB_SeedWidth,
} from './native.js';
import { Status } from './status.js';

type Handle = bigint | number;

const ZERO: Handle = 0;

function isZero(h: Handle): boolean {
  return h === 0 || h === 0n;
}

const seedFinalizer = new FinalizationRegistry<Handle>((handle) => {
  try {
    if (!isZero(handle)) {
      ITB_FreeSeed(handle);
    }
  } catch {
    // Best-effort; finalization runs at unspecified times.
  }
});

export class Seed implements Disposable {
  /** @internal */
  _handle: Handle = ZERO;
  readonly hashName: string;

  /**
   * @param hashName Canonical hash name from `listHashes()`, e.g.
   *   `"blake3"`, `"areion256"`.
   * @param keyBits ITB key width in bits — 512, 1024, 2048
   *   (multiple of 64).
   */
  constructor(hashName: string, keyBits: number) {
    const out: [Handle] = [ZERO];
    check(ITB_NewSeed(hashName, keyBits | 0, out));
    this._handle = out[0]!;
    this.hashName = hashName;
    seedFinalizer.register(this, this._handle, this);
  }

  /**
   * Builds a seed deterministically from caller-supplied uint64
   * components and an optional fixed hash key. Use this on the
   * persistence-restore path; leave `hashKey` empty for a
   * CSPRNG-generated key (still useful when only the components
   * need to be deterministic).
   *
   * Components length must be 8..32 (multiple of 8). When non-empty,
   * `hashKey` length must match the primitive's native fixed-key
   * size: 16 (aescmac), 32 (areion256 / blake2{s,b256} / blake3 /
   * chacha20), 64 (areion512 / blake2b512). Pass an empty buffer
   * for `siphash24` (no internal fixed key).
   */
  static fromComponents(
    hashName: string,
    components: readonly bigint[],
    hashKey: Uint8Array = new Uint8Array(0),
  ): Seed {
    if (!(hashKey instanceof Uint8Array)) {
      throw new TypeError('hashKey must be a Uint8Array');
    }
    const compsArr = BigUint64Array.from(components);
    const out: [Handle] = [ZERO];
    const rc = ITB_NewSeedFromComponents(
      hashName,
      compsArr,
      compsArr.length | 0,
      hashKey.length > 0 ? hashKey : null,
      hashKey.length | 0,
      out,
    );
    check(rc);
    // Bypass the public `new Seed(...)` constructor (which would
    // call ITB_NewSeed) and adopt the freshly-allocated handle.
    const inst = Object.create(Seed.prototype) as Seed;
    inst._handle = out[0]!;
    Object.defineProperty(inst, 'hashName', {
      value: hashName,
      writable: false,
      enumerable: true,
      configurable: false,
    });
    seedFinalizer.register(inst, inst._handle, inst);
    return inst;
  }

  get handle(): Handle {
    return this._handle;
  }

  get width(): number {
    const st: [number] = [0];
    const w = ITB_SeedWidth(this._handle, st);
    if (st[0] !== Status.Ok) {
      throw errorFromStatus(st[0]);
    }
    return w;
  }

  get hashKey(): Uint8Array {
    const probe: [number | bigint] = [0];
    let rc = ITB_GetSeedHashKey(this._handle, null, 0, probe);
    if (rc === Status.Ok && Number(probe[0]) === 0) {
      return new Uint8Array(0);
    }
    if (rc !== Status.BufferTooSmall) {
      throw errorFromStatus(rc);
    }
    const cap = Number(probe[0]);
    const buf = new Uint8Array(cap);
    const filled: [number | bigint] = [0];
    rc = ITB_GetSeedHashKey(this._handle, buf, cap, filled);
    check(rc);
    return buf.subarray(0, Number(filled[0]));
  }

  get components(): bigint[] {
    const probe: [number] = [0];
    let rc = ITB_GetSeedComponents(this._handle, null, 0, probe);
    if (rc !== Status.BufferTooSmall) {
      throw errorFromStatus(rc);
    }
    const n = probe[0]!;
    const buf = new BigUint64Array(n);
    const filled: [number] = [0];
    rc = ITB_GetSeedComponents(this._handle, buf, n, filled);
    check(rc);
    return Array.from(buf.subarray(0, filled[0]));
  }

  /**
   * Wires a dedicated lockSeed onto this noise seed. The per-chunk
   * PRF closure for the bit-permutation overlay captures both the
   * lockSeed's components and its hash function — keying-material
   * isolation plus algorithm diversity for defence-in-depth on the
   * overlay channel. Both seeds must share the same native hash
   * width.
   *
   * The dedicated lockSeed has no observable effect on the wire
   * output unless the bit-permutation overlay is engaged via
   * `setBitSoup(1)` or `setLockSoup(1)` before the first encrypt /
   * decrypt call.
   *
   * The dedicated lockSeed remains owned by the caller — attach
   * only records the pointer on the noise seed, so keep the
   * lockSeed alive for the lifetime of the noise seed.
   */
  attachLockSeed(lockSeed: Seed): void {
    if (!(lockSeed instanceof Seed)) {
      throw new TypeError('lockSeed must be a Seed instance');
    }
    check(ITB_AttachLockSeed(this._handle, lockSeed.handle));
  }

  free(): void {
    if (isZero(this._handle)) {
      return;
    }
    const h = this._handle;
    this._handle = ZERO;
    seedFinalizer.unregister(this);
    check(ITB_FreeSeed(h));
  }

  [Symbol.dispose](): void {
    this.free();
  }
}
