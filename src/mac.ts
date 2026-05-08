// Handle to one keyed MAC primitive.
//
// Provides a thin wrapper over `ITB_NewMAC` / `ITB_FreeMAC` for use
// with the authenticated encrypt / decrypt entry points. The libitb
// handle is owned by the wrapper and released via [Symbol.dispose] /
// .free() or, as a backstop, by a FinalizationRegistry cleanup
// callback when the wrapper becomes unreachable.

import { check } from './errors.js';
import { ITB_FreeMAC, ITB_NewMAC } from './native.js';

type Handle = bigint | number;

const ZERO: Handle = 0;

function isZero(h: Handle): boolean {
  return h === 0 || h === 0n;
}

const macFinalizer = new FinalizationRegistry<Handle>((handle) => {
  try {
    if (!isZero(handle)) {
      ITB_FreeMAC(handle);
    }
  } catch {
    // Best-effort; finalization runs at unspecified times.
  }
});

export class MAC implements Disposable {
  /** @internal */
  _handle: Handle = ZERO;
  readonly name: string;

  /**
   * @param macName Canonical MAC name from `listMacs()`:
   *   `"kmac256"`, `"hmac-sha256"`, or `"hmac-blake3"`.
   * @param key Key bytes. Length must be at least the primitive's
   *   `min_key_bytes` (16 for kmac256 / hmac-sha256, 32 for
   *   hmac-blake3).
   */
  constructor(macName: string, key: Uint8Array) {
    if (!(key instanceof Uint8Array)) {
      throw new TypeError('key must be a Uint8Array');
    }
    const out: [Handle] = [ZERO];
    check(ITB_NewMAC(macName, key, key.length, out));
    this._handle = out[0]!;
    this.name = macName;
    macFinalizer.register(this, this._handle, this);
  }

  get handle(): Handle {
    return this._handle;
  }

  free(): void {
    if (isZero(this._handle)) {
      return;
    }
    const h = this._handle;
    this._handle = ZERO;
    macFinalizer.unregister(this);
    check(ITB_FreeMAC(h));
  }

  [Symbol.dispose](): void {
    this.free();
  }
}
