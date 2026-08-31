// URL-query builder for the opts pass-through string.
//
// The builder performs no validation — every key and value is
// rendered into a percent-encoded query string and passed through to
// Go verbatim; libitb rejects unknown keys or bad values with a
// diagnostic surfaced via [ItbError]. Primitive / MAC / cipher /
// palette names are opaque strings.

/**
 * Builder producing the URL-query-encoded opts string consumed by
 * `Pipeline.init`, `Pipeline.open`, and `registerProfile`. Fluent —
 * every setter mutates and returns the same instance.
 */
export class Opts {
  private readonly pairs: Array<[string, string]> = [];

  /** Hex-encodes the parallax master override (`pm`). */
  withPermMaster(master: Uint8Array): this {
    return this.withRaw('pm', hex(master));
  }

  /** Hex-encodes the wrapper master override (`wm`). */
  withWrapMaster(master: Uint8Array): this {
    return this.withRaw('wm', hex(master));
  }

  withParallax(on: boolean): this {
    return this.withRaw('withParallax', String(on));
  }

  withWrapper(on: boolean): this {
    return this.withRaw('withWrapper', String(on));
  }

  withMaxWorkers(n: number): this {
    return this.withRaw('maxWorkers', String(n));
  }

  withNonceBits(n: number): this {
    return this.withRaw('nonceBits', String(n));
  }

  withBarrierFill(n: number): this {
    return this.withRaw('barrierFill', String(n));
  }

  withChunkSize(n: number): this {
    return this.withRaw('chunkSize', String(n));
  }

  withKeyBits(n: number): this {
    return this.withRaw('keyBits', String(n));
  }

  withParallaxSegmentSize(n: number): this {
    return this.withRaw('parallaxSegmentSize', String(n));
  }

  withMacName(name: string): this {
    return this.withRaw('macName', name);
  }

  withInnerHash(name: string): this {
    return this.withRaw('innerHash', name);
  }

  /**
   * Comma-joins an 8-slot per-call inner-hash constellation into the
   * `innerHashes` opts key. Parallel to the Go-side
   * `Opts.MixedHashes [8]string` per-call override; slot ordering is
   * `[noise, lock, data1, data2, data3, start1, start2, start3]`.
   *
   * Fail-fast validation surfaces at Init on the Go side; a typo'd
   * slot or width mismatch surfaces with an error naming the
   * offending slot. When both this and `withInnerHash` are set, the
   * mixed override wins on the Go side.
   */
  withInnerHashes(names: readonly string[]): this {
    return this.withRaw('innerHashes', names.join(','));
  }

  withOuterCipher(name: string): this {
    return this.withRaw('outerCipher', name);
  }

  /** Comma-joins the palette names (`parallaxPalette`). */
  withParallaxPalette(names: readonly string[]): this {
    return this.withRaw('parallaxPalette', names.join(','));
  }

  /**
   * Escape hatch appending a raw `key=value` pair. Covers every key
   * the Go side accepts, including the register-profile grammar
   * (`mode`, `width`, `innerHashes`, `parallaxOn`, `wrapperOn`, …).
   */
  withRaw(key: string, value: string): this {
    this.pairs.push([key, value]);
    return this;
  }

  /** Renders the accumulated pairs as a query string. */
  build(): string {
    return this.pairs.map(([k, v]) => `${enc(k)}=${enc(v)}`).join('&');
  }
}

// Minimal percent-encoding: the accepted values are ASCII names,
// decimal integers, true / false, hex, and comma-separated lists, so
// everything outside the URL-safe subset (plus `,`) is escaped
// byte-wise.
function enc(s: string): string {
  let out = '';
  for (const b of new TextEncoder().encode(s)) {
    const c = String.fromCharCode(b);
    if (/[A-Za-z0-9\-._~,]/.test(c)) {
      out += c;
    } else {
      out += `%${b.toString(16).toUpperCase().padStart(2, '0')}`;
    }
  }
  return out;
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}
