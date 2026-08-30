// Incremental stream sessions over an open Pipeline.
//
// A session is a dumb byte pump: [EncryptStream] takes plaintext in
// through `write` and yields wire through `read` / `drainAll`;
// [DecryptStream] is the mirror (wire in, plaintext out). All
// chunking, MAC, envelope, and wire-format decisions stay inside
// libitb. The session keeps a reference to its parent Pipeline so
// the Pipeline handle cannot be finalized while a session is live.

import {
  type Handle,
  ITB_Triple_DecryptStreamBegin,
  ITB_Triple_EncryptStreamBegin,
  ITB_Triple_StreamEnd,
  ITB_Triple_StreamFree,
  ITB_Triple_StreamRead,
  ITB_Triple_StreamWrite,
} from './ffi.js';
import { check } from './error.js';
import type { Pipeline } from './pipeline.js';

/** Drain slice size used by drainAll / pump. */
const PUMP_BUF = 1 << 20;

function isZero(h: Handle): boolean {
  return h === 0 || h === 0n;
}

const finalizer = new FinalizationRegistry<Handle>((handle) => {
  try {
    if (!isZero(handle)) {
      ITB_Triple_StreamFree(handle);
    }
  } catch {
    // Best-effort backstop; finalization runs at unspecified times.
  }
});

abstract class StreamSession implements Disposable {
  private handle: Handle = 0;
  private ended = false;
  // Keeps the parent Pipeline reachable for the session's lifetime.
  private readonly pipe: Pipeline;

  protected constructor(pipe: Pipeline, encrypt: boolean) {
    const begin = encrypt ? ITB_Triple_EncryptStreamBegin : ITB_Triple_DecryptStreamBegin;
    const out: [Handle] = [0];
    check(begin(pipe._handle, out));
    this.handle = out[0]!;
    this.pipe = pipe;
    finalizer.register(this, this.handle, this);
    void this.pipe;
  }

  /**
   * Feeds `src` into the session. Blocks until the cipher chain
   * accepts the bytes; errors are sticky.
   */
  write(src: Uint8Array): void {
    check(ITB_Triple_StreamWrite(this.handle, src.length > 0 ? src : null, src.length));
  }

  /**
   * Signals end-of-input. Idempotent; `write` after `end` fails with
   * `BadInput`.
   */
  end(): void {
    check(ITB_Triple_StreamEnd(this.handle));
    this.ended = true;
  }

  /**
   * Drains up to `dst.length` produced bytes into `dst`; returns
   * `{ n, finished }`. Partial drains are normal. After `end`, an
   * empty-spool read blocks until the terminal bytes arrive or the
   * session errors.
   */
  read(dst: Uint8Array): { n: number; finished: boolean } {
    const outLen: [number | bigint] = [0];
    const fin: [number] = [0];
    check(ITB_Triple_StreamRead(this.handle, dst, dst.length, outLen, fin));
    return { n: Number(outLen[0]), finished: fin[0] !== 0 };
  }

  /**
   * Calls `end` (if not yet called) and returns every remaining
   * output byte as one Buffer.
   */
  drainAll(): Buffer {
    if (!this.ended) {
      this.end();
    }
    const parts: Buffer[] = [];
    const buf = new Uint8Array(PUMP_BUF);
    for (;;) {
      const { n, finished } = this.read(buf);
      if (n > 0) {
        parts.push(Buffer.from(buf.subarray(0, n)));
      }
      if (finished) {
        return Buffer.concat(parts);
      }
    }
  }

  /**
   * Pumps `chunks` through the session into `sink` with bounded
   * memory: feed a chunk, drain whatever the chain has produced so
   * far (a read before `end` never blocks), repeat; end + final
   * drain after the last chunk.
   */
  pump(chunks: Iterable<Uint8Array>, sink: (out: Buffer) => void): void {
    const buf = new Uint8Array(PUMP_BUF);
    for (const chunk of chunks) {
      this.write(chunk);
      for (;;) {
        const { n } = this.read(buf);
        if (n === 0) {
          break;
        }
        sink(Buffer.from(buf.subarray(0, n)));
      }
    }
    this.end();
    for (;;) {
      const { n, finished } = this.read(buf);
      if (n > 0) {
        sink(Buffer.from(buf.subarray(0, n)));
      }
      if (finished) {
        return;
      }
    }
  }

  /**
   * Cancels (if still running) and releases the session. Safe to
   * call from any state; safe to call more than once.
   */
  free(): void {
    if (isZero(this.handle)) {
      return;
    }
    finalizer.unregister(this);
    ITB_Triple_StreamFree(this.handle);
    this.handle = 0;
  }

  [Symbol.dispose](): void {
    this.free();
  }
}

/** Incremental encrypt session: plaintext in, wire out. */
export class EncryptStream extends StreamSession {
  /** @internal */
  static begin(pipe: Pipeline): EncryptStream {
    return new EncryptStream(pipe, true);
  }
}

/** Incremental decrypt session: wire in, plaintext out. */
export class DecryptStream extends StreamSession {
  /** @internal */
  static begin(pipe: Pipeline): DecryptStream {
    return new DecryptStream(pipe, false);
  }
}
