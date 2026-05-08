// Library-level metadata accessors and process-global setters.
//
// Exposes the libitb free-function surface that is not tied to a
// specific seed / MAC / encryptor instance: hash + MAC catalogs
// (`listHashes`, `listMacs`), `version`, the global getters / setters
// (`setBitSoup`, `setLockSoup`, `setMaxWorkers`, `setNonceBits`,
// `setBarrierFill` and their getter counterparts), key-budget /
// container helpers (`maxKeyBits`, `channels`, `headerSize`), and the
// `parseChunkLen` helper used by streaming consumers.

import { check, errorFromStatus } from './errors.js';
import {
  ITB_Channels,
  ITB_GetBarrierFill,
  ITB_GetBitSoup,
  ITB_GetLockSoup,
  ITB_GetMaxWorkers,
  ITB_GetNonceBits,
  ITB_HashCount,
  ITB_HashName,
  ITB_HashWidth,
  ITB_HeaderSize,
  ITB_MACCount,
  ITB_MACKeySize,
  ITB_MACMinKeyBytes,
  ITB_MACName,
  ITB_MACTagSize,
  ITB_MaxKeyBits,
  ITB_ParseChunkLen,
  ITB_SetBarrierFill,
  ITB_SetBitSoup,
  ITB_SetLockSoup,
  ITB_SetMaxWorkers,
  ITB_SetNonceBits,
  ITB_Version,
} from './native.js';
import { readString } from './read-string.js';
import { Status } from './status.js';

export interface HashEntry {
  readonly name: string;
  readonly width: number;
}

export interface MacEntry {
  readonly name: string;
  readonly keySize: number;
  readonly tagSize: number;
  readonly minKeyBytes: number;
}

export function version(): string {
  const { rc, value } = readString((out, cap, outLen) =>
    ITB_Version(out, cap, outLen),
  );
  if (rc !== Status.Ok) {
    throw errorFromStatus(rc);
  }
  return value;
}

export function listHashes(): HashEntry[] {
  const n = ITB_HashCount();
  const out: HashEntry[] = [];
  for (let i = 0; i < n; i++) {
    const { rc, value: name } = readString((buf, cap, outLen) =>
      ITB_HashName(i, buf, cap, outLen),
    );
    if (rc !== Status.Ok) {
      throw errorFromStatus(rc);
    }
    const width = ITB_HashWidth(i);
    out.push({ name, width });
  }
  return out;
}

export function listMacs(): MacEntry[] {
  const n = ITB_MACCount();
  const out: MacEntry[] = [];
  for (let i = 0; i < n; i++) {
    const { rc, value: name } = readString((buf, cap, outLen) =>
      ITB_MACName(i, buf, cap, outLen),
    );
    if (rc !== Status.Ok) {
      throw errorFromStatus(rc);
    }
    out.push({
      name,
      keySize: ITB_MACKeySize(i),
      tagSize: ITB_MACTagSize(i),
      minKeyBytes: ITB_MACMinKeyBytes(i),
    });
  }
  return out;
}

export function maxKeyBits(): number {
  return ITB_MaxKeyBits();
}

export function channels(): number {
  return ITB_Channels();
}

export function headerSize(): number {
  return ITB_HeaderSize();
}

export function parseChunkLen(header: Uint8Array): number {
  if (!(header instanceof Uint8Array)) {
    throw new TypeError('header must be a Uint8Array');
  }
  const out: [number | bigint] = [0];
  const rc = ITB_ParseChunkLen(header, header.length, out);
  check(rc);
  return Number(out[0]);
}

/**
 * Sets the process-wide Bit Soup mode (0 = byte-level split,
 * non-zero = bit-level Bit Soup split). Independent of
 * `setLockSoup` at the setter level — there is no
 * `BitSoup → LockSoup` cascade. In Single Ouroboros, either flag
 * alone activates the dispatcher's keyed bit-permutation overlay
 * (Single OR-gates the two flags).
 */
export function setBitSoup(mode: number): void {
  check(ITB_SetBitSoup(mode | 0));
}

export function getBitSoup(): number {
  return ITB_GetBitSoup();
}

/**
 * Sets the process-wide Lock Soup mode (0 = off, non-zero = on). A
 * non-zero value auto-couples `setBitSoup(1)` (Lock Soup overlay
 * layers on top of bit soup; one-direction cascade). The off-direction
 * does not auto-disable bit soup.
 */
export function setLockSoup(mode: number): void {
  check(ITB_SetLockSoup(mode | 0));
}

export function getLockSoup(): number {
  return ITB_GetLockSoup();
}

export function setMaxWorkers(n: number): void {
  check(ITB_SetMaxWorkers(n | 0));
}

export function getMaxWorkers(): number {
  return ITB_GetMaxWorkers();
}

/** Accepts 128, 256, 512. Other values raise `ITBError(BadInput)`. */
export function setNonceBits(n: number): void {
  check(ITB_SetNonceBits(n | 0));
}

export function getNonceBits(): number {
  return ITB_GetNonceBits();
}

/** Accepts 1, 2, 4, 8, 16, 32. Other values raise `ITBError(BadInput)`. */
export function setBarrierFill(n: number): void {
  check(ITB_SetBarrierFill(n | 0));
}

export function getBarrierFill(): number {
  return ITB_GetBarrierFill();
}
