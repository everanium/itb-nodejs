// Status codes mirrored from the libitb C ABI
// (cmd/cshared/internal/capi/errors.go). Numeric values are stable
// across releases.

/** Integer status code returned by every libitb entry point. */
export enum Status {
  Ok = 0,
  BadHash = 1,
  BadKeyBits = 2,
  BadHandle = 3,
  BadInput = 4,
  BufferTooSmall = 5,
  EncryptFailed = 6,
  DecryptFailed = 7,
  SeedWidthMix = 8,
  BadMac = 9,
  MacFailure = 10,
  BlobModeMismatch = 19,
  BlobMalformed = 20,
  BlobVersionTooNew = 21,
  BlobTooManyOpts = 22,
  StreamTruncated = 23,
  StreamAfterFinal = 24,
  TripleClosed = 25,
  ProfileExists = 26,
  Internal = 99,
}

const LABELS: Readonly<Record<number, string>> = {
  [Status.Ok]: 'ok',
  [Status.BadHash]: 'unknown hash name',
  [Status.BadKeyBits]: 'invalid key bits',
  [Status.BadHandle]: 'invalid handle',
  [Status.BadInput]: 'invalid input',
  [Status.BufferTooSmall]: 'output buffer too small',
  [Status.EncryptFailed]: 'encrypt failed',
  [Status.DecryptFailed]: 'decrypt failed',
  [Status.SeedWidthMix]: 'seed width mismatch',
  [Status.BadMac]: 'unknown MAC name or invalid MAC handle',
  [Status.MacFailure]: 'MAC verification failed',
  [Status.BlobModeMismatch]: 'blob mode mismatch',
  [Status.BlobMalformed]: 'malformed state blob',
  [Status.BlobVersionTooNew]: 'blob version too new',
  [Status.BlobTooManyOpts]: 'too many blob export opts',
  [Status.StreamTruncated]: 'stream truncated before terminator',
  [Status.StreamAfterFinal]: 'stream chunk after terminator',
  [Status.TripleClosed]: 'Triple Pipeline is closed',
  [Status.ProfileExists]: 'profile name already registered',
  [Status.Internal]: 'internal error',
};

/** Short human-readable label for a status code. */
export function statusLabel(code: number): string {
  return LABELS[code] ?? `unknown status ${code}`;
}
