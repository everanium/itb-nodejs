// Status code constants returned by every libitb FFI entry point.
//
// Mirrors cmd/cshared/internal/capi/errors.go. The numeric layout is
// frozen — block 0..10 covers the low-level seed / encrypt / decrypt
// surface, block 11..18 covers the Easy encryptor, block 19..22
// covers Native Blob, and 99 is the catch-all internal error.
//
// `Status` is the public mirror — external consumers can match an
// `ITBError`'s `.code` against `Status.MacFailure`, `Status.BadInput`,
// etc., without depending on an `internal`-visibility table. (The
// FFI layer uses the same constants directly.)

export const Status = {
  Ok: 0,
  BadHash: 1,
  BadKeyBits: 2,
  BadHandle: 3,
  BadInput: 4,
  BufferTooSmall: 5,
  EncryptFailed: 6,
  DecryptFailed: 7,
  SeedWidthMix: 8,
  BadMac: 9,
  MacFailure: 10,
  // Easy encryptor surface — block 11..18.
  EasyClosed: 11,
  EasyMalformed: 12,
  EasyVersionTooNew: 13,
  EasyUnknownPrimitive: 14,
  EasyUnknownMac: 15,
  EasyBadKeyBits: 16,
  EasyMismatch: 17,
  EasyLockSeedAfterEncrypt: 18,
  // Native Blob surface — block 19..22.
  BlobModeMismatch: 19,
  BlobMalformed: 20,
  BlobVersionTooNew: 21,
  BlobTooManyOpts: 22,
  // Streaming AEAD sentinel codes — block 23..24.
  StreamTruncated: 23,
  StreamAfterFinal: 24,
  Internal: 99,
} as const;

export type StatusCode = typeof Status[keyof typeof Status];
