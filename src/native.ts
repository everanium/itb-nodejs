// koffi extern declarations for the libitb C ABI surface.
//
// Every libitb entry point returns `int` (a status code from `Status`
// in `./status.ts`); output buffers / handles / counters are written
// through pointer parameters annotated `_Out_` (koffi writes back
// into a 1-element array passed by the caller).
//
// Output string buffers in libitb are declared as `char *` in the C
// ABI but are not NUL-terminated text — the libitb convention is
// "UTF-8 bytes including a trailing 0x00, with `outLen` reporting
// the byte count INCLUDING the terminator". To bypass koffi's
// auto-string coercion (which would silently truncate at the first
// internal 0x00 if any ever appeared), every such parameter is
// declared as `uint8_t *` here; callers receive a `Uint8Array` and
// decode UTF-8 manually using `outLen - 1` (see `./read-string.ts`).

import { lib } from './library-loader.js';

// ──────────────────────────────────────────────────────────────────
// Library-level metadata + diagnostic surface.
// ──────────────────────────────────────────────────────────────────

export const ITB_Version = lib.func(
  'int ITB_Version(uint8_t *out, size_t capBytes, _Out_ size_t *outLen)',
);
export const ITB_HashCount = lib.func('int ITB_HashCount()');
export const ITB_HashName = lib.func(
  'int ITB_HashName(int i, uint8_t *out, size_t capBytes, _Out_ size_t *outLen)',
);
export const ITB_HashWidth = lib.func('int ITB_HashWidth(int i)');
export const ITB_LastError = lib.func(
  'int ITB_LastError(uint8_t *out, size_t capBytes, _Out_ size_t *outLen)',
);

// ──────────────────────────────────────────────────────────────────
// Seed lifecycle + introspection.
// ──────────────────────────────────────────────────────────────────

export const ITB_NewSeed = lib.func(
  'int ITB_NewSeed(const char *hashName, int keyBits, _Out_ uintptr_t *outHandle)',
);
export const ITB_FreeSeed = lib.func('int ITB_FreeSeed(uintptr_t handle)');
export const ITB_SeedWidth = lib.func(
  'int ITB_SeedWidth(uintptr_t handle, _Out_ int *outStatus)',
);
export const ITB_SeedHashName = lib.func(
  'int ITB_SeedHashName(uintptr_t handle, uint8_t *out, size_t capBytes, _Out_ size_t *outLen)',
);

export const ITB_AttachLockSeed = lib.func(
  'int ITB_AttachLockSeed(uintptr_t noiseHandle, uintptr_t lockHandle)',
);

export const ITB_NewSeedFromComponents = lib.func(
  'int ITB_NewSeedFromComponents(' +
    'const char *hashName, ' +
    'uint64_t *components, int componentsLen, ' +
    'uint8_t *hashKey, int hashKeyLen, ' +
    '_Out_ uintptr_t *outHandle)',
);
export const ITB_GetSeedHashKey = lib.func(
  'int ITB_GetSeedHashKey(uintptr_t handle, uint8_t *out, size_t capBytes, _Out_ size_t *outLen)',
);
export const ITB_GetSeedComponents = lib.func(
  'int ITB_GetSeedComponents(uintptr_t handle, uint64_t *out, int capCount, _Out_ int *outLen)',
);

// ──────────────────────────────────────────────────────────────────
// Single-Ouroboros encrypt / decrypt (low-level seed trio).
// ──────────────────────────────────────────────────────────────────

export const ITB_Encrypt = lib.func(
  'int ITB_Encrypt(' +
    'uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle, ' +
    'uint8_t *plaintext, size_t ptlen, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);
export const ITB_Decrypt = lib.func(
  'int ITB_Decrypt(' +
    'uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle, ' +
    'uint8_t *ciphertext, size_t ctlen, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);

// ──────────────────────────────────────────────────────────────────
// Triple-Ouroboros encrypt / decrypt (low-level seven-seed shape).
// ──────────────────────────────────────────────────────────────────

export const ITB_Encrypt3 = lib.func(
  'int ITB_Encrypt3(' +
    'uintptr_t noiseHandle, ' +
    'uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3, ' +
    'uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3, ' +
    'uint8_t *plaintext, size_t ptlen, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);
export const ITB_Decrypt3 = lib.func(
  'int ITB_Decrypt3(' +
    'uintptr_t noiseHandle, ' +
    'uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3, ' +
    'uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3, ' +
    'uint8_t *ciphertext, size_t ctlen, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);

// ──────────────────────────────────────────────────────────────────
// MAC registry + lifecycle.
// ──────────────────────────────────────────────────────────────────

export const ITB_MACCount = lib.func('int ITB_MACCount()');
export const ITB_MACName = lib.func(
  'int ITB_MACName(int i, uint8_t *out, size_t capBytes, _Out_ size_t *outLen)',
);
export const ITB_MACKeySize = lib.func('int ITB_MACKeySize(int i)');
export const ITB_MACTagSize = lib.func('int ITB_MACTagSize(int i)');
export const ITB_MACMinKeyBytes = lib.func('int ITB_MACMinKeyBytes(int i)');
export const ITB_NewMAC = lib.func(
  'int ITB_NewMAC(const char *macName, uint8_t *key, size_t keyLen, _Out_ uintptr_t *outHandle)',
);
export const ITB_FreeMAC = lib.func('int ITB_FreeMAC(uintptr_t handle)');

// ──────────────────────────────────────────────────────────────────
// Authenticated encrypt / decrypt (Single + Triple).
// ──────────────────────────────────────────────────────────────────

export const ITB_EncryptAuth = lib.func(
  'int ITB_EncryptAuth(' +
    'uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle, ' +
    'uintptr_t macHandle, ' +
    'uint8_t *plaintext, size_t ptlen, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);
export const ITB_DecryptAuth = lib.func(
  'int ITB_DecryptAuth(' +
    'uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle, ' +
    'uintptr_t macHandle, ' +
    'uint8_t *ciphertext, size_t ctlen, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);

export const ITB_EncryptAuth3 = lib.func(
  'int ITB_EncryptAuth3(' +
    'uintptr_t noiseHandle, ' +
    'uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3, ' +
    'uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3, ' +
    'uintptr_t macHandle, ' +
    'uint8_t *plaintext, size_t ptlen, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);
export const ITB_DecryptAuth3 = lib.func(
  'int ITB_DecryptAuth3(' +
    'uintptr_t noiseHandle, ' +
    'uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3, ' +
    'uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3, ' +
    'uintptr_t macHandle, ' +
    'uint8_t *ciphertext, size_t ctlen, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);

// ──────────────────────────────────────────────────────────────────
// Process-global configuration setters / getters.
// ──────────────────────────────────────────────────────────────────

export const ITB_SetBitSoup = lib.func('int ITB_SetBitSoup(int mode)');
export const ITB_GetBitSoup = lib.func('int ITB_GetBitSoup()');
export const ITB_SetLockSoup = lib.func('int ITB_SetLockSoup(int mode)');
export const ITB_GetLockSoup = lib.func('int ITB_GetLockSoup()');
export const ITB_SetMaxWorkers = lib.func('int ITB_SetMaxWorkers(int n)');
export const ITB_GetMaxWorkers = lib.func('int ITB_GetMaxWorkers()');
export const ITB_SetNonceBits = lib.func('int ITB_SetNonceBits(int n)');
export const ITB_GetNonceBits = lib.func('int ITB_GetNonceBits()');
export const ITB_SetBarrierFill = lib.func('int ITB_SetBarrierFill(int n)');
export const ITB_GetBarrierFill = lib.func('int ITB_GetBarrierFill()');
export const ITB_SetMemoryLimit = lib.func(
  'int64_t ITB_SetMemoryLimit(int64_t limit)',
);
export const ITB_SetGCPercent = lib.func('int ITB_SetGCPercent(int pct)');

export const ITB_MaxKeyBits = lib.func('int ITB_MaxKeyBits()');
export const ITB_Channels = lib.func('int ITB_Channels()');
export const ITB_HeaderSize = lib.func('int ITB_HeaderSize()');

export const ITB_ParseChunkLen = lib.func(
  'int ITB_ParseChunkLen(uint8_t *header, size_t headerLen, _Out_ size_t *outChunkLen)',
);

// ──────────────────────────────────────────────────────────────────
// Easy encryptor surface — wraps github.com/everanium/itb/easy.
// ──────────────────────────────────────────────────────────────────

export const ITB_Easy_New = lib.func(
  'int ITB_Easy_New(const char *primitive, int keyBits, const char *macName, int mode, ' +
    '_Out_ uintptr_t *outHandle)',
);
export const ITB_Easy_NewMixed = lib.func(
  'int ITB_Easy_NewMixed(' +
    'const char *primN, const char *primD, const char *primS, const char *primL, ' +
    'int keyBits, const char *macName, ' +
    '_Out_ uintptr_t *outHandle)',
);
export const ITB_Easy_NewMixed3 = lib.func(
  'int ITB_Easy_NewMixed3(' +
    'const char *primN, ' +
    'const char *primD1, const char *primD2, const char *primD3, ' +
    'const char *primS1, const char *primS2, const char *primS3, ' +
    'const char *primL, ' +
    'int keyBits, const char *macName, ' +
    '_Out_ uintptr_t *outHandle)',
);
export const ITB_Easy_Free = lib.func('int ITB_Easy_Free(uintptr_t handle)');
export const ITB_Easy_PrimitiveAt = lib.func(
  'int ITB_Easy_PrimitiveAt(uintptr_t handle, int slot, ' +
    'uint8_t *out, size_t capBytes, _Out_ size_t *outLen)',
);
export const ITB_Easy_IsMixed = lib.func(
  'int ITB_Easy_IsMixed(uintptr_t handle, _Out_ int *outStatus)',
);

export const ITB_Easy_Encrypt = lib.func(
  'int ITB_Easy_Encrypt(uintptr_t handle, ' +
    'uint8_t *plaintext, size_t ptlen, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);
export const ITB_Easy_Decrypt = lib.func(
  'int ITB_Easy_Decrypt(uintptr_t handle, ' +
    'uint8_t *ciphertext, size_t ctlen, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);
export const ITB_Easy_EncryptAuth = lib.func(
  'int ITB_Easy_EncryptAuth(uintptr_t handle, ' +
    'uint8_t *plaintext, size_t ptlen, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);
export const ITB_Easy_DecryptAuth = lib.func(
  'int ITB_Easy_DecryptAuth(uintptr_t handle, ' +
    'uint8_t *ciphertext, size_t ctlen, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);

export const ITB_Easy_SetNonceBits = lib.func(
  'int ITB_Easy_SetNonceBits(uintptr_t handle, int n)',
);
export const ITB_Easy_SetBarrierFill = lib.func(
  'int ITB_Easy_SetBarrierFill(uintptr_t handle, int n)',
);
export const ITB_Easy_SetBitSoup = lib.func(
  'int ITB_Easy_SetBitSoup(uintptr_t handle, int mode)',
);
export const ITB_Easy_SetLockSoup = lib.func(
  'int ITB_Easy_SetLockSoup(uintptr_t handle, int mode)',
);
export const ITB_Easy_SetLockSeed = lib.func(
  'int ITB_Easy_SetLockSeed(uintptr_t handle, int mode)',
);
export const ITB_Easy_SetChunkSize = lib.func(
  'int ITB_Easy_SetChunkSize(uintptr_t handle, int n)',
);

export const ITB_Easy_Primitive = lib.func(
  'int ITB_Easy_Primitive(uintptr_t handle, uint8_t *out, size_t capBytes, _Out_ size_t *outLen)',
);
export const ITB_Easy_KeyBits = lib.func(
  'int ITB_Easy_KeyBits(uintptr_t handle, _Out_ int *outStatus)',
);
export const ITB_Easy_Mode = lib.func(
  'int ITB_Easy_Mode(uintptr_t handle, _Out_ int *outStatus)',
);
export const ITB_Easy_MACName = lib.func(
  'int ITB_Easy_MACName(uintptr_t handle, uint8_t *out, size_t capBytes, _Out_ size_t *outLen)',
);

export const ITB_Easy_SeedCount = lib.func(
  'int ITB_Easy_SeedCount(uintptr_t handle, _Out_ int *outStatus)',
);
export const ITB_Easy_SeedComponents = lib.func(
  'int ITB_Easy_SeedComponents(uintptr_t handle, int slot, ' +
    'uint64_t *out, int capCount, _Out_ int *outLen)',
);
export const ITB_Easy_HasPRFKeys = lib.func(
  'int ITB_Easy_HasPRFKeys(uintptr_t handle, _Out_ int *outStatus)',
);
export const ITB_Easy_PRFKey = lib.func(
  'int ITB_Easy_PRFKey(uintptr_t handle, int slot, ' +
    'uint8_t *out, size_t capBytes, _Out_ size_t *outLen)',
);
export const ITB_Easy_MACKey = lib.func(
  'int ITB_Easy_MACKey(uintptr_t handle, uint8_t *out, size_t capBytes, _Out_ size_t *outLen)',
);

export const ITB_Easy_Close = lib.func('int ITB_Easy_Close(uintptr_t handle)');

export const ITB_Easy_Export = lib.func(
  'int ITB_Easy_Export(uintptr_t handle, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);
export const ITB_Easy_Import = lib.func(
  'int ITB_Easy_Import(uintptr_t handle, uint8_t *blob, size_t blobLen)',
);
export const ITB_Easy_PeekConfig = lib.func(
  'int ITB_Easy_PeekConfig(' +
    'uint8_t *blob, size_t blobLen, ' +
    'uint8_t *primOut, size_t primCap, _Out_ size_t *primLen, ' +
    '_Out_ int *keyBitsOut, _Out_ int *modeOut, ' +
    'uint8_t *macOut, size_t macCap, _Out_ size_t *macLen)',
);
export const ITB_Easy_LastMismatchField = lib.func(
  'int ITB_Easy_LastMismatchField(uint8_t *out, size_t capBytes, _Out_ size_t *outLen)',
);

export const ITB_Easy_NonceBits = lib.func(
  'int ITB_Easy_NonceBits(uintptr_t handle, _Out_ int *outStatus)',
);
export const ITB_Easy_HeaderSize = lib.func(
  'int ITB_Easy_HeaderSize(uintptr_t handle, _Out_ int *outStatus)',
);
export const ITB_Easy_ParseChunkLen = lib.func(
  'int ITB_Easy_ParseChunkLen(uintptr_t handle, ' +
    'uint8_t *header, size_t headerLen, _Out_ size_t *outChunkLen)',
);

// ──────────────────────────────────────────────────────────────────
// Native Blob — low-level state persistence (Blob128 / 256 / 512).
// ──────────────────────────────────────────────────────────────────

export const ITB_Blob128_New = lib.func(
  'int ITB_Blob128_New(_Out_ uintptr_t *outHandle)',
);
export const ITB_Blob256_New = lib.func(
  'int ITB_Blob256_New(_Out_ uintptr_t *outHandle)',
);
export const ITB_Blob512_New = lib.func(
  'int ITB_Blob512_New(_Out_ uintptr_t *outHandle)',
);
export const ITB_Blob_Free = lib.func('int ITB_Blob_Free(uintptr_t handle)');

export const ITB_Blob_Width = lib.func(
  'int ITB_Blob_Width(uintptr_t handle, _Out_ int *outStatus)',
);
export const ITB_Blob_Mode = lib.func(
  'int ITB_Blob_Mode(uintptr_t handle, _Out_ int *outStatus)',
);

export const ITB_Blob_SetKey = lib.func(
  'int ITB_Blob_SetKey(uintptr_t handle, int slot, uint8_t *key, size_t keyLen)',
);
export const ITB_Blob_GetKey = lib.func(
  'int ITB_Blob_GetKey(uintptr_t handle, int slot, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);

export const ITB_Blob_SetComponents = lib.func(
  'int ITB_Blob_SetComponents(uintptr_t handle, int slot, ' +
    'uint64_t *comps, size_t count)',
);
export const ITB_Blob_GetComponents = lib.func(
  'int ITB_Blob_GetComponents(uintptr_t handle, int slot, ' +
    'uint64_t *out, size_t outCap, _Out_ size_t *outCount)',
);

export const ITB_Blob_SetMACKey = lib.func(
  'int ITB_Blob_SetMACKey(uintptr_t handle, uint8_t *key, size_t keyLen)',
);
export const ITB_Blob_GetMACKey = lib.func(
  'int ITB_Blob_GetMACKey(uintptr_t handle, uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);

export const ITB_Blob_SetMACName = lib.func(
  'int ITB_Blob_SetMACName(uintptr_t handle, uint8_t *name, size_t nameLen)',
);
export const ITB_Blob_GetMACName = lib.func(
  'int ITB_Blob_GetMACName(uintptr_t handle, uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);

export const ITB_Blob_Export = lib.func(
  'int ITB_Blob_Export(uintptr_t handle, int optsBitmask, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);
export const ITB_Blob_Export3 = lib.func(
  'int ITB_Blob_Export3(uintptr_t handle, int optsBitmask, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);
export const ITB_Blob_Import = lib.func(
  'int ITB_Blob_Import(uintptr_t handle, uint8_t *blob, size_t blobLen)',
);
export const ITB_Blob_Import3 = lib.func(
  'int ITB_Blob_Import3(uintptr_t handle, uint8_t *blob, size_t blobLen)',
);

// ──────────────────────────────────────────────────────────────────
// Streaming AEAD per-chunk dispatch — Single Ouroboros (3 seeds + MAC).
// streamID points to a 32-byte buffer (length fixed by the
// Streaming AEAD construction). cumulativePixelOffset is the running
// sum of W*H over preceding chunks; finalFlag is non-zero for the
// terminating chunk. finalFlagOut on the decrypt side receives the
// recovered flag value (0 / 1).
// ──────────────────────────────────────────────────────────────────

export const ITB_EncryptStreamAuthenticated128 = lib.func(
  'int ITB_EncryptStreamAuthenticated128(' +
    'uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle, ' +
    'uintptr_t macHandle, ' +
    'uint8_t *plaintext, size_t ptlen, ' +
    'uint8_t *streamID, uint64_t cumulativePixelOffset, int finalFlag, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);
export const ITB_EncryptStreamAuthenticated256 = lib.func(
  'int ITB_EncryptStreamAuthenticated256(' +
    'uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle, ' +
    'uintptr_t macHandle, ' +
    'uint8_t *plaintext, size_t ptlen, ' +
    'uint8_t *streamID, uint64_t cumulativePixelOffset, int finalFlag, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);
export const ITB_EncryptStreamAuthenticated512 = lib.func(
  'int ITB_EncryptStreamAuthenticated512(' +
    'uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle, ' +
    'uintptr_t macHandle, ' +
    'uint8_t *plaintext, size_t ptlen, ' +
    'uint8_t *streamID, uint64_t cumulativePixelOffset, int finalFlag, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);

export const ITB_DecryptStreamAuthenticated128 = lib.func(
  'int ITB_DecryptStreamAuthenticated128(' +
    'uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle, ' +
    'uintptr_t macHandle, ' +
    'uint8_t *ciphertext, size_t ctlen, ' +
    'uint8_t *streamID, uint64_t cumulativePixelOffset, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen, ' +
    '_Out_ int *finalFlagOut)',
);
export const ITB_DecryptStreamAuthenticated256 = lib.func(
  'int ITB_DecryptStreamAuthenticated256(' +
    'uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle, ' +
    'uintptr_t macHandle, ' +
    'uint8_t *ciphertext, size_t ctlen, ' +
    'uint8_t *streamID, uint64_t cumulativePixelOffset, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen, ' +
    '_Out_ int *finalFlagOut)',
);
export const ITB_DecryptStreamAuthenticated512 = lib.func(
  'int ITB_DecryptStreamAuthenticated512(' +
    'uintptr_t noiseHandle, uintptr_t dataHandle, uintptr_t startHandle, ' +
    'uintptr_t macHandle, ' +
    'uint8_t *ciphertext, size_t ctlen, ' +
    'uint8_t *streamID, uint64_t cumulativePixelOffset, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen, ' +
    '_Out_ int *finalFlagOut)',
);

// Triple Ouroboros (7 seeds + MAC) per-chunk Streaming AEAD dispatch.

export const ITB_EncryptStreamAuthenticated3x128 = lib.func(
  'int ITB_EncryptStreamAuthenticated3x128(' +
    'uintptr_t noiseHandle, ' +
    'uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3, ' +
    'uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3, ' +
    'uintptr_t macHandle, ' +
    'uint8_t *plaintext, size_t ptlen, ' +
    'uint8_t *streamID, uint64_t cumulativePixelOffset, int finalFlag, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);
export const ITB_EncryptStreamAuthenticated3x256 = lib.func(
  'int ITB_EncryptStreamAuthenticated3x256(' +
    'uintptr_t noiseHandle, ' +
    'uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3, ' +
    'uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3, ' +
    'uintptr_t macHandle, ' +
    'uint8_t *plaintext, size_t ptlen, ' +
    'uint8_t *streamID, uint64_t cumulativePixelOffset, int finalFlag, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);
export const ITB_EncryptStreamAuthenticated3x512 = lib.func(
  'int ITB_EncryptStreamAuthenticated3x512(' +
    'uintptr_t noiseHandle, ' +
    'uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3, ' +
    'uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3, ' +
    'uintptr_t macHandle, ' +
    'uint8_t *plaintext, size_t ptlen, ' +
    'uint8_t *streamID, uint64_t cumulativePixelOffset, int finalFlag, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);

export const ITB_DecryptStreamAuthenticated3x128 = lib.func(
  'int ITB_DecryptStreamAuthenticated3x128(' +
    'uintptr_t noiseHandle, ' +
    'uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3, ' +
    'uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3, ' +
    'uintptr_t macHandle, ' +
    'uint8_t *ciphertext, size_t ctlen, ' +
    'uint8_t *streamID, uint64_t cumulativePixelOffset, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen, ' +
    '_Out_ int *finalFlagOut)',
);
export const ITB_DecryptStreamAuthenticated3x256 = lib.func(
  'int ITB_DecryptStreamAuthenticated3x256(' +
    'uintptr_t noiseHandle, ' +
    'uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3, ' +
    'uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3, ' +
    'uintptr_t macHandle, ' +
    'uint8_t *ciphertext, size_t ctlen, ' +
    'uint8_t *streamID, uint64_t cumulativePixelOffset, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen, ' +
    '_Out_ int *finalFlagOut)',
);
export const ITB_DecryptStreamAuthenticated3x512 = lib.func(
  'int ITB_DecryptStreamAuthenticated3x512(' +
    'uintptr_t noiseHandle, ' +
    'uintptr_t dataHandle1, uintptr_t dataHandle2, uintptr_t dataHandle3, ' +
    'uintptr_t startHandle1, uintptr_t startHandle2, uintptr_t startHandle3, ' +
    'uintptr_t macHandle, ' +
    'uint8_t *ciphertext, size_t ctlen, ' +
    'uint8_t *streamID, uint64_t cumulativePixelOffset, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen, ' +
    '_Out_ int *finalFlagOut)',
);

// Easy Mode Streaming AEAD per-chunk dispatch (driven by the
// encryptor handle rather than separate seed + MAC handles).

export const ITB_Easy_EncryptStreamAuth = lib.func(
  'int ITB_Easy_EncryptStreamAuth(uintptr_t handle, ' +
    'uint8_t *plaintext, size_t ptlen, ' +
    'uint8_t *streamID, uint64_t cumulativePixelOffset, int finalFlag, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);
export const ITB_Easy_DecryptStreamAuth = lib.func(
  'int ITB_Easy_DecryptStreamAuth(uintptr_t handle, ' +
    'uint8_t *ciphertext, size_t ctlen, ' +
    'uint8_t *streamID, uint64_t cumulativePixelOffset, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen, ' +
    '_Out_ int *finalFlagOut)',
);

// ──────────────────────────────────────────────────────────────────
// Format-deniability wrapper — outer cipher envelope over an ITB
// ciphertext / bytestream. Three outer ciphers are supported (`"aes"`
// / `"chacha"` / `"siphash"`); the wire format is
// `nonce || keystream-XOR(blob)`. See bindings/nodejs/src/wrapper.ts
// for the typed-idiomatic surface.
// ──────────────────────────────────────────────────────────────────

export const ITB_WrapperKeySize = lib.func(
  'int ITB_WrapperKeySize(const char *cipherName, _Out_ size_t *outSize)',
);
export const ITB_WrapperNonceSize = lib.func(
  'int ITB_WrapperNonceSize(const char *cipherName, _Out_ size_t *outSize)',
);

export const ITB_Wrap = lib.func(
  'int ITB_Wrap(const char *cipherName, ' +
    'uint8_t *key, size_t keyLen, ' +
    'uint8_t *blob, size_t blobLen, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);
export const ITB_Unwrap = lib.func(
  'int ITB_Unwrap(const char *cipherName, ' +
    'uint8_t *key, size_t keyLen, ' +
    'uint8_t *wire, size_t wireLen, ' +
    'uint8_t *out, size_t outCap, _Out_ size_t *outLen)',
);

export const ITB_WrapInPlace = lib.func(
  'int ITB_WrapInPlace(const char *cipherName, ' +
    'uint8_t *key, size_t keyLen, ' +
    'uint8_t *blob, size_t blobLen, ' +
    'uint8_t *outNonce, size_t nonceCap)',
);
export const ITB_UnwrapInPlace = lib.func(
  'int ITB_UnwrapInPlace(const char *cipherName, ' +
    'uint8_t *key, size_t keyLen, ' +
    'uint8_t *wire, size_t wireLen)',
);

export const ITB_WrapStreamWriter_Init = lib.func(
  'int ITB_WrapStreamWriter_Init(const char *cipherName, ' +
    'uint8_t *key, size_t keyLen, ' +
    'uint8_t *outNonce, size_t nonceCap, ' +
    '_Out_ uintptr_t *outHandle)',
);
export const ITB_WrapStreamWriter_Update = lib.func(
  'int ITB_WrapStreamWriter_Update(uintptr_t handle, ' +
    'uint8_t *src, size_t srcLen, ' +
    'uint8_t *dst, size_t dstCap)',
);
export const ITB_WrapStreamWriter_Free = lib.func(
  'int ITB_WrapStreamWriter_Free(uintptr_t handle)',
);

export const ITB_UnwrapStreamReader_Init = lib.func(
  'int ITB_UnwrapStreamReader_Init(const char *cipherName, ' +
    'uint8_t *key, size_t keyLen, ' +
    'uint8_t *wireNonce, size_t nonceLen, ' +
    '_Out_ uintptr_t *outHandle)',
);
export const ITB_UnwrapStreamReader_Update = lib.func(
  'int ITB_UnwrapStreamReader_Update(uintptr_t handle, ' +
    'uint8_t *src, size_t srcLen, ' +
    'uint8_t *dst, size_t dstCap)',
);
export const ITB_UnwrapStreamReader_Free = lib.func(
  'int ITB_UnwrapStreamReader_Free(uintptr_t handle)',
);
