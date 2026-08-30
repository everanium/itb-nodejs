// Runtime symbol loading over the libitb shared library (koffi).
//
// Lookup order:
//
//   1. ITB_LIBITB_PATH environment variable (path to the shared
//      library file).
//   2. <repo>/dist/<os>-<arch>/libitb.<ext> resolved by walking up
//      from this module's directory (in-repo builds).
//   3. The OS default loader path (ld.so.cache / DYLD_LIBRARY_PATH /
//      PATH).
//
// Output string buffers are declared `uint8_t *` rather than
// `char *` to bypass koffi's auto-string coercion; callers decode
// UTF-8 over `outLen - 1` bytes (the count includes the trailing
// NUL). koffi passes TypedArrays by reference, so bytes the C side
// writes land directly in the caller's buffer.

import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import koffi from 'koffi';

/** Opaque libitb handle (uintptr_t across the FFI). */
export type Handle = number | bigint;

function libFilename(): string {
  switch (process.platform) {
    case 'darwin': return 'libitb.dylib';
    case 'win32': return 'libitb.dll';
    default: return 'libitb.so';
  }
}

function platformLibDir(): string {
  const sys = process.platform === 'win32' ? 'windows' : process.platform;
  const cpu = process.arch === 'x64' ? 'amd64' : process.arch;
  return `${sys}-${cpu}`;
}

function resolveLibraryPath(): string {
  const env = process.env['ITB_LIBITB_PATH'];
  if (env && env.length > 0) {
    return env;
  }
  let dir = dirname(fileURLToPath(import.meta.url));
  const tail = join('dist', platformLibDir(), libFilename());
  for (let depth = 0; depth < 8; depth++) {
    const candidate = join(dir, tail);
    if (existsSync(candidate)) {
      return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) {
      break;
    }
    dir = parent;
  }
  return libFilename();
}

export const libraryPath: string = resolveLibraryPath();
export const lib = koffi.load(libraryPath);

// ─── Library introspection + Go runtime knobs ──────────────────────

export const ITB_Version = lib.func(
  'int ITB_Version(uint8_t *out, size_t capBytes, _Out_ size_t *outLen)',
);
export const ITB_LastError = lib.func(
  'int ITB_LastError(uint8_t *out, size_t capBytes, _Out_ size_t *outLen)',
);
export const ITB_SetMemoryLimit = lib.func(
  'int64_t ITB_SetMemoryLimit(int64_t limit)',
);
export const ITB_SetGCPercent = lib.func('int ITB_SetGCPercent(int pct)');

// ─── Triple Pipeline surface ───────────────────────────────────────

export const ITB_Triple_Init = lib.func(
  'int ITB_Triple_Init(const char *profile, const char *opts, ' +
    'uint8_t *blobOut, size_t blobCap, _Out_ size_t *blobLen, ' +
    '_Out_ uintptr_t *outHandle)',
);
export const ITB_Triple_Open = lib.func(
  'int ITB_Triple_Open(const char *profile, ' +
    'const uint8_t *blob, size_t blobLen, const char *opts, ' +
    'const uint8_t *permMaster, size_t permMasterLen, ' +
    'const uint8_t *wrapMaster, size_t wrapMasterLen, ' +
    'size_t mastersCount, _Out_ uintptr_t *outHandle)',
);
export const ITB_Triple_Rekey = lib.func(
  'int ITB_Triple_Rekey(uintptr_t handle, ' +
    'const uint8_t *permMaster, size_t permMasterLen, ' +
    'const uint8_t *wrapMaster, size_t wrapMasterLen, ' +
    'uint8_t *blobOut, size_t blobCap, _Out_ size_t *blobLen)',
);
export const ITB_Triple_Close = lib.func('int ITB_Triple_Close(uintptr_t handle)');
export const ITB_Triple_Free = lib.func('int ITB_Triple_Free(uintptr_t handle)');

const CIPHER_SIG =
  '(uintptr_t handle, const uint8_t *src, size_t srcLen, ' +
  'uint8_t *out, size_t outCap, _Out_ size_t *outLen)';
export const ITB_Triple_EncryptStream = lib.func(`int ITB_Triple_EncryptStream${CIPHER_SIG}`);
export const ITB_Triple_DecryptStream = lib.func(`int ITB_Triple_DecryptStream${CIPHER_SIG}`);
export const ITB_Triple_EncryptMessage = lib.func(`int ITB_Triple_EncryptMessage${CIPHER_SIG}`);
export const ITB_Triple_DecryptMessage = lib.func(`int ITB_Triple_DecryptMessage${CIPHER_SIG}`);

export const ITB_Triple_RegisterProfile = lib.func(
  'int ITB_Triple_RegisterProfile(const char *name, const char *opts)',
);

export const ITB_Triple_EncryptStreamBegin = lib.func(
  'int ITB_Triple_EncryptStreamBegin(uintptr_t pipe, _Out_ uintptr_t *outStream)',
);
export const ITB_Triple_DecryptStreamBegin = lib.func(
  'int ITB_Triple_DecryptStreamBegin(uintptr_t pipe, _Out_ uintptr_t *outStream)',
);
export const ITB_Triple_StreamWrite = lib.func(
  'int ITB_Triple_StreamWrite(uintptr_t stream, const uint8_t *src, size_t srcLen)',
);
export const ITB_Triple_StreamEnd = lib.func('int ITB_Triple_StreamEnd(uintptr_t stream)');
export const ITB_Triple_StreamRead = lib.func(
  'int ITB_Triple_StreamRead(uintptr_t stream, uint8_t *out, size_t outCap, ' +
    '_Out_ size_t *outLen, _Out_ int *finished)',
);
export const ITB_Triple_StreamFree = lib.func('int ITB_Triple_StreamFree(uintptr_t stream)');
