// Resolves and dlopens libitb at module-load time.
//
// Lookup order:
//
//   1. ITB_LIBRARY_PATH environment variable — absolute path.
//   2. <repo>/dist/<os>-<arch>/libitb.<ext> — resolved by walking up
//      from this module's import.meta.url to the repo root.
//   3. System loader path (ld.so.cache / DYLD_LIBRARY_PATH / PATH).

import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import koffi from 'koffi';

function platformLibDir(): string {
  const sys = (() => {
    switch (process.platform) {
      case 'linux': return 'linux';
      case 'darwin': return 'darwin';
      case 'win32': return 'windows';
      case 'freebsd': return 'freebsd';
      default: return process.platform;
    }
  })();
  const cpu = (() => {
    switch (process.arch) {
      case 'x64': return 'amd64';
      case 'arm64': return 'arm64';
      default: return process.arch;
    }
  })();
  return `${sys}-${cpu}`;
}

function libFilename(): string {
  switch (process.platform) {
    case 'linux': return 'libitb.so';
    case 'darwin': return 'libitb.dylib';
    case 'win32': return 'libitb.dll';
    case 'freebsd': return 'libitb.so';
    default: return 'libitb.so';
  }
}

function resolveLibraryPath(): string {
  const env = process.env['ITB_LIBRARY_PATH'];
  if (env && env.length > 0) {
    return env;
  }

  // Walk up from the current module's directory looking for
  // `dist/<os>-<arch>/libitb.<ext>` at each ancestor. Layouts that
  // need to resolve: `bindings/nodejs/src/library-loader.ts` (raw
  // sources via Node's type stripping), `bindings/nodejs/dist/
  // library-loader.js` (after `npm run build`), `bindings/nodejs/
  // dist-test/src/library-loader.js` (after `npm test` build), and
  // any future deeper layout. Capping the walk at 8 levels avoids
  // an unbounded climb on detached / sandboxed roots.
  const here = fileURLToPath(import.meta.url);
  let dir = dirname(here);
  const platformDir = platformLibDir();
  const filename = libFilename();
  for (let depth = 0; depth < 8; depth++) {
    const candidate = join(dir, 'dist', platformDir, filename);
    if (existsSync(candidate)) {
      return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) {
      break;
    }
    dir = parent;
  }

  return filename;
}

const resolved = resolveLibraryPath();

export const libraryPath: string = resolved;
export const lib = koffi.load(resolved);
