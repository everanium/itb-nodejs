// eitb — command-line demonstrator for the ITB Node.js binding.
//
// Subcommands:
//
//   eitb version                                   library + binding versions
//   eitb hashes                                    shipped hash primitive roster
//   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
//   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
//
// `encrypt` prints the session blob to stderr as hex; feed that hex
// back to `decrypt` on the receiving side. Argument parsing is
// hand-rolled over process.argv.

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

import { lib } from '../src/ffi.js';
import {
  Opts,
  Pipeline,
  bindingVersion,
  setGCPercent,
  setMemoryLimit,
  version,
} from '../src/index.js';

setMemoryLimit(512n * 1024n * 1024n);
setGCPercent(20);

function usage(): never {
  console.error(
    'usage: eitb version\n' +
      '       eitb hashes\n' +
      '       eitb encrypt <profile> <in-file> <out-file>\n' +
      '       eitb decrypt <profile> <blob-hex> <in-file> <out-file>',
  );
  process.exit(2);
}

function cmdVersion(): void {
  console.log(`libitb ${version()}`);
  console.log(`itb-nodejs ${bindingVersion}`);
}

// The binding library deliberately exposes no primitive enumeration;
// this CLI diagnostic declares the iteration symbols itself so the
// shipped roster can be inspected from the shell.
function cmdHashes(): void {
  const hashCount = lib.func('int ITB_HashCount()');
  const hashName = lib.func(
    'int ITB_HashName(int i, uint8_t *out, size_t capBytes, _Out_ size_t *outLen)',
  );
  const hashWidth = lib.func('int ITB_HashWidth(int i)');
  const decoder = new TextDecoder('utf-8');
  const n: number = hashCount();
  for (let i = 0; i < n; i++) {
    const buf = new Uint8Array(128);
    const len: [number | bigint] = [0];
    const rc = hashName(i, buf, buf.length, len);
    if (rc !== 0) {
      throw new Error(`ITB_HashName(${i}) failed with status ${rc}`);
    }
    const written = Number(len[0]);
    const name = decoder.decode(buf.subarray(0, written > 0 ? written - 1 : 0));
    console.log(`${String(i).padStart(2)}  ${name.padEnd(12)} ${hashWidth(i)} bits`);
  }
}

// Profiles whose canonical name begins with "streaming-" route
// through the one-shot streaming buffered pair instead of the Single
// Message pair.
function isStreamingProfile(profile: string): boolean {
  return profile.startsWith('streaming-');
}

// Recursively create the parent directory of `path` (mkdir -p).
function ensureParentDir(path: string): void {
  const parent = dirname(path);
  if (parent && parent !== '.') {
    mkdirSync(parent, { recursive: true });
  }
}

function cmdEncrypt(profile: string, infile: string, outfile: string): void {
  const plain = readFileSync(infile);
  const pipe = Pipeline.init(profile, new Opts());
  const wire = isStreamingProfile(profile)
    ? pipe.encryptStreamOneShot(plain)
    : pipe.encryptMessage(plain);
  ensureParentDir(outfile);
  writeFileSync(outfile, wire);
  console.error(pipe.blob.toString('hex'));
  console.log(`encrypted ${infile} -> ${outfile} (${plain.length} -> ${wire.length} bytes)`);
  pipe.free();
}

function cmdDecrypt(profile: string, blobHex: string, infile: string, outfile: string): void {
  if (blobHex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(blobHex)) {
    throw new Error('blob hex is malformed');
  }
  const blob = Buffer.from(blobHex, 'hex');
  const wire = readFileSync(infile);
  const pipe = Pipeline.open(profile, blob, new Opts());
  const plain = isStreamingProfile(profile)
    ? pipe.decryptStreamOneShot(wire)
    : pipe.decryptMessage(wire);
  ensureParentDir(outfile);
  writeFileSync(outfile, plain);
  console.log(`decrypted ${infile} -> ${outfile} (${wire.length} -> ${plain.length} bytes)`);
  pipe.free();
}

const args = process.argv.slice(2);
try {
  switch (args[0]) {
    case 'version':
      cmdVersion();
      break;
    case 'hashes':
      cmdHashes();
      break;
    case 'encrypt':
      if (args.length !== 4) {
        usage();
      }
      cmdEncrypt(args[1]!, args[2]!, args[3]!);
      break;
    case 'decrypt':
      if (args.length !== 5) {
        usage();
      }
      cmdDecrypt(args[1]!, args[2]!, args[3]!, args[4]!);
      break;
    default:
      usage();
  }
} catch (e) {
  console.error(`eitb: ${e instanceof Error ? e.message : e}`);
  process.exit(1);
}
