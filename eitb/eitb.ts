// eitb — command-line demonstrator for the ITB Node.js binding.
//
// Subcommands:
//
//   eitb version                                   library + binding versions
//   eitb profiles                                  registered profile catalogue
//   eitb inspect <blob-hex>                        profile record of a blob
//   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
//   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
//
// `encrypt` prints the session blob (Pipeline.save) to stderr as hex;
// feed that hex back to `decrypt` on the receiving side, which reopens
// the session with Pipeline.load (the profile argument only routes
// Single Message versus streaming). `profiles` lists the registered
// profile catalogue one name per line; the profiles that carry a
// cipher surface are the ones `encrypt` / `decrypt` accept. Argument
// parsing is hand-rolled over process.argv.

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

import {
  Opts,
  Pipeline,
  bindingVersion,
  inspect,
  profiles,
  setGCPercent,
  setMemoryLimit,
  version,
} from '../src/index.js';

setMemoryLimit(512n * 1024n * 1024n);
setGCPercent(20);

function usage(): never {
  console.error(
    'usage: eitb version\n' +
      '       eitb profiles\n' +
      '       eitb inspect <blob-hex>\n' +
      '       eitb encrypt <profile> <in-file> <out-file>\n' +
      '       eitb decrypt <profile> <blob-hex> <in-file> <out-file>',
  );
  process.exit(2);
}

function cmdVersion(): void {
  console.log(`libitb ${version()}`);
  console.log(`itb-nodejs ${bindingVersion}`);
}

function cmdProfiles(): void {
  for (const name of profiles()) {
    console.log(name);
  }
}

function blobFromHex(blobHex: string): Buffer {
  if (blobHex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(blobHex)) {
    throw new Error('blob hex is malformed');
  }
  return Buffer.from(blobHex, 'hex');
}

function cmdInspect(blobHex: string): void {
  console.log(JSON.stringify(inspect(blobFromHex(blobHex)), null, 2));
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
  console.error(pipe.save().toString('hex'));
  console.log(`encrypted ${infile} -> ${outfile} (${plain.length} -> ${wire.length} bytes)`);
  pipe.free();
}

function cmdDecrypt(profile: string, blobHex: string, infile: string, outfile: string): void {
  const blob = blobFromHex(blobHex);
  const wire = readFileSync(infile);
  const pipe = Pipeline.load(blob);
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
    case 'profiles':
      cmdProfiles();
      break;
    case 'inspect':
      if (args.length !== 2) {
        usage();
      }
      cmdInspect(args[1]!);
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
