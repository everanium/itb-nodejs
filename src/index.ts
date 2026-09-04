// Thin Node.js / TypeScript proxy over the libitb shared library's
// Triple Pipeline surface.
//
// The package wraps the `ITB_Triple_*` C ABI exported by
// `cmd/cshared` (libitb.so / .dylib / .dll) through koffi — runtime
// FFI, no build step, no C compiler at install time. Every hash-name
// / MAC-name / cipher-name / profile-name is an opaque string passed
// through to Go for validation; the binding carries no ITB
// construction logic of its own.
//
//   import { Opts, Pipeline } from 'itb';
//
//   const sender = Pipeline.init('singlemsg-triple-mac-v1', new Opts());
//   const receiver = Pipeline.load(sender.save());
//   const wire = sender.encryptMessage(Buffer.from('hello'));
//   const plain = receiver.decryptMessage(wire);

export { ItbError } from './error.js';
export { Opts } from './opts.js';
export {
  type Masters,
  Pipeline,
  type Profile,
  inspect,
  lookup,
  profiles,
  register,
} from './pipeline.js';
export { bindingVersion, setGCPercent, setMemoryLimit, version } from './runtime.js';
export { Status, statusLabel } from './status.js';
export { DecryptStream, EncryptStream } from './stream.js';
