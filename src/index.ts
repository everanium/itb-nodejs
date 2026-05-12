// Public API surface for the Node.js / TypeScript binding to libitb.

export {
  Blob128,
  Blob256,
  Blob512,
  BlobExportOpts,
  BlobSlot,
} from './blob.js';
export type { BlobExportOptsValue, BlobSlotValue } from './blob.js';
export {
  decrypt,
  decryptAuth,
  decryptAuthTriple,
  decryptTriple,
  encrypt,
  encryptAuth,
  encryptAuthTriple,
  encryptTriple,
} from './cipher.js';
export { Encryptor } from './encryptor.js';
export type { PeekedConfig } from './encryptor.js';
// Module-level alias for `Encryptor.peekConfig`. The static method on
// `Encryptor` remains the canonical entry point; this alias lets
// callers inspect a blob's bound configuration without naming the
// class.
export { peekConfig } from './encryptor.js';
export {
  ITBBlobMalformedError,
  ITBBlobModeMismatchError,
  ITBBlobVersionTooNewError,
  ITBEasyMismatchError,
  ITBError,
  ITBStreamAfterFinalError,
  ITBStreamTruncatedError,
  lastError,
  lastMismatchField,
} from './errors.js';
export {
  channels,
  getBarrierFill,
  getBitSoup,
  getLockSoup,
  getMaxWorkers,
  getNonceBits,
  headerSize,
  listHashes,
  listMacs,
  maxKeyBits,
  parseChunkLen,
  setBarrierFill,
  setBitSoup,
  setGcPercent,
  setLockSoup,
  setMaxWorkers,
  setMemoryLimit,
  setNonceBits,
  version,
} from './library.js';
export type { HashEntry, MacEntry } from './library.js';
export { libraryPath } from './library-loader.js';
export { MAC } from './mac.js';
export { Seed } from './seed.js';
export { Status } from './status.js';
export type { StatusCode } from './status.js';
export {
  DEFAULT_CHUNK_SIZE,
  STREAM_ID_LEN,
  decryptStream,
  decryptStreamAuth,
  decryptStreamAuthTriple,
  decryptStreamTriple,
  encryptStream,
  encryptStreamAuth,
  encryptStreamAuthTriple,
  encryptStreamTriple,
  StreamDecryptor,
  StreamDecryptorAuth,
  StreamDecryptorAuthTriple,
  StreamDecryptorTriple,
  StreamEncryptor,
  StreamEncryptorAuth,
  StreamEncryptorAuthTriple,
  StreamEncryptorTriple,
} from './streams.js';
export {
  CIPHER_NAMES,
  Cipher,
  generateKey as wrapperGenerateKey,
  InvalidCipherError,
  InvalidKeyError,
  InvalidNonceError,
  keySize as wrapperKeySize,
  nonceSize as wrapperNonceSize,
  unwrap,
  unwrapInPlace,
  UnwrapStreamReader,
  wrap,
  wrapInPlace,
  WrapperError,
  WrapperHandleClosedError,
  WrapStreamWriter,
} from './wrapper.js';
export type { CipherName } from './wrapper.js';
