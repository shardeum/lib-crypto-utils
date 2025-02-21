export type hexstring = string
export type publicKey = hexstring
export type secretKey = hexstring
export type curvePublicKey = hexstring
export type curveSecretKey = hexstring
export type sharedKey = hexstring

import sodium from 'sodium-native'
import xor from 'buffer-xor'
import fastStableStringify from 'fast-stable-stringify'

export let stringify = fastStableStringify as (input: unknown) => string
export let stringifierName = 'fast-stable-stringify'

type Optional<T, K extends keyof T> = Pick<Partial<T>, K> & Omit<T, K>

export interface Keypair {
  publicKey: publicKey
  secretKey: secretKey
}

export interface Signature {
  owner: publicKey
  sig: hexstring
}

export interface LooseObject {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [index: string]: any
}

export interface TaggedObject extends LooseObject {
  tag: hexstring
}

export interface SignedObject extends LooseObject {
  sign: Signature
}

/**
 * The key used for initializing the cryptographic hashing algorithms
 */
let HASH_KEY: Buffer

/**
 * Returns 32-bytes random hex string, otherwise the number of bytes can be specified as an integer
 * @param bytes
 */
export function randomBytes(bytes = 32): hexstring {
  if (!Number.isInteger(bytes) || bytes <= 0) {
    throw new TypeError('Bytes must be given as integer greater than zero.')
  }
  const buf: Buffer = Buffer.allocUnsafe(bytes)
  sodium.randombytes_buf(buf)
  return buf.toString('hex')
}

/**
 * Returns the Blake2b hash of the input string or Buffer, default output type is hex
 * @param input
 * @param fmt
 */
export function hash(input: string, fmt = 'hex'): hexstring {
  if (!HASH_KEY) {
    throw new Error('Hash key must be passed to module constructor.')
  }
  let buf: Buffer
  if (Buffer.isBuffer(input)) {
    buf = input
  } else {
    if (typeof input !== 'string') {
      throw new TypeError('Input must be a string or buffer.')
    }
    buf = Buffer.from(input, 'utf8')
  }
  const digest = Buffer.allocUnsafe(32)
  sodium.crypto_generichash(digest, buf, HASH_KEY)
  let output
  switch (fmt) {
    case 'buffer':
      output = digest
      break
    case 'hex':
      output = digest.toString('hex')
      break
    default:
      throw Error('Invalid type for output format.')
  }
  return output
}

/**
 * Returns the hash of the provided object as a hex string, takes an optional second parameter to hash an object with the "sign" field
 * @param obj
 * @param removeSign
 * @param removeTag
 */
// Note about the partial - objects with only optional properties are not matching structurally downstream. This is an attempt
// to fix that.
export function hashObj(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  obj: { [key: string]: any },
  removeSign = false,
  removeTag = false
): hexstring {
  if (typeof obj !== 'object') {
    throw TypeError('Input must be an object.')
  }
  function performHash(obj): string {
    const input: string = stringify(obj)
    const hashed = hash(input)
    return hashed
  }
  if (removeSign) {
    if (!obj.sign) {
      throw Error('Object must contain a sign field if removeSign is flagged true.')
    }
    const signObj = obj.sign
    delete obj.sign
    const hashed = performHash(obj)
    obj.sign = signObj
    return hashed
  } else if (removeTag) {
    if (!obj.tag) {
      throw Error('Object must contain a tag field if removeTag is flagged true.')
    }
    const tagObj = obj.tag
    delete obj.tag
    const hashed = performHash(obj)
    obj.tag = tagObj
    return hashed
  } else {
    return performHash(obj)
  }
}

/**
 * Generates and retuns { publicKey, secretKey } as hex strings
 */
export function generateKeypair(): Keypair {
  const publicKey = Buffer.allocUnsafe(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = Buffer.allocUnsafe(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return {
    publicKey: publicKey.toString('hex'),
    secretKey: secretKey.toString('hex'),
  }
}

/**
 * Returns a curve sk represented as a hex string when given an sk
 * @param sk
 */
export function convertSkToCurve(sk: secretKey | Buffer): curveSecretKey {
  const skBuf = _ensureBuffer(sk)
  const curveSkBuf = Buffer.allocUnsafe(sodium.crypto_box_SECRETKEYBYTES)
  try {
    sodium.crypto_sign_ed25519_sk_to_curve25519(curveSkBuf, skBuf as Buffer)
  } catch (e) {
    throw new Error('Could not convert given secret key to curve secret key.')
  }
  return curveSkBuf.toString('hex')
}

/**
 * Returns a curve pk represented as a hex string when given a pk
 * @param pk
 */
export function convertPkToCurve(pk: publicKey | Buffer): curvePublicKey {
  const pkBuf = _ensureBuffer(pk)
  const curvePkBuf = Buffer.allocUnsafe(sodium.crypto_box_PUBLICKEYBYTES)
  try {
    sodium.crypto_sign_ed25519_pk_to_curve25519(curvePkBuf, pkBuf as Buffer)
  } catch (e) {
    throw new Error('Could not convert given public key to curve public key.')
  }
  return curvePkBuf.toString('hex')
}

// Vulns were found in encryp decrypt.  would need a security pass if we ever
// need them. GOLD-264

// /**
//  * Returns a payload obtained by encrypting and tagging the message string with a key produced from the given sk and pk
//  * @param message
//  * @param curveSk
//  * @param curvePk
//  */
// export function encrypt( read notes above
//   message: string,
//   curveSk: curveSecretKey | Buffer,
//   curvePk: curvePublicKey | Buffer
// ): string {
//   const messageBuf = Buffer.from(message, 'utf8');
//   const curveSkBuf = _ensureBuffer(curveSk, 'Secret key');
//   const curvePkBuf = _ensureBuffer(curvePk, 'Public key');
//   const ciphertext = Buffer.allocUnsafe(
//     messageBuf.length + sodium.crypto_box_MACBYTES
//   );
//   const nonce = Buffer.allocUnsafe(sodium.crypto_box_NONCEBYTES);
//   sodium.randombytes_buf(nonce);
//   sodium.crypto_box_easy(ciphertext, messageBuf, nonce, curvePkBuf as Buffer, curveSkBuf as Buffer);
//   const payload = [ciphertext.toString('hex'), nonce.toString('hex')];
//   return JSON.stringify(payload);
// }

// /**
//  * Returns the message string obtained by decrypting the payload with the given sk and pk and authenticating the attached tag
//  * @param payload
//  * @param curveSk
//  * @param curvePk
//  */
// export function decrypt(  read notes above
//   payload: string,
//   curveSk: curveSecretKey | Buffer,
//   curvePk: curvePublicKey | Buffer
// ): { isValid: boolean; message: string } {
//   payload = JSON.parse(payload);
//   const ciphertext = _ensureBuffer(payload[0], 'Tag ciphertext');
//   const nonce = _ensureBuffer(payload[1], 'Tag nonce');
//   const secretKey = _ensureBuffer(curveSk, 'Secret key');
//   const publicKey = _ensureBuffer(curvePk, 'Public key');
//   const message = Buffer.allocUnsafe(
//     ciphertext.length - sodium.crypto_box_MACBYTES
//   );
//   const isValid = sodium.crypto_box_open_easy(
//     message,
//     ciphertext as Buffer,
//     nonce as Buffer,
//     publicKey as Buffer,
//     secretKey as Buffer
//   );
//   return { isValid, message: message.toString('utf8') };
// }

/**
 * Returns an authentication tag obtained by encrypting the hash of the message string with a key produced from the given sk and pk
 * @param message
 * @param sharedKey
 */
export function tag(message: string, sharedKey: sharedKey | Buffer): string {
  const messageBuf = Buffer.from(message, 'utf8')

  const nonceBuf = Buffer.allocUnsafe(sodium.crypto_auth_BYTES)
  sodium.randombytes_buf(nonceBuf)
  const nonce = nonceBuf.toString('hex')
  const keyBuf = _getAuthKey(sharedKey, nonce)

  const tagBuf = Buffer.allocUnsafe(sodium.crypto_auth_BYTES)
  sodium.crypto_auth(tagBuf, messageBuf, keyBuf)

  const tag = tagBuf.toString('hex')
  return tag + nonce
}

/**
 * Attaches a tag field to the input object, containg an authentication tag for the obj
 * @param obj
 * @param sharedKey
 */
export function tagObj(obj: TaggedObject, sharedKey: sharedKey | Buffer): void {
  if (typeof obj !== 'object') {
    throw new TypeError('Input must be an object.')
  }
  // If it's an array, we don't want to try to sign it
  if (Array.isArray(obj)) {
    throw new TypeError('Input cannot be an array.')
  }
  if (typeof sharedKey !== 'string' && !Buffer.isBuffer(sharedKey)) {
    throw new TypeError('Shared key must be a hex string or hex buffer.')
  }
  const objStr: string = stringify(obj)
  obj.tag = tag(objStr, sharedKey)
}

/**
 * Returns true if tag is a valid authentication tag for message string
 * @param message
 * @param tag
 * @param sharedKey
 */
export function authenticate(message: string, tag: string, sharedKey: sharedKey | Buffer): boolean {
  const nonce = tag.substring(sodium.crypto_auth_BYTES * 2)
  tag = tag.substring(0, sodium.crypto_auth_BYTES * 2)
  const tagBuf = _ensureBuffer(tag, 'Tag')

  const keyBuf: Buffer = _getAuthKey(sharedKey, nonce)

  const messageBuf = Buffer.from(message, 'utf8')
  return sodium.crypto_auth_verify(tagBuf as Buffer, messageBuf, keyBuf)
}

/**
 * Returns true if the authentication tag is a valid tag for the object minus the tag field
 * @param obj
 * @param sharedKey
 */
export function authenticateObj(obj: TaggedObject, sharedKey: sharedKey | Buffer): boolean {
  if (typeof obj !== 'object') {
    throw new TypeError('Input must be an object.')
  }
  if (!obj.tag) {
    throw new Error('Object must contain a tag field')
  }
  const tag = obj.tag
  const tagless: Optional<TaggedObject, 'tag'> = obj
  delete tagless.tag
  const objStr: string = stringify(obj)
  obj.tag = tag
  return authenticate(objStr, tag, sharedKey)
}

/**
 * Sets a custom stringifier method
 * @param method
 */
export function setCustomStringifier(method: (input: unknown) => string, name: string): void {
  stringify = method
  stringifierName = name
}

/**
 * Returns a signature obtained by signing the input hash (hex string or buffer) with the sk string
 * @param input
 * @param sk
 */
export function sign(input: hexstring | Buffer, sk: secretKey | Buffer): string {
  let inputBuf: Buffer
  let skBuf: Buffer
  if (typeof input !== 'string') {
    if (Buffer.isBuffer(input)) {
      inputBuf = input
    } else {
      throw new TypeError('Input must be a hex string or buffer.')
    }
  } else {
    try {
      inputBuf = Buffer.from(input, 'hex')
    } catch (e) {
      throw new TypeError('Input string must be in hex format.')
    }
  }
  if (typeof sk !== 'string') {
    if (Buffer.isBuffer(sk)) {
      skBuf = sk
    } else {
      throw new TypeError('Secret key must be a hex string or buffer.')
    }
  } else {
    try {
      skBuf = Buffer.from(sk, 'hex')
    } catch (e) {
      throw new TypeError('Secret key string must be in hex format')
    }
  }
  const sig = Buffer.allocUnsafe(inputBuf.length + sodium.crypto_sign_BYTES)
  try {
    sodium.crypto_sign(sig, inputBuf, skBuf)
  } catch (e) {
    throw new Error('Failed to sign input with provided secret key.')
  }
  return sig.toString('hex')
}

/**
 * Attaches a sign field to the input object, containing a signed version of the hash of the object,
 * along with the public key of the signer
 * @param obj
 * @param sk
 * @param pk
 * @returns the new signed object with the `sign` field. The original object is mutated as well.
 */
export function signObj(obj: object, sk: secretKey | Buffer, pk: publicKey | Buffer): SignedObject {
  if (typeof obj !== 'object') {
    throw new TypeError('Input must be an object.')
  }
  // If it's an array, we don't want to try to sign it
  if (Array.isArray(obj)) {
    throw new TypeError('Input cannot be an array.')
  }
  const objStr = stringify(obj)
  const hashed = hash(objStr, 'buffer')
  const sig = sign(hashed, sk)
  const signPk = Buffer.isBuffer(pk) ? bufferToHex(pk) : pk
  ;(obj as SignedObject).sign = { owner: signPk, sig }
  return obj as SignedObject
}

/**
 * Returns true if the hash of the input was signed by the owner of the pk
 * @param msg
 * @param sig
 * @param pk
 */
// verify fails on non hex strings. to re-export, we would need to make things safer,
// or more flexible but also be mindful to not hurt performance of verfyObj which calls this
// and does not need those extra features.   possibly just a verifyInternal clone could be used
function verify(msg: string, sig: hexstring | Buffer, pk: publicKey | Buffer): boolean {
  //READ ABOVE , Do not export
  if (typeof msg !== 'string') {
    throw new TypeError('Message to compare must be a string.')
  }
  const sigBuf = _ensureBuffer(sig)
  const pkBuf = _ensureBuffer(pk)
  try {
    const opened = Buffer.allocUnsafe(sigBuf.length - sodium.crypto_sign_BYTES)
    sodium.crypto_sign_open(opened, sigBuf as Buffer, pkBuf as Buffer)
    const verified = opened.toString('hex')
    return verified === msg
  } catch (e) {
    throw new Error('Unable to verify provided signature with provided public key.')
  }
}

/**
 * Returns true if the hash of the object minus the sign field matches the signed message in the sign field
 * @param obj
 */
export function verifyObj(obj: SignedObject): boolean {
  if (typeof obj !== 'object') {
    throw new TypeError('Input must be an object.')
  }
  if (!obj.sign || !obj.sign.owner || !obj.sign.sig) {
    throw new Error('Object must contain a sign field with the following data: { owner, sig }')
  }
  if (typeof obj.sign.owner !== 'string') {
    throw new TypeError('Owner must be a public key represented as a hex string.')
  }
  if (typeof obj.sign.sig !== 'string') {
    throw new TypeError('Signature must be a valid signature represented as a hex string.')
  }
  const objHash = hashObj(obj, true)
  return verify(objHash, obj.sign.sig, obj.sign.owner)
}

/**
 * This function initialized the cryptographic hashing functions
 * @param key The HASH_KEY for initializing the cryptographic hashing functions
 */
export function init(key: hexstring): void {
  if (!key) {
    throw new Error('Hash key must be passed to module constructor.')
  }
  try {
    HASH_KEY = Buffer.from(key, 'hex')
    if (HASH_KEY.length !== 32) {
      throw new TypeError()
    }
  } catch (e) {
    throw new TypeError('Hash key must be a 32-byte string.')
  }
}

/**
 * Ensures that the input data given is in the form of a buffer, or converted to one if not
 * @param input The input data to be checked for or converted to a buffer
 * @param name The name given to the data to be ensured
 */
export function _ensureBuffer(input: string | Buffer, name = 'Input'): Buffer | string {
  if (typeof input !== 'string') {
    if (Buffer.isBuffer(input)) {
      return input
    } else {
      throw new TypeError(`${name} must be a hex string or buffer.`)
    }
  } else {
    try {
      return Buffer.from(input, 'hex')
    } catch (e) {
      throw new TypeError(`${name} string must be in hex format.`)
    }
  }
}

/**
 *
 * @param curveSk
 * @param curvePk
 */
export function generateSharedKey(
  curveSk: curveSecretKey | Buffer,
  curvePk: curvePublicKey | Buffer
): Buffer {
  const curveSkBuf = _ensureBuffer(curveSk)
  const curvePkBuf = _ensureBuffer(curvePk)

  const keyBuf = Buffer.allocUnsafe(sodium.crypto_scalarmult_BYTES)
  sodium.crypto_scalarmult(keyBuf, curveSkBuf as Buffer, curvePkBuf as Buffer)
  return keyBuf
}

/**
 * Returns the auth key for the provided sharedKey
 * @param sharedKey
 * @param nonce
 */
export function _getAuthKey(sharedKey: sharedKey | Buffer, nonce: string | Buffer): Buffer {
  const sharedKeyBuf = _ensureBuffer(sharedKey)
  const nonceBuf = _ensureBuffer(nonce)
  const resultBuf = xor(sharedKeyBuf as Buffer, nonceBuf as Buffer)
  return resultBuf
}

export function bufferToHex(buffer: Buffer): string {
  return [...new Uint8Array(buffer)].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}
