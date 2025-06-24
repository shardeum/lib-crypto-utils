declare module 'sodium-native' {
  // Type definitions for sodium-native 4.x
  // Minimal definitions for APIs used by lib-crypto-utils

  /// <reference types="node" />

  // Constants used by lib-crypto-utils
  export const crypto_auth_BYTES: number
  export const crypto_box_PUBLICKEYBYTES: number
  export const crypto_box_SECRETKEYBYTES: number
  export const crypto_scalarmult_BYTES: number
  export const crypto_sign_BYTES: number
  export const crypto_sign_PUBLICKEYBYTES: number
  export const crypto_sign_SECRETKEYBYTES: number

  // Functions used by lib-crypto-utils
  export function randombytes_buf(buffer: Buffer): void
  export function crypto_generichash(output: Buffer, input: Buffer, key?: Buffer): void
  export function crypto_sign_keypair(publicKey: Buffer, secretKey: Buffer): void
  export function crypto_sign_ed25519_sk_to_curve25519(curve_sk: Buffer, ed_sk: Buffer): void
  export function crypto_sign_ed25519_pk_to_curve25519(curve_pk: Buffer, ed_pk: Buffer): void
  export function crypto_auth(output: Buffer, input: Buffer, key: Buffer): void
  export function crypto_auth_verify(output: Buffer, input: Buffer, key: Buffer): boolean
  export function crypto_sign(signedMessage: Buffer, message: Buffer, secretKey: Buffer): void
  export function crypto_sign_open(message: Buffer, signedMessage: Buffer, publicKey: Buffer): boolean
  export function crypto_scalarmult(sharedSecret: Buffer, secretKey: Buffer, remotePublicKey: Buffer): void
  export function sodium_memcmp(b1: Buffer, b2: Buffer): boolean
}
