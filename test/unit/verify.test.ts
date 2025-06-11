import { describe, expect, it, beforeAll, beforeEach } from '@jest/globals'
import { generateKeypair, init, testingFunctions, hash } from '../../src'
import sodium from 'sodium-native'
const { verify } = testingFunctions

describe('verify', () => {
  let keypair: { publicKey: string; secretKey: string }
  const testMessage = 'test message'
  let validSignature: string

  beforeAll(() => {
    // Initialize crypto with a test key
    init('69fa4195670576c0160d660c3be36556ff8d504725be8a59b5a96509e0c994bc')
    keypair = generateKeypair()
  })

  beforeEach(() => {
    // Create a valid signature for testing
    const hashedMessage = hash(testMessage)
    const messageBuf = Buffer.from(hashedMessage, 'hex')
    const sig = Buffer.allocUnsafe(messageBuf.length + sodium.crypto_sign_BYTES)
    const skBuf = Buffer.from(keypair.secretKey, 'hex')
    sodium.crypto_sign(sig, messageBuf, skBuf)
    validSignature = sig.toString('hex')
  })

  it('should verify a valid signature', () => {
    const hashedMessage = hash(testMessage)
    const result = verify(hashedMessage, validSignature, keypair.publicKey)
    expect(result).toBe(true)
  })

  it('should reject an invalid signature', () => {
    const invalidSig = validSignature.slice(0, -2) + '00'
    const hashedMessage = hash(testMessage)
    expect(verify(hashedMessage, invalidSig, keypair.publicKey)).toBe(false)
  })

  it('should reject when message is tampered', () => {
    const tamperedMessage = 'tampered message'
    const hashedMessage = hash(tamperedMessage)
    expect(verify(hashedMessage, validSignature, keypair.publicKey)).toBe(false)
  })

  it('should reject when public key is incorrect', () => {
    const wrongKeypair = generateKeypair()
    const hashedMessage = hash(testMessage)
    expect(verify(hashedMessage, validSignature, wrongKeypair.publicKey)).toBe(false)
  })

  it('should handle empty message', () => {
    const emptyMessage = ''
    const hashedMessage = hash(emptyMessage)
    const messageBuf = Buffer.from(hashedMessage, 'hex')
    const sig = Buffer.allocUnsafe(messageBuf.length + sodium.crypto_sign_BYTES)
    const skBuf = Buffer.from(keypair.secretKey, 'hex')
    sodium.crypto_sign(sig, messageBuf, skBuf)
    const emptySig = sig.toString('hex')

    const result = verify(hashedMessage, emptySig, keypair.publicKey)
    expect(result).toBe(true)
  })

  it('should handle message with special characters', () => {
    const specialMessage = '!@#$%^&*()_+{}|:"<>?~`-=[]\\;\',./'
    const hashedMessage = hash(specialMessage)
    const messageBuf = Buffer.from(hashedMessage, 'hex')
    const sig = Buffer.allocUnsafe(messageBuf.length + sodium.crypto_sign_BYTES)
    const skBuf = Buffer.from(keypair.secretKey, 'hex')
    sodium.crypto_sign(sig, messageBuf, skBuf)
    const specialSig = sig.toString('hex')

    const result = verify(hashedMessage, specialSig, keypair.publicKey)
    expect(result).toBe(true)
  })

  it('should handle message with unicode characters', () => {
    const unicodeMessage = 'Hello, 世界! 🌍'
    const hashedMessage = hash(unicodeMessage)
    const messageBuf = Buffer.from(hashedMessage, 'hex')
    const sig = Buffer.allocUnsafe(messageBuf.length + sodium.crypto_sign_BYTES)
    const skBuf = Buffer.from(keypair.secretKey, 'hex')
    sodium.crypto_sign(sig, messageBuf, skBuf)
    const unicodeSig = sig.toString('hex')

    const result = verify(hashedMessage, unicodeSig, keypair.publicKey)
    expect(result).toBe(true)
  })

  it('should throw error for invalid message type', () => {
    expect(() => verify(123 as unknown as string, validSignature, keypair.publicKey)).toThrow(TypeError)
  })

  it('should throw error for invalid signature format', () => {
    const hashedMessage = hash(testMessage)
    expect(() => verify(hashedMessage, 'not-a-hex-string', keypair.publicKey)).toThrow(
      'Unable to verify provided signature with provided public key.'
    )
  })

  it('should throw error for invalid public key format', () => {
    const hashedMessage = hash(testMessage)
    expect(() => verify(hashedMessage, validSignature, 'not-a-hex-string')).toThrow(
      'Unable to verify provided signature with provided public key.'
    )
  })
})
