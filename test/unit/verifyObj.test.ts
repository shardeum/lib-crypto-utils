process.env['NODE_DEV'] = 'TEST'

import { describe, expect, it, beforeAll } from '@jest/globals'
import { verifyObj, generateKeypair, signObj, init, SignedObject } from '../../src'

describe('verifyObj', () => {
  let keypair: { publicKey: string; secretKey: string }
  const testObj = { message: 'test message' }

  beforeAll(() => {
    // Initialize crypto with a test key
    init('69fa4195670576c0160d660c3be36556ff8d504725be8a59b5a96509e0c994bc')
    keypair = generateKeypair()
  })

  it('should verify a valid signed object', () => {
    const signedObj = signObj(testObj, keypair.secretKey, keypair.publicKey)
    const result = verifyObj(signedObj)
    expect(result).toBe(true)
  })

  it('should reject when object is tampered', () => {
    const signedObj = signObj(testObj, keypair.secretKey, keypair.publicKey)
    signedObj.message = 'tampered message'
    const result = verifyObj(signedObj)
    expect(result).toBe(false)
  })

  it('should reject when signature is tampered', () => {
    const signedObj = signObj(testObj, keypair.secretKey, keypair.publicKey)
    signedObj.sign.sig = signedObj.sign.sig.slice(0, -2) + '00'
    const result = verifyObj(signedObj)
    expect(result).toBe(false)
  })

  it('should reject when owner is tampered', () => {
    const signedObj = signObj(testObj, keypair.secretKey, keypair.publicKey)
    const wrongKeypair = generateKeypair()
    signedObj.sign.owner = wrongKeypair.publicKey
    const result = verifyObj(signedObj)
    expect(result).toBe(false)
  })

  it('should handle empty object', () => {
    const emptyObj = {}
    const signedObj = signObj(emptyObj, keypair.secretKey, keypair.publicKey)
    const result = verifyObj(signedObj)
    expect(result).toBe(true)
  })

  it('should handle object with special characters', () => {
    const specialObj = { message: '!@#$%^&*()_+{}|:"<>?~`-=[]\\;\',./' }
    const signedObj = signObj(specialObj, keypair.secretKey, keypair.publicKey)
    const result = verifyObj(signedObj)
    expect(result).toBe(true)
  })

  it('should handle object with unicode characters', () => {
    const unicodeObj = { message: 'Hello, 世界! 🌍' }
    const signedObj = signObj(unicodeObj, keypair.secretKey, keypair.publicKey)
    const result = verifyObj(signedObj)
    expect(result).toBe(true)
  })

  it('should handle nested objects', () => {
    const nestedObj = {
      message: 'test',
      nested: {
        value: 123,
        array: [1, 2, 3],
      },
    }
    const signedObj = signObj(nestedObj, keypair.secretKey, keypair.publicKey)
    const result = verifyObj(signedObj)
    expect(result).toBe(true)
  })

  it('should throw error for missing sign field', () => {
    const obj = { message: 'test' }
    expect(() => verifyObj(obj as unknown as SignedObject)).toThrow(
      'Object must contain a sign field with the following data: { owner, sig }'
    )
  })

  it('should throw error for invalid owner type', () => {
    const obj = {
      message: 'test',
      sign: {
        owner: 123, // Invalid type
        sig: 'some-signature',
      },
    }
    expect(() => verifyObj(obj as unknown as SignedObject)).toThrow(
      'Owner must be a public key represented as a hex string'
    )
  })

  it('should throw error for invalid signature type', () => {
    const obj = {
      message: 'test',
      sign: {
        owner: keypair.publicKey,
        sig: 123, // Invalid type
      },
    }
    expect(() => verifyObj(obj as unknown as SignedObject)).toThrow(
      'Signature must be a valid signature represented as a hex string'
    )
  })
})
