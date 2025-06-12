import * as crypto from '../../src/index'

describe('Detached Signatures', () => {
  beforeAll(() => {
    crypto.init('69fa4195670576c0160d660c3be36556ff8d504725be8a59b5a96509e0c994bc')
  })

  describe('signDetached and verifyDetached', () => {
    it('should create and verify a detached signature', () => {
      const keypair = crypto.generateKeypair()
      const message = 'Hello, World!'
      const messageHash = crypto.hash(message)

      // Create detached signature
      const signature = crypto.signDetached(messageHash, keypair.secretKey)

      // Verify signature is 64 bytes (128 hex chars)
      expect(signature.length).toBe(128)

      // Verify the signature
      const isValid = crypto.verifyDetached(messageHash, signature, keypair.publicKey)
      expect(isValid).toBe(true)

      // Verify with wrong message fails
      const wrongMessage = crypto.hash('Wrong message')
      const isInvalid = crypto.verifyDetached(wrongMessage, signature, keypair.publicKey)
      expect(isInvalid).toBe(false)
    })
  })

  describe('signObjDetached and verifyObjDetached', () => {
    it('should sign and verify objects with detached signatures', () => {
      const keypair = crypto.generateKeypair()
      const testObj = {
        message: 'Test object',
        value: 42,
        timestamp: Date.now(),
      }

      // Sign with detached signature
      const signedObj = crypto.signObjDetached(testObj, keypair.secretKey, keypair.publicKey)

      // Verify signature is 64 bytes
      expect(signedObj.sign.sig.length).toBe(128)

      // Verify the signed object
      const isValid = crypto.verifyObjDetached(signedObj)
      expect(isValid).toBe(true)

      // Tamper with object and verify it fails
      signedObj.value = 43
      const isInvalid = crypto.verifyObjDetached(signedObj)
      expect(isInvalid).toBe(false)
    })
  })

  describe('Backward compatibility', () => {
    it('should verify both old and new signatures with auto-detection', () => {
      const keypair = crypto.generateKeypair()
      const message = 'Test message'
      const messageHash = crypto.hash(message)

      // Create old-style (non-detached) signature
      const oldSignature = crypto.sign(messageHash, keypair.secretKey, false)
      // Old signature should be 96 bytes for 32-byte hash (64 + 32)
      expect(oldSignature.length).toBe(192)

      // Create new-style (detached) signature
      const newSignature = crypto.sign(messageHash, keypair.secretKey, true)
      // New signature should be 64 bytes
      expect(newSignature.length).toBe(128)

      // Both should verify successfully with verifyObj
      const testObj1 = { data: 'test' }
      const testObj2 = { data: 'test' }

      // Sign with old style
      const signedObj1 = crypto.signObj(testObj1, keypair.secretKey, keypair.publicKey, false)
      expect(crypto.verifyObj(signedObj1)).toBe(true)

      // Sign with new style
      const signedObj2 = crypto.signObj(testObj2, keypair.secretKey, keypair.publicKey, true)
      expect(crypto.verifyObj(signedObj2)).toBe(true)
    })

    it('should handle mixed signature types correctly', () => {
      const keypair = crypto.generateKeypair()
      const testObj = { data: 'test data', id: 123 }

      // Create both types of signatures
      const objOld = JSON.parse(JSON.stringify(testObj))
      const objNew = JSON.parse(JSON.stringify(testObj))

      // Sign with old method
      crypto.signObj(objOld, keypair.secretKey, keypair.publicKey, false)

      // Sign with new method
      crypto.signObj(objNew, keypair.secretKey, keypair.publicKey, true)

      // Old signature should be longer
      expect(objOld.sign.sig.length).toBeGreaterThan(objNew.sign.sig.length)

      // Both should verify with verifyObj (auto-detection)
      expect(crypto.verifyObj(objOld)).toBe(true)
      expect(crypto.verifyObj(objNew)).toBe(true)

      // New detached verify should work only with detached signature
      expect(crypto.verifyObjDetached(objNew)).toBe(true)
      expect(() => crypto.verifyObjDetached(objOld)).toThrow()
    })
  })

  describe('Sign function with detached parameter', () => {
    it('should produce different signature lengths based on detached parameter', () => {
      const keypair = crypto.generateKeypair()
      const message = crypto.hash('test')

      // Default (undefined) should now use detached
      const defaultSig = crypto.sign(message, keypair.secretKey)
      expect(defaultSig.length).toBe(128) // 64 bytes sig only

      // Explicit false should use non-detached
      const nonDetachedSig = crypto.sign(message, keypair.secretKey, false)
      expect(nonDetachedSig.length).toBe(192) // 96 bytes = 64 sig + 32 msg

      // Explicit true should use detached
      const detachedSig = crypto.sign(message, keypair.secretKey, true)
      expect(detachedSig.length).toBe(128) // 64 bytes sig only
    })
  })

  describe('Default behavior change', () => {
    it('sign() should default to detached signatures', () => {
      const keypair = crypto.generateKeypair()
      const message = crypto.hash('test message')

      // Call without detached parameter
      const signature = crypto.sign(message, keypair.secretKey)

      // Should produce 64-byte signature
      expect(signature.length).toBe(128) // 128 hex chars = 64 bytes

      // Should verify with verifyDetached
      expect(crypto.verifyDetached(message, signature, keypair.publicKey)).toBe(true)
    })

    it('signObj() should default to detached signatures', () => {
      const keypair = crypto.generateKeypair()
      const obj = { data: 'test', value: 123 }

      // Call without detached parameter
      const signedObj = crypto.signObj(obj, keypair.secretKey, keypair.publicKey)

      // Should produce 64-byte signature
      expect(signedObj.sign.sig.length).toBe(128)

      // Should verify with both methods due to auto-detection
      expect(crypto.verifyObj(signedObj)).toBe(true)
      expect(crypto.verifyObjDetached(signedObj)).toBe(true)
    })
  })

  describe('Manual signature conversion', () => {
    it('should convert non-detached signature to detached by removing excess and verify with verifyObj', () => {
      const keypair = crypto.generateKeypair()
      const testObj = {
        message: 'Test conversion',
        timestamp: Date.now(),
        id: 'test-123',
      }

      // Create a copy for manual signature manipulation
      const objForManualConversion = JSON.parse(JSON.stringify(testObj))

      // Sign with old method (non-detached) - this includes message + signature
      const signedObjOld = crypto.signObj(objForManualConversion, keypair.secretKey, keypair.publicKey, false)

      // Verify the old signature works
      expect(crypto.verifyObj(signedObjOld)).toBe(true)

      // Get the non-detached signature
      const nonDetachedSig = signedObjOld.sign.sig

      // Non-detached signature should be longer than 128 hex chars (64 bytes)
      expect(nonDetachedSig.length).toBeGreaterThan(128)

      // Manual conversion: Extract just the signature part (first 128 hex chars = 64 bytes)
      // In libsodium, non-detached signatures have format: [64-byte signature][original message]
      const detachedSigFromOld = nonDetachedSig.substring(0, 128)

      // Verify the detached signature is exactly 64 bytes
      expect(detachedSigFromOld.length).toBe(128)

      // Create a new object with the manually converted detached signature
      const objWithDetachedSig = {
        ...testObj,
        sign: {
          owner: signedObjOld.sign.owner,
          sig: detachedSigFromOld,
        },
      }

      // This should verify successfully using verifyObj with auto-detection
      expect(crypto.verifyObj(objWithDetachedSig)).toBe(true)

      // It should also verify with the specific detached verification method
      expect(crypto.verifyObjDetached(objWithDetachedSig)).toBe(true)

      // For additional verification, let's also test direct signature verification
      const objHash = crypto.hashObj(objWithDetachedSig, true) // true to remove sign field for hashing
      expect(crypto.verifyDetached(objHash, detachedSigFromOld, keypair.publicKey)).toBe(true)
    })
  })
})
