import { randomBytes } from '../../src'

describe('randomBytes', () => {
  it('should generate a 32-byte hex string by default', () => {
    const result = randomBytes()
    expect(typeof result).toBe('string')
    expect(result.length).toBe(64) // 32 bytes = 64 hex characters
    expect(/^[0-9a-f]+$/i.test(result)).toBe(true) // should be hex string
  })

  it('should generate a hex string of specified length', () => {
    const bytes = 16
    const result = randomBytes(bytes)
    expect(typeof result).toBe('string')
    expect(result.length).toBe(bytes * 2) // each byte = 2 hex characters
    expect(/^[0-9a-f]+$/i.test(result)).toBe(true)
  })

  it('should throw error for invalid input', () => {
    expect(() => randomBytes(-1)).toThrow()
    expect(() => randomBytes(0)).toThrow()
    expect(() => randomBytes(1.5)).toThrow()
  })
})
