/**
 * Tests for reading a ciphertext's header without decrypting (`describeCiphertext`) and for comparing it with a committee (`sealedUnderServers`): this is how an
 * app decides that content must be re-sealed to a new set of key servers.
 */
import { describe, it, expect, vi } from 'vitest'

// The header layout is @mysten/seal's; mock its parser to feed a known header.
const { parseSpy } = vi.hoisted(() => ({ parseSpy: vi.fn() }))
vi.mock('@mysten/seal', () => ({ EncryptedObject: { parse: parseSpy }, SealClient: class {}, SessionKey: class {} }))

// Imported after the mock is registered, so the controller sees the mocked SDK.
const { describeCiphertext, sealedUnderServers } = await import('../src/controller.js')

/** A 32-byte object id from a short hex string (the normalised form the code reports). */
const long = (h: string) => `0x${h.padStart(64, '0')}`

describe('describeCiphertext', () => {
  // The header lists one entry per share, so a server that appears twice has weight 2.
  it('reports identity, package, threshold and servers with weights from repeated entries', () => {
    parseSpy.mockReturnValue({
      id: '0xABCD',
      packageId: '0x1',
      threshold: 2,
      services: [
        ['0x5', 0],
        ['0x5', 1],
        ['0x6', 2],
      ],
    })
    expect(describeCiphertext(new Uint8Array())).toEqual({
      id: 'abcd',
      packageId: long('1'),
      threshold: 2,
      servers: [
        { objectId: long('5'), weight: 2 },
        { objectId: long('6'), weight: 1 },
      ],
    })
  })

  it('throws for bytes that are not a Seal ciphertext', () => {
    parseSpy.mockImplementation(() => {
      throw new Error('bad bcs')
    })
    expect(() => describeCiphertext(new Uint8Array([1]))).toThrow('bad bcs')
  })
})

describe('sealedUnderServers', () => {
  // A ciphertext sealed to servers 5 and 6, one share each, threshold 2.
  const info = { id: 'ab', packageId: long('1'), threshold: 2, servers: [{ objectId: long('5'), weight: 1 }, { objectId: long('6'), weight: 1 }] }

  it('matches the same servers and threshold regardless of order and id form', () => {
    expect(sealedUnderServers(info, [{ objectId: '0x6' }, { objectId: '0x5', weight: 1 }], 2)).toBe(true)
  })

  it('differs on threshold, server set or weight', () => {
    // A different threshold, a different server, a different weight and a missing server must each make it "not the same set".
    expect(sealedUnderServers(info, [{ objectId: '0x5' }, { objectId: '0x6' }], 1)).toBe(false)
    expect(sealedUnderServers(info, [{ objectId: '0x5' }, { objectId: '0x7' }], 2)).toBe(false)
    expect(sealedUnderServers(info, [{ objectId: '0x5', weight: 2 }, { objectId: '0x6' }], 2)).toBe(false)
    expect(sealedUnderServers(info, [{ objectId: '0x5' }], 2)).toBe(false)
  })
})
