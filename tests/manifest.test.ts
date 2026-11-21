/**
 * Tests for the manifest parser (`src/manifest.ts`): the one gate for an untrusted manifest. It accepts an object or JSON text, requires the four fields, types the
 * optional ones, validates the identity as even-length hex, and with a registry lets the provider narrow the parameters (dropping unknown keys, `__proto__` included).
 */
import { describe, it, expect } from 'vitest'
import { parseSealedManifest, SealedManifestError } from '../src/manifest.js'
import { createDefaultRegistry } from '../src/default-registry.js'

/** A well-formed manifest; the cases below change one field of it. */
const valid = {
  policyType: 'nft-gate',
  id: 'deadbeef',
  blobId: 'blob123',
  network: 'testnet',
  params: { gateId: '0x1' },
  label: 'my file',
}

describe('parseSealedManifest', () => {
  it('accepts a well-formed manifest object', () => {
    const m = parseSealedManifest(valid)
    expect(m.policyType).toBe('nft-gate')
    expect(m.id).toBe('deadbeef')
    expect(m.params).toEqual({ gateId: '0x1' })
    expect(m.label).toBe('my file')
  })

  it('accepts a well-formed JSON string', () => {
    expect(parseSealedManifest(JSON.stringify(valid)).blobId).toBe('blob123')
  })

  it('accepts a minimal manifest without optional fields', () => {
    // The two optional fields removed: the result must not invent them.
    const { params, label, ...minimal } = valid
    const m = parseSealedManifest(minimal)
    expect(m.params).toBeUndefined()
    expect(m.label).toBeUndefined()
  })

  it('rejects invalid JSON', () => {
    expect(() => parseSealedManifest('{ not json')).toThrow(SealedManifestError)
  })

  it('rejects non-objects', () => {
    // `null`, a number and an array are not manifests.
    expect(() => parseSealedManifest(null)).toThrow(SealedManifestError)
    expect(() => parseSealedManifest(42)).toThrow(SealedManifestError)
    expect(() => parseSealedManifest([valid])).toThrow(SealedManifestError)
  })

  it.each(['policyType', 'id', 'blobId', 'network'])('rejects a missing %s', (key) => {
    const bad = { ...valid } as Record<string, unknown>
    delete bad[key]
    expect(() => parseSealedManifest(bad)).toThrow(SealedManifestError)
  })

  it.each(['policyType', 'id', 'blobId', 'network'])('rejects an empty %s', (key) => {
    expect(() => parseSealedManifest({ ...valid, [key]: '' })).toThrow(SealedManifestError)
  })

  it('rejects a non-object params', () => {
    expect(() => parseSealedManifest({ ...valid, params: 'nope' })).toThrow(SealedManifestError)
  })

  it('rejects a non-string label', () => {
    expect(() => parseSealedManifest({ ...valid, label: 5 })).toThrow(SealedManifestError)
  })
})

describe('parseSealedManifest: identity and params', () => {
  // A valid gate id and a manifest for the nft-gate policy (identity: 32-byte gate id + 16-byte nonce, as hex).
  const GATE = '0x' + 'ab'.repeat(32)
  const nft = { policyType: 'nft-gate', id: 'ab'.repeat(48), blobId: 'blob', network: 'testnet', params: { gateId: GATE, soulbound: true } }
  // The default registry, so the providers' own validation runs.
  const registry = createDefaultRegistry()

  it('requires the identity to be even-length hex', () => {
    // Not hex, odd length, a `0x` prefix (the identity is persisted without one) and a space are all refused.
    for (const id of ['xyz', 'abc', '0xabcd', 'ab cd']) {
      expect(() => parseSealedManifest({ ...nft, id })).toThrow(SealedManifestError)
    }
    expect(parseSealedManifest({ ...nft, id: 'ABCD' }).id).toBe('ABCD')
  })

  it('with a registry: checks the policy type and lets the provider validate and narrow the params', () => {
    expect(parseSealedManifest(nft, registry).params).toEqual({ gateId: GATE, soulbound: true })
    expect(() => parseSealedManifest({ ...nft, policyType: 'mystery' }, registry)).toThrow(/unknown policy type/)
    expect(() => parseSealedManifest({ ...nft, params: { gateId: GATE, soulbound: 'false' } }, registry)).toThrow(/soulbound must be a boolean/)
    expect(() => parseSealedManifest({ ...nft, params: { gateId: 'nope' } }, registry)).toThrow(/gateId/)
    expect(() => parseSealedManifest({ ...nft, params: undefined }, registry)).toThrow(/params are missing/)
  })

  it('drops unknown params keys (including __proto__) when a provider narrows them', () => {
    // `JSON.parse` makes `__proto__` an own key here; the provider must drop it with the other unknown keys, so nothing can pollute a prototype later.
    const raw = JSON.parse(`{"gateId":"${GATE}","nftId":"${GATE}","__proto__":{"polluted":true},"extra":1}`)
    const m = parseSealedManifest({ ...nft, params: raw }, registry)
    expect(Object.keys(m.params ?? {}).sort()).toEqual(['gateId', 'nftId'])
  })

  it('accepts a time-lock manifest, which has no params to check', () => {
    expect(parseSealedManifest({ policyType: 'time-lock', id: 'ab'.repeat(16), blobId: 'b', network: 'testnet' }, registry).policyType).toBe('time-lock')
  })
})
