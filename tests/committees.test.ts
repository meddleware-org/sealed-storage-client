import { describe, it, expect } from 'vitest'
import {
  SEAL_COMMITTEES,
  SEAL_COMMITTEES_PENDING,
  committeeServerConfigs,
  sealCommittee,
} from '../src/committees.js'
import * as entry from '../src/index.js'
import * as deployments from '../src/deployments.js'
import { bytesToHex, objectIdBytes } from '../src/bytes.js'

const HEX_ID = /^0x[0-9a-f]{64}$/

describe('Seal committees', () => {
  const testnet = SEAL_COMMITTEES.testnet

  it('records testnet with full-length lowercase ids already in canonical form', () => {
    expect(testnet.servers.length).toBeGreaterThan(0)
    for (const s of testnet.servers) {
      expect(s.name).toMatch(/\S/)
      expect(s.objectId).toMatch(HEX_ID)
      expect(`0x${bytesToHex(objectIdBytes(s.objectId))}`).toBe(s.objectId)
      expect(Number.isInteger(s.weight) && s.weight >= 1).toBe(true)
    }
  })

  it('keeps the testnet threshold an integer within the total weight', () => {
    const total = testnet.servers.reduce((n, s) => n + s.weight, 0)
    expect(Number.isInteger(testnet.threshold)).toBe(true)
    expect(testnet.threshold).toBeGreaterThanOrEqual(1)
    expect(testnet.threshold).toBeLessThanOrEqual(total)
    expect(testnet.threshold).toBe(2)
  })

  it('has no duplicate object ids', () => {
    const ids = testnet.servers.map((s) => s.objectId)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it('shows mainnet as not published, with the decided operators and threshold recorded', () => {
    expect(SEAL_COMMITTEES.mainnet).toBeUndefined()
    expect(SEAL_COMMITTEES_PENDING.mainnet.threshold).toBe(2)
    expect(SEAL_COMMITTEES_PENDING.mainnet.providers).toEqual(['Overclock', 'NodeInfra', 'H2O Open mode'])
    expect(() => sealCommittee('mainnet')).toThrow(/no Seal key-server committee is published for mainnet/)
  })

  it('resolves a published committee and refuses unknown networks and prototype members', () => {
    expect(sealCommittee('testnet')).toBe(testnet)
    for (const name of ['devnet', 'constructor', 'toString', '__proto__']) {
      expect(() => sealCommittee(name)).toThrow(/no Seal key-server committee is published/)
    }
  })

  it('builds KeyServerConfig[]: a url becomes aggregatorUrl, an independent server gets none', () => {
    const configs = committeeServerConfigs(testnet)
    expect(configs).toHaveLength(testnet.servers.length)
    expect(configs[0]).toEqual({
      objectId: testnet.servers[0]?.objectId,
      weight: 1,
      aggregatorUrl: 'https://seal-aggregator-testnet.mystenlabs.com',
    })
    expect(configs.slice(1).every((c) => !('aggregatorUrl' in c))).toBe(true)
  })

  it('is exported from the package entry and the deployments subpath', () => {
    expect(entry.SEAL_COMMITTEES).toBe(SEAL_COMMITTEES)
    expect(entry.sealCommittee).toBe(sealCommittee)
    expect(deployments.SEAL_COMMITTEES).toBe(SEAL_COMMITTEES)
    expect(deployments.committeeServerConfigs).toBe(committeeServerConfigs)
  })
})
