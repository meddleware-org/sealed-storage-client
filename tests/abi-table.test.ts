/**
 * Tests for the ABI table (`tests/abi-table.ts`): it covers every exported builder and every policy of the default registry, and every call it makes targets
 * the placeholder package and one of the four known Move functions. The live half of the drift check compares the same table with the deployed package.
 */
import { describe, it, expect } from 'vitest'
import { BUILDERS, PROVIDERS, allMoveCalls, exportedBuilders, registeredPolicies, PKG } from './abi-table.js'

describe('ABI table (feeds the testnet drift check)', () => {
  // A new `build…Tx` export with no table entry would be unchecked against the chain.
  it('covers every exported transaction builder', () => {
    expect(Object.keys(BUILDERS).sort()).toEqual(exportedBuilders)
  })

  // Likewise a new built-in policy.
  it('covers every policy in the default registry', () => {
    expect(Object.keys(PROVIDERS).sort()).toEqual(registeredPolicies)
  })

  it('every call targets the given package, and each provider calls its own module', () => {
    const calls = allMoveCalls()
    // Every call goes to the package we passed in (no hard-coded id in a builder).
    for (const c of calls) expect(c.package).toBe(PKG)
    expect(calls.map((c) => `${c.module}::${c.function}`).sort()).toEqual([
      'nft_gate::seal_approve',
      'nft_gate::seal_approve_soulbound',
      'sealed_content::publish',
      'timelock::seal_approve',
    ])
  })
})
