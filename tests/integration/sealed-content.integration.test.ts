/**
 * Live check of sealed-content discovery against the public testnet full node: every
 * `SealedContentPublished` event the scan meets is BCS-decoded with the parser's layout, so a layout
 * drift from the Move struct fails here. Requires SEAL_TESTNET=1.
 */
import { describe, it, expect } from 'vitest'
import { SuiGrpcClient } from '@mysten/sui/grpc'
import { sealPoliciesDeployment } from '../../src/deployments.js'
import { listSealedContent, type SealEventsClient } from '../../src/sealed-content.js'
import { skipIfPruned } from './pruned.js'

describe.skipIf(!process.env.SEAL_TESTNET)('listSealedContent (testnet)', () => {
  const client = new SuiGrpcClient({ network: 'testnet', baseUrl: 'https://fullnode.testnet.sui.io:443' })
  const { originalId } = sealPoliciesDeployment('testnet')

  it('decodes every published pointer it scans', async (ctx) => {
    // A gate id nothing is published for: the scan decodes every event and keeps none. A node that has pruned the events rejects instead (see ./pruned.ts): skip then.
    const page = await skipIfPruned(ctx, () => listSealedContent(client as unknown as SealEventsClient, {
      originalId,
      gateId: '0x' + '00'.repeat(31) + '01',
      maxPages: 3,
    }))
    expect(page.source).toBe('rpc')
    expect(page.pointers).toEqual([])
  })
})
