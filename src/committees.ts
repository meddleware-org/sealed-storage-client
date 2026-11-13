// The Seal key-server committees Meddleware's apps seal to, per network: the single owner of these
// ids (workspace FU-0062). Data only. `deployments.ts` (generated) re-exports this module, so the
// `./deployments` subpath carries it too.
import type { KeyServerConfig } from './controller.js'

/** One key server of a committee. */
export interface SealCommitteeServer {
  /** Human name of the operator or committee (display only). */
  name: string
  /** On-chain `KeyServer` object id: `0x` + 64 lowercase hex digits. */
  objectId: string
  /** Contribution toward the threshold. */
  weight: number
  /**
   * The aggregator URL, set only for a committee reached through an aggregator (it becomes
   * `KeyServerConfig.aggregatorUrl`). An independent server publishes its URL on-chain: leave unset.
   */
  url?: string
}

/** A published committee: `threshold` is `t` in t-of-n over the servers' total weight. */
export interface SealCommittee {
  threshold: number
  servers: readonly SealCommitteeServer[]
}

/**
 * The committee per network. A network whose committee is not published is `undefined`, so a consumer
 * must handle "not published" (use {@link sealCommittee} to throw instead).
 *
 * - `testnet`: Mysten's decentralised committee, reached through its aggregator (counts as ONE
 *   server), plus two Mysten Open-mode servers, threshold 2 (ADR-0002).
 * - `mainnet`: not published. It is filled with the mainnet record at publication; see
 *   {@link SEAL_COMMITTEES_PENDING} for what is already decided.
 */
export const SEAL_COMMITTEES: {
  readonly testnet: SealCommittee
  readonly mainnet: SealCommittee | undefined
} = {
  testnet: {
    threshold: 2,
    servers: [
      {
        name: 'Mysten decentralised committee (aggregator)',
        objectId: '0xb012378c9f3799fb5b1a7083da74a4069e3c3f1c93de0b27212a5799ce1e1e98',
        weight: 1,
        url: 'https://seal-aggregator-testnet.mystenlabs.com',
      },
      {
        name: 'Mysten Open server 1',
        objectId: '0x73d05d62c18d9374e3ea529e8e0ed6161da1a141a94d3f76ae3fe4e99356db75',
        weight: 1,
      },
      {
        name: 'Mysten Open server 2',
        objectId: '0xf5d14a81a982144ae441cd7d64b09027f116a468bd36e7eca494f750591623c8',
        weight: 1,
      },
    ],
  },
  // Mainnet: filled with the mainnet record at publication. No object ids are recorded until then.
  mainnet: undefined,
}

/** A network's committee, by network name. */
export type SealCommitteeNetwork = keyof typeof SEAL_COMMITTEES

/**
 * What is already decided for a network whose committee is not yet published: the operators and the
 * threshold (ADR-0002, D24). The object ids are added to {@link SEAL_COMMITTEES} at publication.
 */
export const SEAL_COMMITTEES_PENDING = {
  mainnet: {
    threshold: 2,
    providers: ['Overclock', 'NodeInfra', 'H2O Open mode'],
  },
} as const

/**
 * The published committee on `network`.
 *
 * @throws {Error} if no committee is published for `network` (unknown network, or mainnet before publication).
 */
export function sealCommittee(network: string): SealCommittee {
  const committee = Object.hasOwn(SEAL_COMMITTEES, network) ? (SEAL_COMMITTEES as Record<string, SealCommittee | undefined>)[network] : undefined
  if (!committee) throw new Error(`no Seal key-server committee is published for ${network}`)
  return committee
}

/** The `SealController` `serverConfigs` for a committee (a server's `url` becomes its `aggregatorUrl`). */
export function committeeServerConfigs(committee: SealCommittee): KeyServerConfig[] {
  return committee.servers.map((s) => ({ objectId: s.objectId, weight: s.weight, ...(s.url ? { aggregatorUrl: s.url } : {}) }))
}
