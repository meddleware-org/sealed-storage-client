/**
 * @file The `time-lock` Seal policy: anyone can decrypt once the on-chain clock passes the unlock time.
 *
 * Role: mirrors the `sealed_storage::timelock` Move module 1:1. The Seal identity is `[8-byte big-endian unlock_ms][8-byte random nonce]`; a decrypt builds the
 * `seal_approve` call (with the shared Clock) the key servers dry-run. It shares nothing with `nft-gate`. Main export: `timeLockProvider`. Tested in
 * `tests/providers.test.ts`.
 */
import type { SealPolicyProvider, PolicyDescriptor } from '../types.js'
import { u64beBytes, randomBytes, concatBytes } from '../bytes.js'

/** The parameters of the time-lock policy. */
export interface TimeLockParams {
  /** Unlock time in epoch milliseconds. Needed to encrypt; not needed to decrypt. */
  unlockMs?: number | bigint
  /**
   * Allow an unlock time that has already passed. By default encrypting with a past time throws:
   * content "locked" until a moment that is gone is public as soon as it is stored.
   */
  allowPast?: boolean
}

/** The shared on-chain Clock object id. */
const CLOCK_ID = '0x6'
/**
 * Random nonce appended after the 8-byte unlock timestamp.
 *
 * Width rationale (8 bytes / 64 bits): the prefix is an 8-byte big-endian unlock timestamp, which
 * is low-entropy and frequently shared (many documents unlock at the same instant), so the nonce
 * disambiguates ciphertexts that share an unlock time. 64 bits is comfortably collision-safe for
 * the per-unlock-time population and keeps the identity compact and symmetric with the 8-byte
 * timestamp (total 16 bytes). As with nft-gate this is a uniqueness budget, not a secrecy one — the
 * identity is public in the manifest. The width is fixed by the on-chain
 * `sealed_storage::timelock` identity layout `[8-byte BE unlock_ms][8-byte nonce]`; do not change one
 * side only. See SECURITY.md.
 */
const NONCE_LEN = 8

/**
 * Time-lock encryption: decryptable by anyone once the on-chain Clock passes the unlock time.
 * Mirrors `sealed_storage::timelock`. Identity layout: `[8-byte BE unlock_ms][8-byte nonce]`.
 * Deliberately shares nothing with `nft-gate` — different fields, different args.
 */
export const timeLockProvider: SealPolicyProvider<TimeLockParams> = {
  type: 'time-lock',

  buildId(params) {
    // The unlock time is the whole point of the policy; without it there is nothing to build.
    if (params.unlockMs == null) {
      throw new Error('time-lock encrypt requires `unlockMs` (unlock time in epoch ms).')
    }
    // u64beBytes rejects non-integers, negatives and anything that would wrap past 2^64 - 1.
    const unlock = u64beBytes(params.unlockMs)
    // Content "locked" until a moment that has passed is public the instant it is stored, so refuse unless the caller says it is intended.
    if (!params.allowPast && BigInt(params.unlockMs) <= BigInt(Date.now())) {
      throw new Error('time-lock unlockMs is not in the future; pass allowPast: true if that is intended.')
    }
    // The timestamp first, then the nonce that tells apart ciphertexts sharing an unlock time.
    return concatBytes(unlock, randomBytes(NONCE_LEN))
  },

  verifyId(idBytes) {
    // Layout `[8-byte BE unlock_ms][8-byte nonce]` — anything else cannot have been produced by
    // buildId and would be rejected on-chain.
    if (idBytes.length !== 8 + NONCE_LEN) {
      throw new Error(
        `sealed-storage-client: time-lock id must be ${8 + NONCE_LEN} bytes ([unlock_ms][nonce]); got ${idBytes.length}`,
      )
    }
  },

  buildApprove(tx, target, idBytes) {
    // The Clock is a shared object the contract compares with the unlock time; there is no pass to present.
    tx.moveCall({
      target: `${target.publishedAt}::timelock::seal_approve`,
      arguments: [tx.pure.vector('u8', Array.from(idBytes)), tx.object(target.policyConfigId), tx.object(CLOCK_ID)],
    })
  },

  // One field to encrypt (the unlock time) and none to decrypt: anyone can, once the time has passed.
  describe(): PolicyDescriptor {
    return {
      type: 'time-lock',
      label: 'Time lock',
      help: 'Anyone can decrypt once the unlock time has passed.',
      encryptFields: [
        {
          name: 'unlockMs',
          label: 'Unlock time',
          kind: 'datetime',
          required: true,
          help: 'The ciphertext becomes decryptable at this moment.',
        },
      ],
      decryptFields: [],
    }
  },
}
