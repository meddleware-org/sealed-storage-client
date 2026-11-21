/**
 * @file The `nft-gate` Seal policy: only holders of a pass for one access gate can decrypt.
 *
 * Role: mirrors the `sealed_storage::nft_gate` Move module 1:1. The Seal identity is `[32-byte gate id][16-byte random nonce]`; a decrypt builds the
 * `seal_approve` (or `seal_approve_soulbound`) call the key servers dry-run. Main export: `createNftGateProvider`. Tested in `tests/providers.test.ts`.
 * The identity layout and the call arguments must change together with the Move module (the live suite checks them).
 */
import { fetchOwnedGates } from '@meddleware/access-gate-client'
import type { SealPolicyProvider, PolicyDescriptor, FieldSuggestion, SuggestContext } from '../types.js'
import { objectIdBytes, randomBytes, concatBytes } from '../bytes.js'

/** The parameters of the nft-gate policy, as stored (without secrets) in a manifest. */
export interface NftGateParams {
  /** Access gate shared object id (0x…). Needed to encrypt AND decrypt. */
  gateId: string
  /** The holder's pass NFT object id. Needed only to decrypt. */
  nftId?: string
  /** Whether the gate mints soulbound passes. Needed only to decrypt. */
  soulbound?: boolean
}

/**
 * Random nonce appended after the 32-byte gate id so each ciphertext gets a unique Seal identity.
 *
 * Width rationale (16 bytes / 128 bits): the 32-byte prefix is the *gate id* — a stable, public
 * value reused for every ciphertext encrypted under that gate. All per-ciphertext uniqueness
 * therefore comes from the nonce alone, so it is sized for a negligible birthday-collision
 * probability across an effectively unbounded ciphertext population per gate. (The identity is not
 * secret — it is stored verbatim in the manifest — so this is a uniqueness/domain-separation
 * budget, not a secrecy budget.) The width is fixed by the on-chain `sealed_storage::nft_gate`
 * identity layout `[32-byte gate id][16-byte nonce]`; do not change one side only. See SECURITY.md.
 */
const NONCE_LEN = 16

/**
 * A gate id as 32 bytes. An empty, `0x`-only or all-zero id would namespace the content to gate
 * `0x0`, which nobody can ever unlock, so it is refused.
 */
function requireGateId(gateId: string): Uint8Array {
  // A string of `0x` and 1 to 64 hex digits; anything else is a typo, not a gate.
  if (typeof gateId !== 'string' || !/^0x[0-9a-fA-F]{1,64}$/.test(gateId)) {
    throw new Error('nft-gate encrypt requires `gateId` (0x followed by up to 64 hex digits).')
  }
  // The all-zero id would silently namespace the content to a gate nobody controls.
  const bytes = objectIdBytes(gateId)
  if (bytes.every((b) => b === 0)) throw new Error('nft-gate gateId must not be the zero address.')
  return bytes
}

/** The form description of the policy: one field to encrypt (the gate), three to decrypt (gate, pass, soulbound flag). */
function descriptor(): PolicyDescriptor {
  return {
    type: 'nft-gate',
    label: 'Access-gate NFT',
    help: 'Only holders of a valid pass for the chosen access gate can decrypt.',
    encryptFields: [
      {
        name: 'gateId',
        label: 'Access gate ID',
        kind: 'objectId',
        required: true,
        help: 'The shared Gate object whose pass-holders may decrypt.',
      },
    ],
    decryptFields: [
      { name: 'gateId', label: 'Access gate ID', kind: 'objectId', required: true },
      { name: 'nftId', label: 'Your pass NFT', kind: 'objectId', required: true },
      { name: 'soulbound', label: 'Soulbound pass', kind: 'boolean', required: false },
    ],
  }
}

/**
 * Create an nft-gate policy provider.
 *
 * @param accessGateOriginalId - The `access_gate` package's **original id** on the target network
 *   (`accessGateDeployment(network).originalId` from `@meddleware/access-gate-client/deployments`).
 *   When non-empty, `suggest()` lists the gates the connected wallet administers.
 */
export function createNftGateProvider(accessGateOriginalId = ''): SealPolicyProvider<NftGateParams> {
  return {
    type: 'nft-gate',

    // The identity is the gate id followed by a random nonce, so every ciphertext under a gate has its own identity.
    buildId(params) {
      return concatBytes(requireGateId(params.gateId), randomBytes(NONCE_LEN))
    },

    verifyId(idBytes, params) {
      // Layout `[32-byte gate id][16-byte nonce]` — anything else cannot have come from buildId.
      if (idBytes.length !== 32 + NONCE_LEN) {
        throw new Error(`sealed-storage-client: nft-gate id must be ${32 + NONCE_LEN} bytes ([gate id][nonce]); got ${idBytes.length}`)
      }
      // The first 32 bytes must be the gate the params name: a manifest whose id and params disagree is corrupt or mixed up.
      const expected = objectIdBytes(params.gateId)
      for (let i = 0; i < 32; i++) {
        if (idBytes[i] !== expected[i]) {
          throw new Error(
            `sealed-storage-client: id/params mismatch — stored id does not match params.gateId (byte ${i} differs). ` +
            `The manifest may be corrupted or the wrong params were supplied.`,
          )
        }
      }
    },

    buildApprove(tx, target, idBytes, params) {
      // Decrypting needs the person's pass; without it the call cannot be built.
      if (!params.nftId) {
        throw new Error('nft-gate decrypt requires `nftId` (the pass you hold for this gate).')
      }
      // The soulbound and transferable passes are different Move types, so they have different approve functions.
      const fn = params.soulbound ? 'seal_approve_soulbound' : 'seal_approve'
      // Argument order is the Move module's: the identity, the shared PolicyConfig (version gate), the gate, then the pass.
      tx.moveCall({
        target: `${target.publishedAt}::nft_gate::${fn}`,
        arguments: [
          tx.pure.vector('u8', Array.from(idBytes)),
          tx.object(target.policyConfigId),
          tx.object(params.gateId),
          tx.object(params.nftId),
        ],
      })
    },

    parseParams(raw) {
      if (!raw) throw new Error('nft-gate manifest params are missing (gateId is required).')
      const out: NftGateParams = { gateId: '' }
      // One object-id reader for the two id fields, naming the field in its error.
      const id = (key: string, value: unknown): string => {
        if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{1,64}$/.test(value)) {
          throw new Error(`nft-gate manifest params.${key} must be 0x followed by up to 64 hex digits.`)
        }
        return value
      }
      // Copy only the known keys; the gate is required, the other two optional but typed when present.
      out.gateId = id('gateId', raw.gateId)
      if (raw.nftId !== undefined) out.nftId = id('nftId', raw.nftId)
      if (raw.soulbound !== undefined) {
        if (typeof raw.soulbound !== 'boolean') throw new Error('nft-gate manifest params.soulbound must be a boolean.')
        out.soulbound = raw.soulbound
      }
      return out
    },

    describe: descriptor,

    async suggest({ account, client }: SuggestContext): Promise<Partial<Record<string, FieldSuggestion[]>>> {
      // Without the package id or an account there is nothing to look up.
      if (!accessGateOriginalId || !account) return {}
      const gates = await fetchOwnedGates(client, account, accessGateOriginalId)
      if (!gates.length) return {}
      return {
        // Label each gate with its NFT name, or the start of its id when it has none.
        gateId: gates.map((g) => ({ value: g.gateId, label: g.nftName || g.gateId.slice(0, 10) + '…' })),
      }
    },
  }
}
