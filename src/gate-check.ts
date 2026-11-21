/**
 * @file The check that a gate is one the sealed-storage policies can actually be unlocked by.
 *
 * Role: a Seal policy is tied to the `access_gate` package it was published against. Sealing to an object of any other type succeeds but can never be
 * decrypted, so the check runs before the person encrypts. Main export: `assertLinkedGate`. Tested in `tests/refusal.test.ts` and the live suite.
 */
import { normalizeStructTag, normalizeSuiAddress } from '@mysten/sui/utils'
import type { SealSuggestClient } from './types.js'

/**
 * Check that `gateId` is a `Gate` of the `access_gate` package whose original id is
 * `accessGateOriginalId` (the one `sealed_storage` links). Sealing to anything else (a typo, a
 * non-gate object, a gate of a superseded package) succeeds but can never be unlocked, because
 * `nft_gate::seal_approve` only accepts the linked package's `Gate` type.
 *
 * With `requireSoulbound`, a gate that mints transferable passes is refused too: a holder of a transferable
 * pass (`AccessNFT` has `store`) can freeze or share it, after which anyone can present it and the policy
 * approves, so sealed content is only as private as the gate's passes are soulbound.
 *
 * @throws {Error} if the object cannot be read, is not that package's `Gate`, or (with `requireSoulbound`)
 *   mints transferable passes.
 */
export async function assertLinkedGate(
  client: SealSuggestClient,
  gateId: string,
  accessGateOriginalId: string,
  options: { requireSoulbound?: boolean } = {},
): Promise<void> {
  // Fields are fetched only when the soulbound flag has to be read.
  const { object } = await client.core.getObject({
    objectId: normalizeSuiAddress(gateId),
    ...(options.requireSoulbound ? { include: { json: true } } : {}),
  })
  // The expected full type, and the object's own type, both normalised so address spellings compare equal.
  const want = normalizeStructTag(`${normalizeSuiAddress(accessGateOriginalId)}::access_gate::Gate`)
  const have = object.type ? normalizeStructTag(object.type) : undefined
  if (have !== want) {
    throw new Error(`sealed-storage-client: ${gateId} is not a Gate of the linked access_gate package; content sealed to it could never be decrypted.`)
  }
  // `soulbound` must be exactly `true`: a missing or mistyped field is not proof, and the check fails closed.
  if (options.requireSoulbound && object.json?.soulbound !== true) {
    throw new Error(
      `sealed-storage-client: gate ${gateId} mints transferable passes; a holder can freeze one into public access. ` +
        'Seal to a soulbound gate, or set allowTransferableGates to accept this.',
    )
  }
}
