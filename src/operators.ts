/**
 * @file Which addresses to trust as authors of a gate's sealed content.
 *
 * Role: Seal gives confidentiality, not authenticity, so a UI that lists a gate's sealed items should list only those published by the operator (or by addresses
 * the operator vouches for). Main export: `gateOperators`. Tested in `tests/operators.test.ts`.
 */
import { fetchGate } from '@meddleware/access-gate-client'
import type { SuiObjectClient } from '@meddleware/access-gate-client'
import { normalizeSuiAddress } from '@mysten/sui/utils'

/**
 * The addresses to trust as authors of a gate's sealed content: the gate's `payment_recipient` (the
 * address the operator set to receive its income) plus any `extra` addresses the caller vouches for
 * (for example the operator's own publishing wallet, since a pointer's `publisher` is whoever sent
 * the transaction). Pass the result as `listSealedContent({ publishers })`.
 *
 * Seal gives confidentiality, not authenticity: a successful decrypt proves only that the item was
 * sealed to the gate's namespace, not who wrote it. Listing only the operator's pointers is the
 * default a UI should use.
 *
 * @throws {Error} if the gate cannot be read or is not a `Gate` of `accessGateOriginalId`.
 */
export async function gateOperators(
  client: SuiObjectClient,
  gateId: string,
  accessGateOriginalId: string,
  extra: string[] = [],
): Promise<string[]> {
  // Read the gate from the chain (the payment recipient is the operator's own income address).
  const gate = await fetchGate(client, gateId, accessGateOriginalId)
  if (!gate) throw new Error(`sealed-storage-client: ${gateId} is not a Gate of ${accessGateOriginalId}`)
  // Normalised and de-duplicated, so the same address in two spellings counts once.
  return [...new Set([gate.paymentRecipient, ...extra].map((a) => normalizeSuiAddress(a)))]
}
