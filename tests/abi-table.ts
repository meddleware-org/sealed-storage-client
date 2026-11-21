// Every transaction builder and every policy provider's `buildApprove`, called with placeholder ids,
// and the Move calls they produce. Shared by the offline completeness test and the testnet
// ABI-drift check (tests/integration/abi-drift).
//
// Why: the live drift check compares the table with the deployed package; the offline test below proves the table is complete, so adding a builder or a
// policy without a table entry fails before it can escape the drift check.
import { Transaction } from '@mysten/sui/transactions'
import * as client from '../src/index.js'

/** A placeholder package id: nothing here reads a chain. */
export const PKG = '0x' + 'a1'.repeat(32)
/** A distinct placeholder object id per number, so a test can tell which argument went where. */
const id = (n: number) => '0x' + n.toString(16).padStart(64, '0')
/** The call target of every builder: our placeholder package and a placeholder PolicyConfig. */
const target = { publishedAt: PKG, policyConfigId: id(1) }
/** Valid pointer fields for the publish builders. */
const content = { gateId: id(2), blobId: 'blob', sealId: 'ab', label: 'l' }
/** A 48-byte identity, the length of an nft-gate identity (32-byte gate id + 16-byte nonce). The providers' `buildApprove` does not check the layout. */
const idBytes = new Uint8Array(48)

/** The `seal_approve*` transaction of the default registry's provider `type` for `params`. */
function approve(type: string, params: Record<string, unknown>): Transaction {
  const tx = new Transaction()
  client.createDefaultRegistry().get(type).buildApprove(tx, target, idBytes, params)
  return tx
}

/** Exported builder name → transactions it builds. */
export const BUILDERS: Record<string, () => Transaction[]> = {
  buildPublishSealedContentTransaction: () => [client.buildPublishSealedContentTransaction(target, content)],
  buildPublishSealedContentTx: () => {
    const tx = new Transaction()
    client.buildPublishSealedContentTx(tx, target, content)
    return [tx]
  },
}

/** Policy provider type → `seal_approve*` transactions (one per Move function it can choose). */
export const PROVIDERS: Record<string, () => Transaction[]> = {
  'nft-gate': () => [
    approve('nft-gate', { gateId: id(2), nftId: id(3) }),
    approve('nft-gate', { gateId: id(2), nftId: id(3), soulbound: true }),
  ],
  'time-lock': () => [approve('time-lock', {})],
}

/** One Move call in a transaction, reduced to what the ABI check compares. */
export interface MoveCallShape {
  /** The package id the call targets. */
  package: string
  /** The module. */
  module: string
  /** The function. */
  function: string
  /** How many type arguments the call carries. */
  typeArguments: number
  /** How many arguments the call carries. */
  arguments: number
}

/** The Move calls in `tx`, as target + arity. */
export function moveCalls(tx: Transaction): MoveCallShape[] {
  // Only `MoveCall` commands matter here.
  return tx.getData().commands.flatMap((c) =>
    c.$kind === 'MoveCall'
      ? [{
          package: c.MoveCall.package,
          module: c.MoveCall.module,
          function: c.MoveCall.function,
          typeArguments: c.MoveCall.typeArguments.length,
          arguments: c.MoveCall.arguments.length,
        }]
      : [],
  )
}

/** Every distinct Move call the builders and providers make. */
export function allMoveCalls(): MoveCallShape[] {
  // Keyed by target, so a function called by two variants counts once.
  const seen = new Map<string, MoveCallShape>()
  for (const build of [...Object.values(BUILDERS), ...Object.values(PROVIDERS)]) {
    for (const tx of build()) {
      for (const call of moveCalls(tx)) seen.set(`${call.package}::${call.module}::${call.function}`, call)
    }
  }
  return [...seen.values()]
}

/** Exported builder names (`build…Tx` / `build…Transaction`). */
export const exportedBuilders = Object.keys(client).filter((k) => /^build\w*(Tx|Transaction)$/.test(k)).sort()

/** Policy types the default registry ships. */
export const registeredPolicies = client.createDefaultRegistry().list().map((p) => p.type).sort()
