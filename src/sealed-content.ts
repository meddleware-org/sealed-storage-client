/**
 * @file Publishing and discovering sealed-content pointers: the on-chain breadcrumbs that tell a gate's pass-holders where sealed blobs are.
 *
 * Role: a pointer binds a Walrus blob id and a Seal identity to a gate and is emitted as a `SealedContentPublished` event. It grants nothing on its own
 * (Seal and the `nft_gate` policy enforce confidentiality), and it proves nothing about authorship, so a listing can be limited to the publishers the caller
 * trusts. Listing reads the read-indexer first (display only) and falls back to a full node, like the events in `access-gate-client`.
 *
 * Main exports: `buildPublishSealedContentTransaction`, `buildPublishSealedContentTx`, `listSealedContent`, `parseSealedContentEvent`,
 * `sealedContentEventType`, `SEALED_CONTENT_LIMITS`. Tested in `tests/sealed-content.test.ts`.
 */
// `bcs` describes the event layout; the address helpers make ids comparable; `readIndexerEvents` is the shared, hardened indexer reader.
import { bcs } from '@mysten/sui/bcs'
import { Transaction } from '@mysten/sui/transactions'
import { fromBase64, normalizeStructTag, normalizeSuiAddress } from '@mysten/sui/utils'
import { readIndexerEvents } from '@meddleware/access-gate-client'
import type { CoreEventEntry, EventCursor, IndexerSource } from '@meddleware/access-gate-client'
import type { SealPolicyTarget } from './types.js'

/** Fields needed to publish an on-chain pointer binding sealed content to a gate. */
export interface SealedContentInput {
  /** The access gate object id the content is sealed to. */
  gateId: string
  /** Walrus blob id of the ciphertext. */
  blobId: string
  /** Seal identity (hex) the content was encrypted under. */
  sealId: string
  /** Human-readable label shown in unlock UIs. */
  label: string
}

/**
 * Byte limits `sealed_content::publish` enforces on its strings (mirrors the Move constants
 * `MAX_LABEL_BYTES` / `MAX_BLOB_ID_BYTES` / `MAX_SEAL_ID_BYTES`).
 */
export const SEALED_CONTENT_LIMITS = Object.freeze({ label: 256, blobId: 128, sealId: 256 })

/**
 * A transaction that publishes one sealed-content pointer (see {@link buildPublishSealedContentTx}).
 * `target` is the package's latest published-at and its shared `PolicyConfig`.
 *
 * @throws {Error} if a string exceeds its {@link SEALED_CONTENT_LIMITS} byte limit.
 */
export function buildPublishSealedContentTransaction(target: SealPolicyTarget, input: SealedContentInput): Transaction {
  const tx = new Transaction()
  buildPublishSealedContentTx(tx, target, input)
  return tx
}

/**
 * Append `sealed_storage::sealed_content::publish(...)` to `tx`. Sharing a `SealedContent` makes the
 * content discoverable by a gate's pass-holders (via the `SealedContentPublished` event). The
 * pointer grants nothing on its own — confidentiality is enforced by Seal + `nft_gate`.
 *
 * @throws {Error} if a string exceeds its {@link SEALED_CONTENT_LIMITS} byte limit (UTF-8), which
 *   the Move function would reject.
 */
export function buildPublishSealedContentTx(
  tx: Transaction,
  target: SealPolicyTarget,
  input: SealedContentInput,
): void {
  // The Move function limits each string in BYTES, not characters, so measure the UTF-8 length.
  const enc = new TextEncoder()
  for (const [field, max] of Object.entries(SEALED_CONTENT_LIMITS) as [keyof typeof SEALED_CONTENT_LIMITS, number][]) {
    const bytes = enc.encode(input[field]).length
    if (bytes > max) {
      throw new Error(`sealed-storage-client: ${field} is ${bytes} bytes; sealed_content::publish accepts at most ${max}`)
    }
  }
  // Argument order is the Move function's: the PolicyConfig (version gate), the gate id, then the three strings.
  tx.moveCall({
    target: `${target.publishedAt}::sealed_content::publish`,
    arguments: [
      tx.object(target.policyConfigId),
      tx.pure.id(input.gateId),
      tx.pure.string(input.blobId),
      tx.pure.string(input.sealId),
      tx.pure.string(input.label),
    ],
  })
}

/** A discovered on-chain pointer to gate-unlockable sealed content. */
export interface SealedContentPointer {
  /** The shared `SealedContent` object's id. */
  contentId: string
  /** The gate whose pass-holders can unlock the content. */
  gateId: string
  /** The Walrus blob id of the ciphertext. */
  blobId: string
  /** The Seal identity (hex) the content was encrypted under. */
  sealId: string
  /** The human-readable label. */
  label: string
  /** The address that published the pointer: whoever sent the transaction, so not proof of authorship. */
  publisher: string
  /** The publishing transaction, to check the pointer against a full node. */
  txDigest: string
  /** `null` where the transport does not report it. */
  checkpoint: string | null
}

/** The `SealedContentPublished` event type, normalised, at the package's **original id**. */
export function sealedContentEventType(originalId: string): string {
  return `${normalizeSuiAddress(originalId)}::sealed_content::SealedContentPublished`
}

// Decoded from BCS (exact on every transport); mirrors the Move event struct field for field.
/** The BCS layout of `SealedContentPublished`, in the Move struct's field order. */
const SealedContentPublished = bcs.struct('SealedContentPublished', {
  content_id: bcs.Address,
  gate_id: bcs.Address,
  blob_id: bcs.string(),
  seal_id: bcs.string(),
  label: bcs.string(),
  publisher: bcs.Address,
})

/**
 * Decode one `SealedContentPublished` event, or `null` unless its type is exactly that event of
 * `originalId` (normalised comparison; the same name in another package is rejected).
 *
 * @throws {Error} if the BCS bytes do not decode.
 */
export function parseSealedContentEvent(entry: CoreEventEntry, originalId: string): SealedContentPointer | null {
  let type: string
  // A type string that does not parse is not our event.
  try {
    type = normalizeStructTag(entry.eventType)
  } catch {
    return null
  }
  // The exact event of this package (the same name in another package is refused).
  if (type !== sealedContentEventType(originalId)) return null
  // The indexer serves base64 bytes; a full node gives bytes.
  const e = SealedContentPublished.parse(typeof entry.bcs === 'string' ? fromBase64(entry.bcs) : entry.bcs)
  return {
    contentId: e.content_id,
    gateId: e.gate_id,
    blobId: e.blob_id,
    sealId: e.seal_id,
    label: e.label,
    publisher: e.publisher,
    txDigest: entry.transactionDigest,
    checkpoint: entry.checkpoint,
  }
}

/** `parseSealedContentEvent`, with a row that fails to decode reported as `'invalid'` instead of thrown. */
function tryParse(entry: CoreEventEntry, originalId: string): SealedContentPointer | null | 'invalid' {
  try {
    return parseSealedContentEvent(entry, originalId)
  } catch {
    return 'invalid'
  }
}

/** Minimal structural subset of a core Sui client used for event queries (`SuiGrpcClient`). */
export interface SealEventsClient {
  /** The SDK's unified core API. */
  core: {
    /** One page of events, optionally only of one Move type. */
    listEvents(options: {
      /** Only events of this type. */
      filter?: { eventType: string }
      /** The page size. */
      limit?: number
      /** Where the previous page ended. */
      before?: string | null
      /** The order to read in. */
      order?: 'ascending' | 'descending'
    }): Promise<{ events: CoreEventEntry[]; hasNextPage: boolean; endCursor: string | null }>
  }
}

/** What `listSealedContent` accepts. */
export interface ListSealedContentOptions {
  /** The `sealed_storage` package's original id. */
  originalId: string
  /** The gate to list pointers for. */
  gateId: string
  /** Target number of pointers (default 50, at most 200). */
  limit?: number
  /** Continue from a previous page's `cursor`. */
  cursor?: EventCursor | null
  /** A read-indexer to try first. */
  indexer?: IndexerSource
  /** Full-node pages scanned per call (default 20). */
  maxPages?: number
  /**
   * Only list pointers published by these addresses. Seal gives confidentiality, not authenticity:
   * anyone can seal content to a gate's namespace and publish a pointer for it, and a pass holder
   * will decrypt it successfully. UIs should pass the gate's operators ({@link gateOperators}).
   */
  publishers?: string[]
}

/** Keep a pointer only if `publishers` is unset or lists its publisher (normalised comparison). */
function publishedBy(options: ListSealedContentOptions): (p: SealedContentPointer) => boolean {
  // No filter set: every publisher is accepted.
  if (!options.publishers) return () => true
  // Compare in normalised form, so the same address in two spellings matches.
  const allowed = new Set(options.publishers.map((a) => normalizeSuiAddress(a)))
  return (p) => allowed.has(normalizeSuiAddress(p.publisher))
}

/** One page of listed pointers. */
export interface SealedContentPage {
  /** Newest first. */
  pointers: SealedContentPointer[]
  /** Pass back as `cursor` for older pointers; `null` when there are none. */
  cursor: EventCursor | null
  /** Where this page came from. */
  source: 'indexer' | 'rpc'
  /** Oldest checkpoint the indexer covers. Indexer pages only. */
  indexedFromCheckpoint?: string
  /** Why the indexer was skipped, when a first page fell back to the full node. */
  indexerError?: string
  /** Rows of this package's event that did not decode and were skipped (one bad row must not fail the page). */
  skipped: number
}

/** Page size the public full nodes cap `listEvents` at. */
const RPC_PAGE = 50
/** At most 20 pages × 50 events are scanned per call, whatever `maxPages` says. */
const MAX_RPC_PAGES = 20

/**
 * Pointers published for `gateId`, newest first.
 *
 * - With `indexer`, a first page is read from it. If it fails or times out (3 s by default), the
 *   page comes from the full node and `indexerError` says why.
 * - A cursor stays with the source that issued it.
 * - On the full node, events are filtered here by gate. A page can hold up to one full-node page
 *   more than `limit`, or fewer when `maxPages` pages are scanned without filling it.
 *
 * @throws {Error} if the full node (or, for an indexer cursor, the indexer) fails.
 */
export async function listSealedContent(
  client: SealEventsClient,
  options: ListSealedContentOptions,
): Promise<SealedContentPage> {
  // Clamp the page size to 1..200.
  const limit = Math.min(Math.max(1, Math.floor(options.limit ?? 50)), 200)
  const { cursor, indexer } = options
  // The indexer is tried first, unless the cursor came from a full node.
  if (indexer && cursor?.source !== 'rpc') {
    try {
      return await listFromIndexer(indexer, options, limit, cursor?.value)
    } catch (e) {
      // A later page has no fallback (the full node cannot continue an indexer cursor); a first page falls back and says why.
      if (cursor) throw e
      const page = await listFromRpc(client, options, limit, null)
      return { ...page, indexerError: e instanceof Error ? e.message : String(e) }
    }
  }
  // An indexer cursor with no indexer cannot be continued anywhere.
  if (cursor?.source === 'indexer') throw new Error('sealed-storage-client: an indexer cursor needs the indexer option')
  return listFromRpc(client, options, limit, cursor?.value ?? null)
}

/** List pointers from a full node: read pages of the package's events (all gates) and keep this gate's, within a bounded scan. */
async function listFromRpc(
  client: SealEventsClient,
  options: ListSealedContentOptions,
  limit: number,
  before: string | null,
): Promise<SealedContentPage> {
  const gate = normalizeSuiAddress(options.gateId)
  // Each page scans RPC_PAGE events of ALL gates (the event filter cannot select one), so the scan is capped.
  const maxPages = Math.min(Math.max(1, Math.floor(options.maxPages ?? 20)), MAX_RPC_PAGES)
  const pointers: SealedContentPointer[] = []
  // Rows of this package's event that did not decode: counted, not thrown, so one bad row cannot fail the page.
  let skipped = 0
  let cursor = before
  for (let page = 0; page < maxPages; page++) {
    const res = await client.core.listEvents({
      filter: { eventType: sealedContentEventType(options.originalId) },
      limit: RPC_PAGE,
      order: 'descending',
      before: cursor,
    })
    for (const entry of res.events) {
      // Keep a pointer only if it is for this gate and from an accepted publisher.
      const pointer = tryParse(entry, options.originalId)
      if (pointer === 'invalid') skipped++
      else if (pointer && pointer.gateId === gate && publishedBy(options)(pointer)) pointers.push(pointer)
    }
    // Continue from where the node ended, or stop when it has no more or the page is full.
    cursor = res.hasNextPage ? res.endCursor : null
    if (!cursor || pointers.length >= limit) break
  }
  return { pointers, cursor: cursor ? { source: 'rpc', value: cursor } : null, source: 'rpc', skipped }
}

/** List pointers from the read-indexer: one request, rows decoded and filtered here (the indexer is display-only, never trusted). */
async function listFromIndexer(
  indexer: IndexerSource,
  options: ListSealedContentOptions,
  limit: number,
  before: string | undefined,
): Promise<SealedContentPage> {
  const gate = normalizeSuiAddress(options.gateId)
  // The shared reader: https only, the timeout, a body cap before parsing, a checked page shape.
  const body = await readIndexerEvents(indexer, `v1/${encodeURIComponent(indexer.network)}/sealed-content`, {
    gate,
    before,
    limit: String(limit),
  })

  // The indexer is display-only: rows still have to be this package's event for this gate.
  // Decode every row; a row that does not decode is counted, not fatal.
  const parsed = body.events.map((entry) => tryParse(entry, options.originalId))
  const skipped = parsed.filter((p) => p === 'invalid').length
  const pointers = parsed.filter(
    (p): p is SealedContentPointer => p !== null && p !== 'invalid' && p.gateId === gate && publishedBy(options)(p),
  )
  // The indexer's cursor is wrapped with its source so it cannot be sent to a full node.
  return {
    pointers,
    skipped,
    cursor: body.cursor ? { source: 'indexer', value: body.cursor } : null,
    source: 'indexer',
    indexedFromCheckpoint: body.indexedFromCheckpoint,
  }
}
