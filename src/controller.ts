/**
 * @file `SealController`: threshold encrypt and decrypt over a registry of policy providers, with a cached per-address SessionKey.
 *
 * Role: the one place that talks to the Seal key servers. It owns no policy logic (each provider builds its own identity and approve call), but it owns the
 * checks that keep a person from losing data or leaking keys: the committee and threshold are validated, a gate is checked before sealing to it, and before
 * any key is requested a ciphertext must name the identity and policy package the caller expects and the approve transaction must hold only `seal_approve*`
 * calls. Main exports: `SealController`, `describeCiphertext`, `sealedUnderServers`, `assertApproveOnly`. Tested in `tests/controller.test.ts` and
 * `tests/refusal.test.ts`; the real key servers are exercised by the live suite (`tests/integration/`).
 */
// The SDK's client, session key and ciphertext parser.
import { EncryptedObject, SealClient, SessionKey } from '@mysten/seal'
import type { SealCompatibleClient } from '@mysten/seal'
import { Transaction } from '@mysten/sui/transactions'
import type { PolicyRegistry } from './registry.js'
import { bytesToHex, hexToBytes } from './bytes.js'
import { assertLinkedGate } from './gate-check.js'
import { explainApproveRefusal } from './refusal.js'
import type { RefusalClient, RefusalExplanation } from './refusal.js'
import type { SealSuggestClient } from './types.js'

/** One key server in the threshold committee. */
export interface KeyServerConfig {
  /** On-chain key server object id. */
  objectId: string
  /** Contribution toward the threshold (default 1). */
  weight?: number
  /** Aggregator URL — required for committee-mode key servers (all fetch-key calls proxy it). */
  aggregatorUrl?: string
  /** API-key header name for an authenticated server/aggregator (e.g. `X-API-Key`). */
  apiKeyName?: string
  /** API key for an authenticated server/aggregator (a publishable client key — it ships to browsers). */
  apiKey?: string
}

/** Everything a `SealController` needs: the chain objects, the committee and its threshold, and the safety switches. */
export interface SealControllerConfig {
  /** A Sui client exposing the core API (e.g. `SuiGrpcClient` from `@mysten/sui/grpc`). */
  suiClient: SealCompatibleClient
  /**
   * The `sealed_storage` package's **original id**: the Seal identity namespace (encrypt, the
   * ciphertext check) and the SessionKey scope. It never changes across upgrades.
   */
  originalId: string
  /** The package's latest **published-at** id: the call target of the `seal_approve*` PTB. */
  publishedAt: string
  /** The package's shared `PolicyConfig` (version gate), passed to every `seal_approve*`. */
  policyConfigId: string
  /** Committee of key servers: encryption targets all; decryption needs `threshold` of them. */
  serverConfigs: KeyServerConfig[]
  /** `t` in t-of-n. With a 3-server committee, 2 tolerates any one server being offline. */
  threshold: number
  /** SessionKey time-to-live in minutes (default 10). */
  sessionTtlMin?: number
  /**
   * Verify each key server's URL against its on-chain object before use (prevents a look-alike
   * server object pointing at a known URL). Defaults to `true` unless any server is reached through
   * an aggregator (committee mode), where per-server verification does not apply.
   *
   * The SDK offers one global switch, not one per server: in a mixed configuration (an aggregator plus
   * independent servers) the default turns verification off for the independent servers too. See
   * {@link SealController.verifiesKeyServers}.
   */
  verifyKeyServers?: boolean
  /**
   * Check that key shares from different servers are consistent before combining them (default
   * `true`, recommended by Seal for sensitive data).
   */
  checkShareConsistency?: boolean
  /**
   * The `access_gate` package's original id that `sealed_storage` links. When set, `encrypt` for the
   * `nft-gate` policy reads the gate first and refuses one that is not a `Gate` of that package
   * (content sealed to it could never be decrypted).
   */
  accessGateOriginalId?: string
  /**
   * Allow sealing to a gate that mints transferable passes (default `false`). A holder of a transferable pass
   * can freeze or share it, after which anyone can present it and `nft_gate::seal_approve` approves: the
   * content is then effectively public. Only checked when `accessGateOriginalId` is set (the gate is read).
   */
  allowTransferableGates?: boolean
}

/** Wallet hook: sign a personal message, returning the signature (base64). */
export type SignPersonalMessage = (message: Uint8Array) => Promise<{ signature: string }>

/** What `encrypt` returns. */
export interface EncryptResult {
  /** Seal identity (hex, no `0x`) — persist this in the manifest; required verbatim to decrypt. */
  id: string
  /** The encrypted object bytes to store (e.g. upload to Walrus). */
  ciphertext: Uint8Array
}

/**
 * Orchestrates Seal threshold encrypt/decrypt over a policy registry, and manages the per-address
 * SessionKey (signed once, cached until it expires). No policy logic lives here — that is entirely
 * in the registered providers, so new policy types need no controller changes.
 */
export class SealController {
  /** The SDK client, configured once from the committee. */
  private readonly client: SealClient
  /** Cached session keys by address and policy package, each with the time after which it must not be reused. */
  private readonly sessions = new Map<string, { key: SessionKey; expiresAt: number }>()
  /** Session keys being minted right now, so concurrent decrypts share one wallet prompt. */
  private readonly minting = new Map<string, Promise<SessionKey>>()

  constructor(
    private readonly cfg: SealControllerConfig,
    private readonly registry: PolicyRegistry,
  ) {
    // A session shorter than two minutes would be treated as expired by the one-minute early-expiry margin the moment it is minted.
    const ttl = cfg.sessionTtlMin ?? 10
    if (ttl < 2) {
      throw new Error(
        `sessionTtlMin must be ≥ 2 (got ${ttl}); a shorter TTL leaves no window before the early-expiry guard fires`,
      )
    }
    // The committee in the SDK's shape: a missing weight is 1, and an API key (publishable, it ships to browsers) gets its header name.
    this.client = new SealClient({
      suiClient: cfg.suiClient,
      serverConfigs: cfg.serverConfigs.map((s) => ({
        objectId: s.objectId,
        weight: s.weight ?? 1,
        aggregatorUrl: s.aggregatorUrl,
        ...(s.apiKey ? { apiKeyName: s.apiKeyName ?? 'X-API-Key', apiKey: s.apiKey } : {}),
      })),
      verifyKeyServers: cfg.verifyKeyServers ?? !cfg.serverConfigs.some((s) => s.aggregatorUrl),
    }) // see `verifiesKeyServers`
    // The threshold must be reachable: at least 1 and at most the total weight, or no set of servers could ever release a key (the data would be unrecoverable).
    const totalWeight = cfg.serverConfigs.reduce((n, s) => n + (s.weight ?? 1), 0)
    if (!Number.isInteger(cfg.threshold) || cfg.threshold < 1 || cfg.threshold > totalWeight) {
      throw new Error(
        `threshold must be an integer in [1, ${totalWeight}] (the total server weight); got ${cfg.threshold}`,
      )
    }
  }

  /**
   * Whether key-server URLs are verified against their on-chain objects. It is one SDK-wide switch: on by
   * default, but off as soon as ANY server is reached through an aggregator — so in a mixed configuration
   * the independent servers are not URL-verified either. Check this before trusting a mixed setup.
   */
  get verifiesKeyServers(): boolean {
    return this.cfg.verifyKeyServers ?? !this.cfg.serverConfigs.some((s) => s.aggregatorUrl)
  }

  /** Encrypt `data` under policy `type` with `params`. Returns the identity (hex) + ciphertext. */
  async encrypt<P>(type: string, params: P, data: Uint8Array): Promise<EncryptResult> {
    // The provider owns the identity layout; the controller only hex-encodes it for the manifest.
    const provider = this.registry.get<P>(type)
    const id = bytesToHex(provider.buildId(params))
    const gateId = (params as { gateId?: unknown } | null)?.gateId
    // For the nft-gate policy, check the gate before sealing: sealing to anything else succeeds but can never be unlocked.
    if (type === 'nft-gate' && this.cfg.accessGateOriginalId && typeof gateId === 'string') {
      await assertLinkedGate(this.cfg.suiClient as unknown as SealSuggestClient, gateId, this.cfg.accessGateOriginalId, {
        requireSoulbound: !this.cfg.allowTransferableGates,
      })
    }
    // Threshold encryption to the whole committee, under the policy package's original id (the Seal namespace).
    const { encryptedObject } = await this.client.encrypt({
      threshold: this.cfg.threshold,
      packageId: this.cfg.originalId,
      id,
      data,
    })
    return { id, ciphertext: encryptedObject }
  }

  /**
   * Decrypt `ciphertext` sealed under policy `type` with identity `id` (hex, from the manifest).
   * `params` supplies the on-chain objects the policy's `seal_approve` needs. Prompts a single
   * wallet personal-message signature per address to mint a SessionKey (cached until expiry).
   *
   * Before any key is requested it checks, and throws on a mismatch: the id is even-length hex; the
   * provider's `verifyId` (layout and consistency with `params`); that the ciphertext header names the
   * same identity and this controller's policy package; and that the approve PTB holds only
   * `seal_approve*` calls to the policy package.
   */
  async decrypt<P>(
    type: string,
    params: P,
    id: string,
    ciphertext: Uint8Array,
    opts: { address: string; signPersonalMessage: SignPersonalMessage },
  ): Promise<Uint8Array> {
    // Everything below is checked BEFORE any key is requested, so a wrong input never costs a wallet prompt or a key-server request.
    const provider = this.registry.get<P>(type)
    if (id.length % 2 !== 0) throw new Error(`malformed Seal id (odd hex length): ${id}`)
    const idBytes = hexToBytes(id)
    // Defense-in-depth: verify stored id is consistent with the supplied params.
    provider.verifyId(idBytes, params)
    // The ciphertext itself names the identity and namespace it was sealed to; refuse to request
    // keys for a different identity than the one the caller expects (a swapped ciphertext or a
    // tampered manifest would otherwise ask the servers for the wrong key).
    const sealed = EncryptedObject.parse(ciphertext)
    if (sealed.id.toLowerCase().replace(/^0x/, '') !== id.toLowerCase()) {
      throw new Error('sealed-storage-client: ciphertext identity does not match the expected Seal id')
    }
    // Sealed under another package: the key servers would evaluate another package's policy.
    if (normalizeHexId(sealed.packageId) !== normalizeHexId(this.cfg.originalId)) {
      throw new Error('sealed-storage-client: ciphertext was sealed under a different policy package')
    }
    // The session key (one wallet signature per address, cached), then the approve transaction the key servers dry-run.
    const sessionKey = await this.session(opts.address, opts.signPersonalMessage)

    const tx = new Transaction()
    provider.buildApprove(tx, { publishedAt: this.cfg.publishedAt, policyConfigId: this.cfg.policyConfigId }, idBytes, params)
    // A provider must not smuggle other commands into the transaction the servers evaluate.
    assertApproveOnly(tx, this.cfg.publishedAt)
    // `onlyTransactionKind`: the servers need the commands, not a gas payment or a sender.
    const txBytes = await tx.build({ client: this.cfg.suiClient, onlyTransactionKind: true })

    return this.client.decrypt({
      data: ciphertext,
      sessionKey,
      txBytes,
      // On by default: key shares from different servers are verified before they are combined.
      checkShareConsistency: this.cfg.checkShareConsistency ?? true,
    })
  }

  /**
   * Explain why a decrypt was (or would be) refused: builds the same approve PTB `decrypt` sends to the key
   * servers, simulates it as `opts.address` over the controller's client (read-only: no signing, no funds, one
   * RPC) and returns the policy abort it hits. The key servers' own refusal (`NoAccessError`,
   * `InvalidParameterError`) carries no abort, which is why this exists.
   *
   * Call it after a decrypt failed, never automatically: `decrypt` does not call it. It does not throw on a
   * refusal; an error while simulating (network, a node that rejects the build) comes back as
   * `kind: 'unknown'` with the error as `cause`. `kind: 'allowed'` means the policy approves this address, so the
   * refusal came from the key servers (unreachable, below the threshold, or a full node that has not seen a new
   * object yet). It does not use or mint a SessionKey.
   *
   * @throws {Error} only for an unregistered policy `type` (as `decrypt`).
   */
  async explainRefusal<P>(
    type: string,
    params: P,
    id: string,
    opts: { address: string },
  ): Promise<RefusalExplanation> {
    const provider = this.registry.get<P>(type)
    let tx: Transaction
    // Building can fail (a bad id, a provider error); that is reported as `unknown`, not thrown, because this method explains failures.
    try {
      const idBytes = hexToBytes(id)
      tx = new Transaction()
      provider.buildApprove(tx, { publishedAt: this.cfg.publishedAt, policyConfigId: this.cfg.policyConfigId }, idBytes, params)
      assertApproveOnly(tx, this.cfg.publishedAt)
    } catch (error) {
      const text = error instanceof Error ? error.message : String(error)
      return { kind: 'unknown', message: `Could not build the access check: ${text}`, cause: error }
    }
    return explainApproveRefusal(this.cfg.suiClient as unknown as RefusalClient, tx, {
      sender: opts.address,
      policyPackageIds: [this.cfg.originalId, this.cfg.publishedAt],
    })
  }

  /**
   * Drop cached SessionKey(s). Call this on wallet disconnect or account change so a key minted
   * for a previous address is never reused after reconnect — a reused session would sign key-server
   * requests under a stale identity. With no argument, clears every cached session; with an
   * address, clears just that one.
   */
  clearSession(address?: string): void {
    // No argument: every address (a full disconnect). With one: just that address.
    if (address === undefined) this.sessions.clear()
    else this.sessions.delete(this.sessionKeyId(address))
  }

  /** Sessions are scoped to the address AND the policy package they authorise. */
  private sessionKeyId(address: string): string {
    // Lower-case, so the same address in two spellings shares one session; the package is part of the key because a session authorises one package.
    return `${address.toLowerCase()}:${normalizeHexId(this.cfg.originalId)}`
  }

  /** The cached session key for `address`, or a freshly minted one (one mint in flight per address). */
  private async session(address: string, sign: SignPersonalMessage): Promise<SessionKey> {
    const cached = this.sessions.get(this.sessionKeyId(address))
    if (cached && cached.expiresAt > Date.now()) return cached.key

    // Concurrent decrypts share one mint (and one wallet prompt).
    const id = this.sessionKeyId(address)
    const pending = this.minting.get(id)
    if (pending) return pending
    // Forget the in-flight mint when it settles, whether it worked or not, so a failure can be retried.
    const minted = this.mint(address, sign, id).finally(() => this.minting.delete(id))
    this.minting.set(id, minted)
    return minted
  }

  /** Create a session key, have the wallet sign its message, and cache it under `id`. */
  private async mint(address: string, sign: SignPersonalMessage, id: string): Promise<SessionKey> {
    const ttlMin = this.cfg.sessionTtlMin ?? 10
    // The key's lifetime starts when it is created and is bound into the message the wallet signs,
    // so the cache margin counts from here, not from when the (possibly slow) signature returns.
    const createdAt = Date.now()
    const key = await SessionKey.create({
      address,
      packageId: this.cfg.originalId,
      ttlMin,
      suiClient: this.cfg.suiClient,
    })
    const { signature } = await sign(key.getPersonalMessage())
    // The signature is checked by the SDK when it is set.
    await key.setPersonalMessageSignature(signature)
    // Expire a minute early so we never hand a just-expired key to a key server.
    this.sessions.set(id, { key, expiresAt: createdAt + (ttlMin - 1) * 60_000 })
    return key
  }
}

/**
 * An approve PTB holds only `seal_approve*` calls to the policy package (the key servers reject
 * anything else; checking here fails fast and keeps a misbehaving provider from building more).
 *
 * @throws {Error} if the PTB is empty or holds any other command or target.
 */
export function assertApproveOnly(tx: Transaction, publishedAt: string): void {
  const pkg = normalizeHexId(publishedAt)
  const commands = tx.getData().commands
  // An empty transaction approves nothing; a provider that built none has a bug.
  if (commands.length === 0) throw new Error('sealed-storage-client: the approve PTB is empty')
  // Every command must be a Move call, to the policy package, to a function named `seal_approve…`.
  for (const c of commands) {
    const call = c.$kind === 'MoveCall' ? c.MoveCall : null
    if (!call || normalizeHexId(call.package) !== pkg || !call.function.startsWith('seal_approve')) {
      throw new Error('sealed-storage-client: the approve PTB may hold only seal_approve* calls to the policy package')
    }
  }
}

/** Lower-case, `0x`-prefixed, zero-padded 32-byte hex id for comparisons. */
function normalizeHexId(v: string): string {
  // Strip the prefix and pad to 64 digits, so `0x2` and its full form compare equal.
  const hex = v.toLowerCase().replace(/^0x/, '')
  return `0x${hex.padStart(64, '0')}`
}

/** What a ciphertext's header records: who can release its key, and under which policy package. */
export interface CiphertextInfo {
  /** Seal identity (hex, no `0x`). */
  id: string
  /** The policy package's original id (normalised). */
  packageId: string
  /** How much weight must cooperate to open it. */
  threshold: number
  /** Key servers it was sealed to, with their weights (normalised object ids, in header order). */
  servers: { objectId: string; weight: number }[]
}

/**
 * Read a ciphertext's header without decrypting. The header names the key servers and threshold it
 * was sealed under; decrypting needs a controller configured with those servers (re-sealing moves
 * content to a new set).
 *
 * @throws {Error} if the bytes are not a Seal ciphertext.
 */
export function describeCiphertext(ciphertext: Uint8Array): CiphertextInfo {
  const parsed = EncryptedObject.parse(ciphertext)
  const servers: { objectId: string; weight: number }[] = []
  // The header lists one entry per share; a server that holds several shares appears several times, which is its weight.
  for (const [objectId] of parsed.services) {
    const id = normalizeHexId(objectId)
    const existing = servers.find((s) => s.objectId === id)
    if (existing) existing.weight += 1
    else servers.push({ objectId: id, weight: 1 })
  }
  return {
    id: parsed.id.toLowerCase().replace(/^0x/, ''),
    packageId: normalizeHexId(parsed.packageId),
    threshold: parsed.threshold,
    servers,
  }
}

/** True if `info` was sealed to exactly these servers (same weights) at this threshold. */
export function sealedUnderServers(
  info: CiphertextInfo,
  servers: readonly Pick<KeyServerConfig, 'objectId' | 'weight'>[],
  threshold: number,
): boolean {
  // The same threshold and the same number of distinct servers, then every configured server present with the same weight.
  if (info.threshold !== threshold || info.servers.length !== servers.length) return false
  return servers.every((s) =>
    info.servers.some((h) => h.objectId === normalizeHexId(s.objectId) && h.weight === (s.weight ?? 1)),
  )
}
