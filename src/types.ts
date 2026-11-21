/**
 * @file Types for sealed-storage-client: the policy-provider contract, the manifest that links an encrypt to a decrypt, and the structural subset of a Sui client
 * the suggestions need.
 *
 * Role: the vocabulary every other module shares. Types only (no runtime code), apart from the import of `Transaction` for a type position.
 * A provider mirrors one `sealed_storage` Move module 1:1; the manifest is the portable pointer to one sealed blob.
 */
import type { Transaction } from '@mysten/sui/transactions'

/** A suggested value for a policy form field, sourced from chain state. */
export interface FieldSuggestion {
  /** What goes into the field (an object id, say). */
  value: string
  /** What the person sees in the picker. */
  label: string
}

/**
 * Minimal structural subset of a Sui gRPC core client needed by `suggest`.
 * Compatible with `SuiGrpcClient.core` from `@mysten/sui/grpc` without importing it directly.
 */
export interface SealSuggestClient {
  /** The SDK's unified core API. */
  core: {
    /** One page of the objects an address owns, optionally of one Move type, with their fields when `include.json` is set. */
    listOwnedObjects(options: {
      /** The owner's address. */
      owner: string
      /** Only objects of this Move type. */
      type?: string
      /** Where the previous page ended. */
      cursor?: string | null
      /** The page size. */
      limit?: number
      /** Ask for the objects' fields as JSON. */
      include?: { json?: boolean }
    }): Promise<{
      objects: Array<{ objectId: string; type?: string; json?: Record<string, unknown> | null }>
      hasNextPage: boolean
      cursor: string | null
    }>
    /** One object by id; rejects when it does not exist. */
    getObject(options: {
      /** The object's id. */
      objectId: string
      /** Ask for the object's fields as JSON. */
      include?: { json?: boolean }
    }): Promise<{ object: { objectId: string; type?: string; json?: Record<string, unknown> | null } }>
  }
}

/** Context passed to a provider's `suggest` method. */
export interface SuggestContext {
  /** The connected wallet address. */
  account: string
  /** Sui gRPC client (structural — any compatible client is accepted). */
  client: SealSuggestClient
}

/** A single input field a policy needs, used to render encrypt/decrypt forms generically. */
export interface FieldSpec {
  /** Key in the provider's params object. */
  name: string
  /** Human label for the form. */
  label: string
  /** Rendering/validation hint. */
  kind: 'text' | 'objectId' | 'datetime' | 'boolean'
  /** Whether the form refuses an empty value. */
  required: boolean
  /** One plain sentence under the field. */
  help?: string
}

/** UI-facing description of a policy: label + which fields encrypt vs decrypt need. */
export interface PolicyDescriptor {
  /** The provider's stable machine id (`nft-gate`, `time-lock`). */
  type: string
  /** The name shown in a policy picker. */
  label: string
  /** A plain-language explanation of what the policy does. */
  help: string
  /** Fields required to ENCRYPT under this policy (feed `buildId`). */
  encryptFields: FieldSpec[]
  /** Fields required to DECRYPT (feed `buildApprove`), in addition to the stored identity. */
  decryptFields: FieldSpec[]
}

/**
 * Where a `sealed_storage` call goes: the package's latest published-at (call target) and its shared
 * `PolicyConfig` (the version gate every `seal_approve*` and `sealed_content::publish` reads).
 * `sealPoliciesDeployment(network)` from `@meddleware/sealed-storage-client/deployments` supplies both.
 */
export interface SealPolicyTarget {
  /** The call target: the package's latest published-at id. */
  publishedAt: string
  /** The shared `PolicyConfig` object (the version gate). */
  policyConfigId: string
}

/**
 * A Seal access policy, mirrored 1:1 with a `sealed_storage` Move module. Providers are peers —
 * none is privileged. Adding a policy type is a new provider here + a new Move module; existing
 * code is untouched.
 */
export interface SealPolicyProvider<P = Record<string, unknown>> {
  /** Stable machine id, e.g. 'nft-gate' | 'time-lock'. */
  readonly type: string

  /**
   * Build the Seal identity bytes for a new ciphertext (namespace prefix + a random nonce).
   * Called once at encrypt time; the result is persisted in the manifest and reused verbatim
   * to decrypt.
   */
  buildId(params: P): Uint8Array

  /**
   * Append the `seal_approve*` move call to `tx`: the identity first, the shared `PolicyConfig`
   * second (version gate), then the policy's objects. Called at decrypt time to produce the PTB the
   * key servers dry-run.
   */
  buildApprove(tx: Transaction, target: SealPolicyTarget, idBytes: Uint8Array, params: P): void

  /** Form/rendering metadata (drives a generic, registry-driven UI). */
  describe(): PolicyDescriptor

  /**
   * Verify that `idBytes` (from the stored manifest or the ciphertext) has this policy's layout and
   * is consistent with `params` (supplied at decrypt time). Throw an `Error` on mismatch — a
   * corrupted manifest, or params for a different ciphertext. Required: `SealController.decrypt`
   * calls it before building the approve PTB, so every policy checks the identity it will be
   * approved against.
   */
  verifyId(idBytes: Uint8Array, params: P): void

  /**
   * Optional: validate the `params` of an untrusted manifest and return them narrowed (own, known keys only).
   * Throw an `Error` on a malformed value (a string where a boolean belongs, a bad object id). When present,
   * `parseSealedManifest(raw, registry)` calls it at import, so a bad manifest fails there instead of at build.
   */
  parseParams?(params: Record<string, unknown> | undefined): P

  /**
   * Optional: suggest values for form fields by querying chain state (e.g. objects owned by the
   * connected wallet). Returns a map of `fieldName → suggestions[]`. Only fields with non-empty
   * suggestion arrays need be included. The UI renders a picker for those fields and falls back
   * to a plain text input when no suggestions are available or the user opts out.
   */
  suggest?(context: SuggestContext): Promise<Partial<Record<string, FieldSuggestion[]>>>
}

/** Portable pointer to one sealed blob — the interchange format between encrypt and decrypt. */
export interface SealedManifest {
  /** Policy `type` used to seal this content. */
  policyType: string
  /** Seal identity (hex, no 0x) produced by `buildId` — required to decrypt. */
  id: string
  /** Storage pointer to the ciphertext (e.g. a Walrus blob id). */
  blobId: string
  /** Network the policy package + key servers live on. */
  network: string
  /** Non-secret policy params needed to rebuild the approve PTB (e.g. gateId). */
  params?: Record<string, unknown>
  /** Optional human label. */
  label?: string
}
