// The SealedManifest is the interchange format between encrypt and decrypt (CLAUDE.md invariant).
// This guard is the single place the shape is validated, so every consumer (sealed-storage-ui and any other
// app) rejects malformed manifests the same way rather than each re-implementing an ad-hoc check.

//
// Role: the manifest travels outside this package (a file, a link, a database), so it is untrusted when it comes back. This parser is the one gate: it returns
// only the known fields, in the right types, or throws `SealedManifestError` with a clear reason. Main exports: `parseSealedManifest`, `SealedManifestError`.
// Tested in `tests/manifest.test.ts`.
import type { PolicyRegistry } from './registry.js'
import type { SealedManifest } from './types.js'

/** Thrown when a value cannot be parsed as a `SealedManifest`. */
export class SealedManifestError extends Error {
  /** @param message - what is wrong; the class adds the "invalid sealed manifest" prefix and sets `name` so callers can test for it. */
  constructor(message: string) {
    super(`invalid sealed manifest: ${message}`)
    this.name = 'SealedManifestError'
  }
}

/** The string at `key`, which must be non-empty. @throws {SealedManifestError} otherwise. */
function requireNonEmptyString(o: Record<string, unknown>, key: string): string {
  const v = o[key]
  if (typeof v !== 'string' || v.length === 0) {
    throw new SealedManifestError(`\`${key}\` must be a non-empty string`)
  }
  return v
}

/** The Seal identity at `id`: even-length hex, no `0x` (it is persisted verbatim and decoded with `hexToBytes`). @throws {SealedManifestError} otherwise. */
function requireIdentityHex(o: Record<string, unknown>): string {
  const id = requireNonEmptyString(o, 'id')
  if (!/^(?:[0-9a-fA-F]{2})+$/.test(id)) {
    throw new SealedManifestError('`id` must be even-length hex (the Seal identity, without 0x)')
  }
  return id
}

/**
 * Parse and validate an untrusted value as a {@link SealedManifest}. Accepts either a JSON string
 * or an already-parsed object. Throws {@link SealedManifestError} on any malformed input — a
 * missing/empty required field (`policyType`, `id`, `blobId`, `network`), a non-object `params`,
 * or a non-string `label`. On success the returned object contains only the known manifest fields.
 *
 * `id` must be even-length hex (the Seal identity, persisted verbatim). With a `registry`, `policyType` must be
 * registered there and the provider's `parseParams` (when it has one) validates and narrows `params`, so a
 * malformed manifest fails here with a clear error instead of at PTB build time.
 *
 * This does NOT check that `network` matches the app's current network — that is an
 * application-level policy the caller enforces after parsing (see sealed-storage-ui).
 */
export function parseSealedManifest(raw: unknown, registry?: PolicyRegistry): SealedManifest {
  // A string is JSON text to parse; anything else is taken as already parsed.
  let value: unknown = raw
  if (typeof raw === 'string') {
    try {
      value = JSON.parse(raw)
    } catch {
      throw new SealedManifestError('not valid JSON')
    }
  }
  // A manifest is an object: not null, not a number, not an array.
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new SealedManifestError('not an object')
  }
  const o = value as Record<string, unknown>

  // The four required fields; only these are copied, so an extra key in the input is dropped, never passed along.
  const manifest: SealedManifest = {
    policyType: requireNonEmptyString(o, 'policyType'),
    id: requireIdentityHex(o),
    blobId: requireNonEmptyString(o, 'blobId'),
    network: requireNonEmptyString(o, 'network'),
  }

  // Optional fields: absent is fine, present must have the right type.
  if (o.params !== undefined) {
    if (!o.params || typeof o.params !== 'object' || Array.isArray(o.params)) {
      throw new SealedManifestError('`params` must be an object when present')
    }
    manifest.params = o.params as Record<string, unknown>
  }
  if (o.label !== undefined) {
    if (typeof o.label !== 'string') {
      throw new SealedManifestError('`label` must be a string when present')
    }
    manifest.label = o.label
  }

  // With a registry the policy type must be known, and its provider may validate the parameters too.
  if (registry) {
    if (!registry.has(manifest.policyType)) {
      throw new SealedManifestError(`unknown policy type "${manifest.policyType}"`)
    }
    const provider = registry.get(manifest.policyType)
    if (provider.parseParams) {
      // Surface a provider's validation error as a manifest error, so a caller handles one type of failure.
      try {
        manifest.params = provider.parseParams(manifest.params) as unknown as Record<string, unknown>
      } catch (e) {
        throw new SealedManifestError(e instanceof Error ? e.message : String(e))
      }
    }
  }

  return manifest
}
