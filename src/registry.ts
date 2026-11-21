/**
 * @file The registry of Seal policy providers.
 *
 * Role: a UI renders its policy picker from `list()`, and `SealController` finds the provider of a manifest by `get(type)`. Adding a policy type is one
 * `register` call here plus a Move module; nothing else changes. Main export: `PolicyRegistry`. Tested in `tests/registry.test.ts`.
 */
import type { SealPolicyProvider } from './types.js'

/**
 * A registry of Seal policy providers. Neither ordering nor identity is privileged — the
 * consuming UI iterates `list()` to render its policy picker, so registering a new provider is
 * the only change needed to expose a new policy type.
 */
export class PolicyRegistry {
  /** Providers by type, in insertion order. Stored as `<never>` params: the registry does not know each provider's parameter type, callers do. */
  private readonly providers = new Map<string, SealPolicyProvider<never>>()

  /**
   * Register a provider. Returns `this` for chaining.
   *
   * A second provider for a type that is already registered is refused: replacing the built-in `nft-gate`
   * would silently change how identities are built. Pass `{ replace: true }` when that is the intent.
   */
  register<P>(provider: SealPolicyProvider<P>, options: { replace?: boolean } = {}): this {
    // Refuse a silent replacement: a different provider under the same type would change how identities are built, and old ciphertexts would no longer decrypt.
    if (this.providers.has(provider.type) && !options.replace) {
      throw new Error(
        `A Seal policy provider for "${provider.type}" is already registered; pass { replace: true } to replace it.`,
      )
    }
    // The cast erases the parameter type for storage; `get` restores it for the caller.
    this.providers.set(provider.type, provider as SealPolicyProvider<never>)
    return this
  }

  /** Look up a provider by type, throwing a clear error if it is not registered. */
  get<P = Record<string, unknown>>(type: string): SealPolicyProvider<P> {
    const provider = this.providers.get(type)
    if (!provider) {
      // Name what is registered, so a typo in a stored manifest is easy to spot.
      const known = [...this.providers.keys()].join(', ') || '(none)'
      throw new Error(`Unknown Seal policy type "${type}". Registered: ${known}.`)
    }
    return provider as unknown as SealPolicyProvider<P>
  }

  /** True if a provider is registered for `type`. */
  has(type: string): boolean {
    return this.providers.has(type)
  }

  /** All registered providers, in insertion order. */
  list(): SealPolicyProvider<never>[] {
    return [...this.providers.values()]
  }
}
