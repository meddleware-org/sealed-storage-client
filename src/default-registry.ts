/**
 * @file The registry with Meddleware's built-in policies already registered.
 *
 * Role: the one-call setup most apps use. Main export: `createDefaultRegistry`. Tested in `tests/registry.test.ts`.
 */
import { PolicyRegistry } from './registry.js'
import { createNftGateProvider } from './providers/nft-gate.js'
import { timeLockProvider } from './providers/timelock.js'

/**
 * A registry pre-loaded with the built-in providers (`nft-gate`, `time-lock`), registered as
 * peers in no particular priority. Consumers may `.register(...)` additional providers.
 *
 * @param accessGateOriginalId - The `access_gate` package's original id on the target network, to
 *   enable `suggest()` on the nft-gate provider. Omit (or pass `''`) for a registry with no chain
 *   suggestions.
 */
export function createDefaultRegistry(accessGateOriginalId = ''): PolicyRegistry {
  // `register` returns the registry, so the two built-ins chain; they are peers, neither has priority.
  return new PolicyRegistry()
    .register(createNftGateProvider(accessGateOriginalId))
    .register(timeLockProvider)
}
