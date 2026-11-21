// Vitest settings for the offline unit suite: `npm test`. The live suite (real key servers and a full node) has its own config (vitest.integration.config.ts).
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // Node, not jsdom: the package has no DOM code.
    environment: 'node',
    // The integration tests need a network (and some a funded key), so they are excluded from the default run.
    exclude: ['tests/integration/**', 'node_modules/**'],
    // Ten seconds per test: the suite is offline, so a test that needs longer is hung.
    testTimeout: 10_000,
  },
})
