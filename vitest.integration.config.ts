import { defineConfig } from 'vitest/config'

// Live testnet tests (real key servers + fullnode); run with `npm run test:integration`.
//
// Most are read-only and need no key. The funded nft-gate round trip (`nft-gate.integration.test.ts`) is maintainer-run: it needs a funded testnet key in a file
// the maintainer names, which must never be a CI secret, so it skips itself in CI. CI runs this suite weekly (.github/workflows/live.yml), not on every push.
export default defineConfig({
  test: {
    environment: 'node',
    // Every file under tests/integration.
    include: ['tests/integration/**/*.test.ts'],
    // Two minutes per test: key servers and a public node are slow, and the round trip waits for them.
    testTimeout: 120_000,
  },
})
