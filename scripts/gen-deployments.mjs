#!/usr/bin/env node
// Generate src/deployments.ts from @meddleware/sealed-storage-sui's Published.toml and
// deployments.json: per network, published-at (call target: seal_approve*, publish), original-id
// (Seal identity namespace, event types) and the shared PolicyConfig (version gate).
// `--check` fails (exit 1) when the committed file differs from what the records produce.
//
// Why a generator: the ids are facts about a deployment, recorded once by the Move package that was published. Copying them by hand into this client
// is how a client ends up pointing at a superseded package, so the file is produced from the records and CI (`npm run check:deployments`) fails on drift.
//
// Usage:       node scripts/gen-deployments.mjs [--check]     (npm run gen:deployments / check:deployments)
// Reads:       the installed @meddleware/sealed-storage-sui (a devDependency, pinned exactly): Published.toml, deployments.json, package.json.
// Writes:      src/deployments.ts (without --check only). Nothing else, and nothing outside the repository.
// Exit codes:  0 written or matching; 1 drift under --check; a thrown error (non-zero) when a record is missing or malformed.
// Node built-ins only: this script adds no dependency.
import { readFileSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

// The repository root, found from this file so the script works from any directory.
const root = join(dirname(fileURLToPath(import.meta.url)), '..')
// The generated file.
const out = join(root, 'src/deployments.ts')
// Resolve the Move package the way Node would from this repository, so the installed (pinned) copy is the one read.
const require = createRequire(join(root, 'package.json'))
const pkgDir = dirname(require.resolve('@meddleware/sealed-storage-sui/package.json'))
// Its version goes into the generated header, so a reader sees which release the ids come from.
const { version } = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8'))

/** `[published.<network>]` tables of Published.toml → { network: { key: value } } (strings only). */
function parsePublished(toml) {
  // network name → its key/value pairs.
  const nets = {}
  // The table being read, or null outside a `[published.*]` table.
  let current = null
  for (const raw of toml.split('\n')) {
    const line = raw.trim()
    // A `[published.<network>]` header starts a new table.
    const table = /^\[published\.([A-Za-z0-9_-]+)\]$/.exec(line)
    if (table) {
      current = nets[table[1]] = {}
      continue
    }
    // Any other table (for example `[toolchain]`) is not ours: stop collecting until the next `[published.*]`.
    if (line.startsWith('[')) {
      current = null
      continue
    }
    // `key = "value"` inside a published table; comments, blank lines and non-string values are skipped.
    const kv = /^([A-Za-z0-9_-]+)\s*=\s*"([^"]*)"$/.exec(line)
    if (current && kv) current[kv[1]] = kv[2]
  }
  return nets
}

/** A Sui object or package id as the records spell it: `0x` and exactly 64 lower-case hex digits. */
const HEX_ID = /^0x[0-9a-f]{64}$/
/**
 * Check that `value` is a well-formed id and return it.
 * @param value - what the record holds
 * @param what - which record, for the error message
 * @throws {Error} if `value` is not a `0x` + 64-hex-digit string (a typo must stop the generator, not ship)
 */
function id(value, what) {
  if (typeof value !== 'string' || !HEX_ID.test(value)) {
    throw new Error(`${what}: expected a 0x-prefixed 64-hex-digit id, got ${JSON.stringify(value)}`)
  }
  return value
}

// The two records, read once. `published` maps a network to its package ids; `objects` maps it to the shared object ids.
const published = parsePublished(readFileSync(join(pkgDir, 'Published.toml'), 'utf8'))
const objects = JSON.parse(readFileSync(join(pkgDir, 'deployments.json'), 'utf8'))
// Sorted, so the output does not depend on the order of the records.
const networks = Object.keys(published).sort()
// An empty table would generate a client that knows no deployment; refuse that rather than publish it.
if (networks.length === 0) throw new Error('Published.toml has no [published.<network>] table')

// One object-literal entry per network, every id validated on the way.
const entries = networks.map((net) => {
  const p = published[net]
  // `original-id`: where the types are defined and what Seal key servers bind identities to (never changes across upgrades).
  const originalId = id(p['original-id'], `${net} original-id`)
  // `published-at`: the latest version, the target of `seal_approve*` and `publish`.
  const publishedAt = id(p['published-at'], `${net} published-at`)
  // The shared PolicyConfig (version gate), from the other record.
  const policyConfigId = id(objects[net]?.policyConfigId, `${net} policyConfigId (deployments.json)`)
  return [
    // A network name that is a valid identifier is written bare; any other is quoted.
    `  ${/^[A-Za-z_$][\w$]*$/.test(net) ? net : `'${net}'`}: {`,
    `    originalId: '${originalId}',`,
    `    publishedAt: '${publishedAt}',`,
    `    policyConfigId: '${policyConfigId}',`,
    `  },`,
  ].join('\n')
})

// The whole generated file. Its comments are written here, because a generated file is documented at its generator.
const source = `// Generated by scripts/gen-deployments.mjs from @meddleware/sealed-storage-sui@${version} — do not edit.
// Regenerate with \`npm run gen:deployments\` after bumping that package.
//
// Role: the one place this client learns which package and shared objects a network uses. A deployment that is not recorded here is an error, never a
// guess (see \`sealPoliciesDeployment\`). Exported through the \`@meddleware/sealed-storage-client/deployments\` subpath, which also re-exports the Seal committees.

/** One network's \`sealed_storage\` deployment. */
export interface SealPoliciesDeployment {
  /**
   * Package id the types and events are defined at (never changes across upgrades). Seal key
   * servers bind identities to it: encrypt under this id.
   */
  originalId: string
  /** Latest package version: the call target for \`seal_approve*\` and \`sealed_content::publish\`. */
  publishedAt: string
  /** The shared \`PolicyConfig\` (version gate) every \`seal_approve*\` and \`publish\` reads. */
  policyConfigId: string
}

/** Every recorded \`sealed_storage\` deployment, by network. */
export const SEAL_POLICIES_DEPLOYMENTS = {
${entries.join('\n')}
} as const satisfies Record<string, SealPoliciesDeployment>

/** The networks that have a recorded deployment (today: the keys of \`SEAL_POLICIES_DEPLOYMENTS\`). */
export type SealPoliciesNetwork = keyof typeof SEAL_POLICIES_DEPLOYMENTS

/**
 * The \`sealed_storage\` deployment on \`network\`.
 *
 * @throws {Error} if there is no deployment recorded for \`network\`.
 */
export function sealPoliciesDeployment(network: string): SealPoliciesDeployment {
  // \`Object.hasOwn\` so a name like \`constructor\` or \`__proto__\` is not found on the prototype chain.
  const deployment = Object.hasOwn(SEAL_POLICIES_DEPLOYMENTS, network) ? (SEAL_POLICIES_DEPLOYMENTS as Record<string, SealPoliciesDeployment>)[network] : undefined
  if (!deployment) throw new Error(\`no sealed_storage deployment recorded for \${network}\`)
  return deployment
}

// The Seal key-server committees live in ./committees.ts (hand-written data, one owner); re-exported so this subpath carries them.
export {
  SEAL_COMMITTEES,
  SEAL_COMMITTEES_PENDING,
  committeeServerConfigs,
  sealCommittee,
  type SealCommittee,
  type SealCommitteeNetwork,
  type SealCommitteeServer,
} from './committees.js'
`

// `--check`: compare, do not write (what CI runs).
if (process.argv.includes('--check')) {
  let current = ''
  try {
    current = readFileSync(out, 'utf8')
  } catch {
    // missing file is drift
  }
  // Any difference at all (a changed id, a version bump, a hand edit) is drift.
  if (current !== source) {
    console.error('src/deployments.ts is out of date with @meddleware/sealed-storage-sui — run `npm run gen:deployments`.')
    process.exit(1)
  }
  console.log(`src/deployments.ts matches @meddleware/sealed-storage-sui@${version}.`)
} else {
  // The default: write the file.
  writeFileSync(out, source)
  console.log(`Wrote src/deployments.ts from @meddleware/sealed-storage-sui@${version} (${networks.join(', ')}).`)
}
