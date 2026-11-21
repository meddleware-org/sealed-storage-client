// @meddleware/sealed-storage-client — modular Seal encryption for Sui.
//
// The on-chain half is the `sealed_storage` Move package (repos/sealed-storage-sui). Each policy is
// a provider here mirrored 1:1 with a Move module; the registry is the extension seam.
//
// This file is the public surface of the root entry: it only re-exports. `SealController` itself, with `describeCiphertext` and `sealedUnderServers`, is
// also available from the `./controller` subpath (the app loads it lazily, because it pulls in the Seal SDK), and the generated deployment ids from
// `./deployments`. Anything not exported from one of those is internal and may change without notice.

// Types first: they are erased at runtime, so a consumer importing only types pulls in no code.
export type {
  FieldSpec,
  PolicyDescriptor,
  SealPolicyProvider,
  SealPolicyTarget,
  SealedManifest,
  FieldSuggestion,
  SealSuggestClient,
  SuggestContext,
} from './types.js'
// The byte helpers (hex, object ids, u64, random bytes): exported whole because an app builds identities with them.
export * from './bytes.js'
// The manifest parser (the one gate for an untrusted manifest) and the registry that maps a policy type to its provider.
export { parseSealedManifest, SealedManifestError } from './manifest.js'
export { PolicyRegistry } from './registry.js'
export { createDefaultRegistry } from './default-registry.js'
// The controller (encrypt, decrypt, explain a refusal) and its configuration types.
export {
  SealController,
  assertApproveOnly,
  type SealControllerConfig,
  type KeyServerConfig,
  type SignPersonalMessage,
  type EncryptResult,
} from './controller.js'
// The two built-in policies.
export { createNftGateProvider, type NftGateParams } from './providers/nft-gate.js'
export { timeLockProvider, type TimeLockParams } from './providers/timelock.js'
// Sealed-content pointers: publish one, list a gate's, decode an event.
export {
  buildPublishSealedContentTransaction,
  buildPublishSealedContentTx,
  listSealedContent,
  parseSealedContentEvent,
  SEALED_CONTENT_LIMITS,
  sealedContentEventType,
  type ListSealedContentOptions,
  type SealEventsClient,
  type SealedContentInput,
  type SealedContentPage,
  type SealedContentPointer,
} from './sealed-content.js'
// Abort codes of the policy modules and the finders that name an abort from an error.
export {
  POLICY_ABORTS,
  classifyPolicyAbort,
  describePolicyAbort,
  parseMoveAbort,
  type ParsedMoveAbort,
  type PolicyAbort,
  type PolicyModule,
} from './aborts.js'
// Explaining a refusal: simulate the approve transaction as the requester and say why it would abort.
export {
  REASON_NOT_OWNER,
  explainApproveRefusal,
  refusalMessage,
  type RefusalClient,
  type RefusalExplanation,
} from './refusal.js'
// Which addresses to trust as authors of a gate's content, and the check that a gate is the one the policy links.
export { gateOperators } from './operators.js'
export { assertLinkedGate } from './gate-check.js'
// The key-server committees (hand-written data in `committees.ts`, also re-exported by the deployments subpath).
export {
  SEAL_COMMITTEES,
  SEAL_COMMITTEES_PENDING,
  committeeServerConfigs,
  sealCommittee,
  type SealCommittee,
  type SealCommitteeNetwork,
  type SealCommitteeServer,
} from './committees.js'
// Deployment ids are in the `@meddleware/sealed-storage-client/deployments` subpath.
