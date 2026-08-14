// backends/index.ts — the registry. The ONE ordered list of backend
// modules; every consumer (startup orchestration, settings mode cards,
// first-run choice, connection save/apply guard) walks this instead of
// keeping its own mode literals.

import { cloudBackend } from './cloud'
import { localBackend } from './local'
import { remoteBackend } from './remote'
import { sshBackend } from './ssh'
import type { AvailabilityFacts, BackendModule, ConnectionMode, ModeAvailability } from './types'

export const DESKTOP_BACKENDS: readonly BackendModule[] = [localBackend, remoteBackend, cloudBackend, sshBackend]

/** Availability for every mode, derived once from the injected facts. */
export function resolveBackendAvailability(facts: AvailabilityFacts): ModeAvailability[] {
  return DESKTOP_BACKENDS.map(backend => backend.isAvailable(facts))
}

export function modeAvailability(list: ModeAvailability[], mode: ConnectionMode): ModeAvailability {
  return list.find(entry => entry.mode === mode) ?? { mode, available: true }
}

export { ensureLocal, prepareLocal } from './local'
export { connectSavedRemote } from './remote'
export { probeSshClient } from './ssh'
export type {
  AvailabilityFacts,
  BackendCapabilities,
  BackendModule,
  ConnectionMode,
  ModeAvailability,
  UnavailableReason
} from './types'
export { CONNECTION_MODES } from './types'
