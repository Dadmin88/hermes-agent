// backends/types.ts — shared contracts for the desktop's backend modules.
//
// One file per backend lives beside this (local, remote, cloud, ssh); the
// registry in index.ts is the single list every consumer walks. The
// desktop AGENTS.md ladder rule applies: precedence and availability are
// data in one place, a missing capability is an availability fact with a
// reason (not a connect-time error), and every module is pure — the
// impure powers (spawning, boot progress UI, log ring, connection.json)
// arrive through BackendCapabilities, implemented in main.ts.

import type { ArtifactKind } from '../install-stamp'

/** Every connection mode the desktop can be asked to use. */
export const CONNECTION_MODES = ['local', 'remote', 'cloud', 'ssh'] as const

export type ConnectionMode = (typeof CONNECTION_MODES)[number]

/** The machine/artifact facts availability is derived from. */
export interface AvailabilityFacts {
  /** The artifact kind from the baked install stamp ('bootstrap' when unstamped/dev). */
  artifactKind: ArtifactKind
  /** Whether an ssh client executable was found on this machine. */
  sshClientFound: boolean
}

export type UnavailableReason = 'light-artifact' | 'missing-ssh'

export type ModeAvailability =
  | { mode: ConnectionMode; available: true }
  | { mode: ConnectionMode; available: false; reason: UnavailableReason }

/**
 * The impure powers a backend module may use, implemented by main.ts.
 * Modules never import electron or reach for module-global state; whatever
 * a start path needs (progress UI, logging, persisted-connection reads,
 * runtime resolution) comes in here.
 */
export interface BackendCapabilities<Backend, RuntimeBackend, Remote, Connection> {
  /** Advance the boot progress UI (phase id, human message, percent). */
  bootProgress: (phase: string, message: string, progress: number) => Promise<unknown> | unknown
  /** Append to the main-process log ring. */
  log: (line: string) => void
  /** Dial a resolved remote/cloud/ssh connection descriptor. */
  connectRemote: (remote: Remote) => Promise<Connection>
  /** Read the persisted remote-like connection for the primary profile, if any. */
  resolveRemote: () => Promise<Remote | null>
  /** Park until an in-flight app update releases the venv (local spawns only). */
  waitForLocalStart: () => Promise<unknown>
  /** Resolve the local backend descriptor (embedded payload / checkout / PATH). */
  prepareLocalBackend: () => Backend | Promise<Backend>
  /** Materialize the runtime for a prepared local backend (bootstrap if needed). */
  ensureLocalRuntime: (backend: Backend) => Promise<RuntimeBackend>
}

/**
 * A backend module: identity plus its pure availability rule. Start-path
 * hooks are added per module where the mode genuinely owns behavior
 * (local's pre/post-decision rungs, remote's saved-connection dial);
 * modes that share a path share the function instead of duplicating it.
 */
export interface BackendModule {
  mode: ConnectionMode
  isAvailable(facts: AvailabilityFacts): ModeAvailability
}
