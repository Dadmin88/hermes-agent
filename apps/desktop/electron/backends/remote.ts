// backends/remote.ts — a user-owned remote gateway (URL + token or OAuth).
//
// Always offered: whether the URL answers is a connect-time question, not
// an availability fact. This module also owns the shared saved-connection
// dial that cloud and ssh reuse — all three persist a remote-shaped block
// and connect the same way; only their provenance and setup UI differ.

import type { BackendCapabilities, BackendModule, ModeAvailability } from './types'

export const remoteBackend: BackendModule = {
  mode: 'remote',

  isAvailable(): ModeAvailability {
    return { mode: 'remote', available: true }
  }
}

/**
 * Dial the persisted remote-like connection (remote, cloud, or ssh —
 * resolveRemote reads whichever block connection.json holds). Returns
 * null when nothing is saved; throws when a caller KNOWS one must exist
 * (post-Apply) — that variant lives in the orchestrator.
 */
export async function connectSavedRemote<Backend, RuntimeBackend, Remote, Connection>(
  caps: BackendCapabilities<Backend, RuntimeBackend, Remote, Connection>
): Promise<Connection | null> {
  const saved = await caps.resolveRemote()

  if (!saved) {
    return null
  }

  return caps.connectRemote(saved)
}
