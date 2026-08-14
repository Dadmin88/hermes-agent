// backends/local.ts — the local backend: spawn the agent on this machine.
//
// Availability is a constant of the artifact: a light artifact ships no
// runtime and cannot bootstrap one, so local is unavailable by
// construction — never by machine state. bootstrap and bundled artifacts
// always offer it.

import type { AvailabilityFacts, BackendCapabilities, BackendModule, ModeAvailability } from './types'

export const localBackend: BackendModule = {
  mode: 'local',

  isAvailable(facts: AvailabilityFacts): ModeAvailability {
    if (facts.artifactKind === 'light') {
      return { mode: 'local', available: false, reason: 'light-artifact' }
    }

    return { mode: 'local', available: true }
  }
}

/**
 * The local rungs that run BEFORE the first-run decision: park behind any
 * in-flight update, then resolve which local backend this artifact runs
 * (embedded payload / checkout / PATH). The returned descriptor carries
 * the `kind` the setup gate keys on ('bootstrap-needed' arms the choice).
 */
export async function prepareLocal<Backend, RuntimeBackend, Remote, Connection>(
  caps: BackendCapabilities<Backend, RuntimeBackend, Remote, Connection>
): Promise<Backend> {
  await caps.waitForLocalStart()
  await caps.bootProgress('backend.runtime', 'Resolving Hermes runtime', 28)

  return caps.prepareLocalBackend()
}

/** The post-decision rung: materialize the runtime (bootstrap if needed). */
export async function ensureLocal<Backend, RuntimeBackend, Remote, Connection>(
  caps: BackendCapabilities<Backend, RuntimeBackend, Remote, Connection>,
  backend: Backend
): Promise<RuntimeBackend> {
  return caps.ensureLocalRuntime(backend)
}
