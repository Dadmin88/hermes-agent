import type { BackendCapabilities, ModeAvailability } from './backends'
import { connectSavedRemote, ensureLocal, prepareLocal } from './backends'
import type { FirstRunSetupDecision } from './first-run-setup-gate'

export interface PrimaryBackendStartupOptions<Backend, RuntimeBackend, Remote, Connection>
  extends BackendCapabilities<Backend, RuntimeBackend, Remote, Connection> {
  waitForDecision: (backend: Backend) => Promise<FirstRunSetupDecision>
  /**
   * The registry's availability entry for the local mode. When local is
   * unavailable (a light artifact), a missing saved remote goes straight
   * to the first-run decision with `setupBackend` — a synthetic descriptor
   * that arms the remote-only setup surface. No local rung runs, and a
   * 'continue-local' decision is a wiring bug, not a fallback.
   */
  localMode: { availability: ModeAvailability; setupBackend: Backend }
}

export type PrimaryBackendStartupResult<RuntimeBackend, Connection> =
  { kind: 'local'; backend: RuntimeBackend } | { kind: 'remote'; connection: Connection }

export class FirstRunSetupResetError extends Error {
  readonly firstRunSetupReset = true

  constructor() {
    super('First-run setup was reset before a choice completed.')
    this.name = 'FirstRunSetupResetError'
  }
}

// Owns the production startHermes path up to the local process spawn,
// orchestrating the backend modules in ./backends. Keeping the full
// ordering here makes the first-run remote boundary executable in a test:
// an already-saved remote wins immediately; otherwise the local rungs
// (update exclusion, backend resolution) run before the setup gate, and a
// remote Apply re-resolves persisted config without ever entering
// ensureRuntime/bootstrap. When the artifact offers no local mode, every
// local rung is skipped.
export async function runPrimaryBackendStartup<Backend, RuntimeBackend, Remote, Connection>(
  options: PrimaryBackendStartupOptions<Backend, RuntimeBackend, Remote, Connection>
): Promise<PrimaryBackendStartupResult<RuntimeBackend, Connection>> {
  const { localMode, waitForDecision } = options

  const saved = await connectSavedRemote(options)

  if (saved) {
    return { kind: 'remote', connection: saved }
  }

  const connectAppliedRemote = async () => {
    const applied = await connectSavedRemote(options)

    if (!applied) {
      throw new Error('First-run remote setup completed without a saved remote backend.')
    }

    return { kind: 'remote' as const, connection: applied }
  }

  const localAvailability = localMode.availability

  if (localAvailability.available === false) {
    const decision = await waitForDecision(localMode.setupBackend)

    if (decision === 'reset') {
      throw new FirstRunSetupResetError()
    }

    if (decision !== 'remote-applied') {
      // The setup surface offers no local option when local is
      // unavailable, so any other decision means a wiring bug — never
      // fall through to local rungs this artifact does not have.
      throw new Error(
        `This build offers no local backend (${localAvailability.reason}); first-run decision was '${decision}'.`
      )
    }

    return connectAppliedRemote()
  }

  const backend = await prepareLocal(options)
  const decision = await waitForDecision(backend)

  if (decision === 'remote-applied') {
    return connectAppliedRemote()
  }

  if (decision === 'reset') {
    throw new FirstRunSetupResetError()
  }

  return { kind: 'local', backend: await ensureLocal(options, backend) }
}
