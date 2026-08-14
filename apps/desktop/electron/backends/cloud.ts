// backends/cloud.ts — a discovered Hermes Cloud instance (Nous portal).
//
// Always offered; sign-in and org discovery are connect-time concerns.
// Cloud persists a remote-shaped block with its own provenance tag and
// connects through the same dial as remote (backends/remote.ts) — the
// difference is the setup surface and how the URL is discovered, not the
// connection mechanics.

import type { BackendModule, ModeAvailability } from './types'

export const cloudBackend: BackendModule = {
  mode: 'cloud',

  isAvailable(): ModeAvailability {
    return { mode: 'cloud', available: true }
  }
}
