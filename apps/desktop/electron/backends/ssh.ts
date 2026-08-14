// backends/ssh.ts — a backend on another machine, reached over ssh.
//
// Availability = an ssh client exists to spawn. That is a machine fact,
// not an artifact fact: every artifact kind (including light) offers ssh
// when the client is present. Reaching or bootstrapping the remote host
// is connect-time work (ssh-connection.ts / ssh-bootstrap-coordinator.ts);
// once up, ssh connects through the shared remote dial.

import fs from 'node:fs'
import path from 'node:path'

import type { AvailabilityFacts, BackendModule, ModeAvailability } from './types'

export const sshBackend: BackendModule = {
  mode: 'ssh',

  isAvailable(facts: AvailabilityFacts): ModeAvailability {
    if (!facts.sshClientFound) {
      return { mode: 'ssh', available: false, reason: 'missing-ssh' }
    }

    return { mode: 'ssh', available: true }
  }
}

/**
 * Locate an ssh client. Windows ships OpenSSH under System32 (often absent
 * from GUI-app PATH); elsewhere scan PATH. Existence only — this is an
 * availability probe, not a version check.
 */
export function probeSshClient(
  platform: NodeJS.Platform = process.platform,
  env: NodeJS.ProcessEnv = process.env,
  exists: (p: string) => boolean = p => {
    try {
      return fs.existsSync(p)
    } catch {
      return false
    }
  }
): boolean {
  if (platform === 'win32') {
    const system32Ssh = path.join(env.SystemRoot || 'C:\\Windows', 'System32', 'OpenSSH', 'ssh.exe')

    if (exists(system32Ssh)) {
      return true
    }
  }

  const binary = platform === 'win32' ? 'ssh.exe' : 'ssh'

  return String(env.PATH || '')
    .split(path.delimiter)
    .filter(Boolean)
    .some(dir => exists(path.join(dir, binary)))
}
