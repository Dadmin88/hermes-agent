// linux-desktop-entry.ts — install the XDG launcher entry on Linux.
//
// The entry text is generated at BUILD time by
// scripts/gen-linux-desktop-entry.mjs (electron-builder's own
// LinuxTargetHelper, so the AppImage-internal entry and this one can never
// disagree) and baked into the bundle as the __HERMES_LINUX_DESKTOP_ENTRY__
// define — the same mechanism as the install stamp and product identity.
// Dev bundles bake nothing; the typeof guard yields null and the installer
// is a no-op.
//
// At runtime this module substitutes the @@EXEC@@ / @@ICON@@ placeholders
// with real paths and writes the entry + icon into XDG data dirs. The
// filename is variant-owned (com.nousresearch.hermes[-light].desktop), so
// Hermes and Hermes Light install side by side without clobbering each
// other. Nix builds never reach this code path (the store derivation ships
// the entry system-wide and the stamp says distribution 'nix').

import { execFile } from 'node:child_process'
import * as fsDefault from 'node:fs'
import * as path from 'node:path'

/** The baked entry: variant-named file + placeholder-bearing content. */
export interface LinuxDesktopEntry {
  fileName: string
  content: string
}

// Build-time define (see bundle-electron-main.mjs). Dev bundles never
// define the binding; the typeof guard below is the existence check.
declare const __HERMES_LINUX_DESKTOP_ENTRY__: LinuxDesktopEntry

/** The baked launcher entry of this artifact, or null on dev bundles. */
export const LINUX_DESKTOP_ENTRY: Readonly<LinuxDesktopEntry> | null =
  typeof __HERMES_LINUX_DESKTOP_ENTRY__ === 'undefined' ? null : Object.freeze(__HERMES_LINUX_DESKTOP_ENTRY__)

/**
 * Escape a substituted Exec path per the desktop entry spec's
 * reserved-character rule. The placeholder sits inside double quotes in the
 * generated entry, so only `"` `$` ` \ need escaping.
 */
export function quoteDesktopExecEscape(value: string): string {
  return value.replace(/["$`\\]/g, '\\$&')
}

/**
 * The command the launcher entry should run. AppImage runs must point at
 * the .AppImage file itself (process.execPath is a path inside the
 * extracted squashfs mount that dies with the process); other packaged
 * runs use the real executable. Dev runs return null — no artifact, no
 * launcher entry.
 */
export function resolveLauncherExec(env: NodeJS.ProcessEnv, execPath: string, isPackaged: boolean): string | null {
  const appImage = env.APPIMAGE

  if (appImage && appImage.trim().length > 0) {
    return appImage
  }

  return isPackaged ? execPath : null
}

/** Filesystem seam so vitest covers the installer without a Linux desktop. */
export interface DesktopEntryFs {
  mkdirSync: typeof fsDefault.mkdirSync
  readFileSync: typeof fsDefault.readFileSync
  writeFileSync: typeof fsDefault.writeFileSync
  copyFileSync: typeof fsDefault.copyFileSync
  existsSync: typeof fsDefault.existsSync
}

export interface InstallDesktopEntryOptions {
  entry: LinuxDesktopEntry
  /** Absolute launch command target (from resolveLauncherExec). */
  execPath: string
  /** Absolute source icon path, or null when the artifact carries none. */
  iconPath: string | null
  env: NodeJS.ProcessEnv
  fs?: DesktopEntryFs
  /** Menu-cache refresh runner; defaults to spawning update-desktop-database. */
  refreshMenuCache?: (applicationsDir: string) => void
}

export interface InstallDesktopEntryResult {
  installed: boolean
  entryPath: string | null
  changed: boolean
}

function xdgDataHome(env: NodeJS.ProcessEnv): string | null {
  const raw = env.XDG_DATA_HOME

  if (raw && raw.trim().length > 0) {
    return raw
  }

  const home = env.HOME

  if (home && home.trim().length > 0) {
    return path.join(home, '.local', 'share')
  }

  return null
}

function defaultRefreshMenuCache(applicationsDir: string): void {
  // Best-effort: a missing tool or a failure never surfaces. The entry is
  // valid without the cache; the cache only speeds up menu discovery.
  execFile('update-desktop-database', [applicationsDir], () => undefined)
}

/**
 * Write the launcher entry (and icon) into the user's XDG data dir.
 * Idempotent: an unchanged entry is not rewritten, so launches do not churn
 * the menu caches. Failures return installed:false — launcher plumbing must
 * never block a launch.
 */
export function installLinuxDesktopEntry(options: InstallDesktopEntryOptions): InstallDesktopEntryResult {
  const { entry, execPath, iconPath, env } = options
  const fs = options.fs ?? fsDefault
  const refresh = options.refreshMenuCache ?? defaultRefreshMenuCache

  const dataHome = xdgDataHome(env)

  if (!dataHome) {
    return { installed: false, entryPath: null, changed: false }
  }

  const applicationsDir = path.join(dataHome, 'applications')
  const entryPath = path.join(applicationsDir, entry.fileName)
  const iconBase = entry.fileName.replace(/\.desktop$/, '')

  try {
    let iconValue: string

    if (iconPath) {
      const iconDir = path.join(dataHome, 'icons', 'hicolor', '1024x1024', 'apps')
      const iconDest = path.join(iconDir, `${iconBase}.png`)
      fs.mkdirSync(iconDir, { recursive: true })
      fs.copyFileSync(iconPath, iconDest)
      iconValue = iconDest
    } else {
      // Themed name — resolves only if some other install shipped the icon,
      // and renders as a generic icon otherwise. Still better than a broken
      // absolute path.
      iconValue = iconBase
    }

    const content = entry.content.replace('@@EXEC@@', quoteDesktopExecEscape(execPath)).replace('@@ICON@@', iconValue)

    if (fs.existsSync(entryPath) && fs.readFileSync(entryPath, 'utf8') === content) {
      return { installed: true, entryPath, changed: false }
    }

    fs.mkdirSync(applicationsDir, { recursive: true })
    fs.writeFileSync(entryPath, content, { mode: 0o755 })
    refresh(applicationsDir)

    return { installed: true, entryPath, changed: true }
  } catch {
    return { installed: false, entryPath: null, changed: false }
  }
}
