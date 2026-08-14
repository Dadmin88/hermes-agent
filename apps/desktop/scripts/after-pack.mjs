/**
 * after-pack.mjs — electron-builder afterPack hook.
 *
 * Stamps the Hermes icon + identity onto the packed Windows Hermes.exe via
 * rcedit (delegated to set-exe-identity.mjs). This runs for EVERY packed build
 * — first install, `hermes desktop`, the installer's --update rebuild, and a
 * dev's manual `npm run pack` — so the branded exe can never silently revert
 * to the stock "Electron" icon/name (the bug when the stamp lived only in
 * install.ps1, which the update path doesn't use).
 *
 * Windows-only: rcedit edits PE resources, irrelevant on macOS/Linux where the
 * app identity comes from the bundle Info.plist / desktop entry. Best-effort:
 * a stamp failure must never fail an otherwise-good build (worst case is the
 * stock icon, not a broken app), so we log and resolve rather than throw.
 *
 * electron-builder passes a context with:
 *   - electronPlatformName: 'win32' | 'darwin' | 'linux'
 *   - appOutDir:            the unpacked app directory for this target
 *   - packager.appInfo.productFilename: the exe basename (e.g. 'Hermes')
 */

import path from 'node:path'

import { stampExeIdentity } from './set-exe-identity.mjs'
import { sanitizeTree } from './sanitize-pe-signatures.mjs'

export default async function afterPack(context) {
  if (context.electronPlatformName !== 'win32') {
    return
  }

  const productName = context.packager?.appInfo?.productFilename || 'Hermes'
  const exe = path.join(context.appOutDir, `${productName}.exe`)
  const desktopRoot = path.resolve(import.meta.dirname, '..')

  // Repair dangling PE certificate tables BEFORE electron-builder signs the
  // tree. A stripped-but-still-declared signature makes signtool reject the
  // file with 0x800700C1, and AppxSIP inspects every PE inside the MSIX, so
  // one bad payload DLL fails the whole package. Unlike the stamp below this
  // is NOT best-effort: shipping past it means shipping an unsignable bundle.
  // this is a hack until https://github.com/astral-sh/python-build-standalone/pull/1217 is merged.
  const { scanned, repaired } = sanitizeTree(context.appOutDir)
  console.log(`[after-pack] ${scanned} PEs scanned, ${repaired.length} dangling certificate tables cleared`)
  for (const file of repaired) {
    console.log(`  ${file}`)
  }

  try {
    await stampExeIdentity(exe, desktopRoot)
  } catch (err) {
    // Never fail the build over a cosmetic stamp.
    console.warn(`[after-pack] exe identity stamp failed (${err.message}); Hermes.exe keeps the stock Electron icon`)
  }
}
