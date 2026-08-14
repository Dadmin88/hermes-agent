// install-stamp.ts — the typed build-time install stamp.
//
// scripts/write_install_stamp.py writes build/install-stamp.json during
// `npm run build`.
// bundle-electron-main.mjs bakes that file into the
// production bundle by defining the __HERMES_INSTALL_STAMP__ global as
// the stamp.  The stamp is a constant of the artifact.
// It cannot be missing, stale, or edited after signing.
//
// Dev bundles and test runs define nothing; the typeof guard makes the
// stamp null there (a dev run has no artifact to be truthful about).

/**
 * The desktop artifact kind — which runtime story this artifact tells:
 *  - 'bootstrap': no runtime in the artifact; first launch bootstraps a
 *    local install (the default; also what non-desktop stamps carry).
 *  - 'bundled': the agent runtime ships inside the artifact resources.
 *  - 'light': no runtime at all; remote connections only.
 * Selected at build time by HERMES_DESKTOP_VARIANT (unset = bootstrap).
 */
export type ArtifactKind = 'bootstrap' | 'bundled' | 'light'

/** Mirrors the dict scripts/write_install_stamp.py::build_stamp returns. */
export interface InstallStamp {
  schemaVersion: number
  commit: string | null
  commitDate: number | null
  branch: string | null
  builtAt: string | null
  dirty: boolean
  /** Build provenance: where the stamp's facts came from. */
  source: 'build' | 'ci' | 'docker' | 'fallback' | 'git' | 'local' | 'nix' | 'unknown' | null
  /** The steward of a sealed tree ('desktop-app' | 'docker' | 'nix'), when packaged. */
  distribution: string | null
  baseVersion: string | null
  displayVersion: string | null
  distance: number | null
  payload: ArtifactKind
  /** The pinned release tag. Always set for 'bundled' and 'light', never for 'bootstrap'. */
  tag: string | null
}

declare const __HERMES_INSTALL_STAMP__: InstallStamp | undefined

/** The baked stamp of this artifact, or null on dev bundles. */
export const INSTALL_STAMP: Readonly<InstallStamp> | null =
  typeof __HERMES_INSTALL_STAMP__ === 'undefined' ? null : Object.freeze(__HERMES_INSTALL_STAMP__)
