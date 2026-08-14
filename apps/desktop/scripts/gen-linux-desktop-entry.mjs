#!/usr/bin/env node
// gen-linux-desktop-entry.mjs — generate the Linux .desktop entry with the
// same electron-builder machinery that packages the AppImage.
//
// Exec and Icon are emitted as @@EXEC@@ / @@ICON@@ placeholders. Consumers
// substitute real paths at install time (nix wrapper substituteInPlace, the
// runtime installer). The Exec placeholder sits inside double quotes, so a
// substituted absolute path needs no re-quoting — it only has to escape the
// four reserved characters (" $ ` \), which quoteDesktopExecEscape below
// does for runtime callers (nix store paths never contain them).
//
// This runs only at build time (dev deps present), never at runtime.

import { mkdirSync, writeFileSync } from "node:fs"
import { createRequire } from "node:module"
import path from "node:path"
import { fileURLToPath } from "node:url"

import { LinuxTargetHelper } from "../../../node_modules/app-builder-lib/dist/targets/linux/LinuxTargetHelper.js"

const require = createRequire(import.meta.url)
const here = path.dirname(fileURLToPath(import.meta.url))

export const EXEC_PLACEHOLDER = "@@EXEC@@"
export const ICON_PLACEHOLDER = "@@ICON@@"

/**
 * Escape a path for substitution into the quoted Exec placeholder, per the
 * desktop entry spec's reserved-character rule for quoted Exec tokens.
 * @param {string} value
 * @returns {string}
 */
export function quoteDesktopExecEscape(value) {
  return value.replace(/["$`\\]/g, "\\$&")
}

/**
 * Build the stub packager LinuxTargetHelper reads. Only the fields
 * computeDesktopEntry() / getDesktopFileName() touch are provided; anything
 * else throwing is a signal the helper grew a new dependency.
 * @returns {{ helper: LinuxTargetHelper, config: import("app-builder-lib").Configuration }}
 */
function makeHelper() {
  /** @type {import("app-builder-lib").Configuration} */
  const config = require("../electron-builder.config.cjs")
  const packager = {
    appInfo: {
      productName: config.productName,
      description: config.linux?.synopsis ?? "",
    },
    executableName: config.executableName,
    metadata: { desktopName: config.extraMetadata?.desktopName },
    platformOptions: config.linux,
    config,
    fileAssociations: [],
  }
  // @ts-expect-error — deliberate stub; see the comment above.
  return { helper: new LinuxTargetHelper(packager), config }
}

/**
 * The variant's .desktop file name (appId-based, e.g.
 * "com.nousresearch.hermes-light.desktop").
 * @returns {string}
 */
export function desktopFileName() {
  const { helper } = makeHelper()
  return `${helper.getDesktopFileName()}.desktop`
}

/**
 * The variant's .desktop entry text with @@EXEC@@ / @@ICON@@ placeholders.
 * @returns {Promise<string>}
 */
export async function generateLinuxDesktopEntry() {
  const { helper, config } = makeHelper()
  return helper.computeDesktopEntry(
    config.linux ?? {},
    `"${EXEC_PLACEHOLDER}" %U`,
    { Icon: ICON_PLACEHOLDER },
  )
}

// ── CLI: --out-dir DIR ──────────────────────────────────────────────────────
// Writes DIR/<fileName> and prints the written path.
const isCli = process.argv[1] && path.resolve(process.argv[1]) === path.resolve(here, "gen-linux-desktop-entry.mjs")
if (isCli) {
  const outDirArg = process.argv.find((a) => a.startsWith("--out-dir="))?.slice("--out-dir=".length)
  if (!outDirArg) {
    console.error("usage: gen-linux-desktop-entry.mjs --out-dir=DIR")
    process.exit(1)
  }
  const file = path.join(outDirArg, desktopFileName())
  mkdirSync(outDirArg, { recursive: true })
  writeFileSync(file, await generateLinuxDesktopEntry())
  console.log(file)
}
