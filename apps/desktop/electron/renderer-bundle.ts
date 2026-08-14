/**
 * Renderer bundle generation check.
 *
 * `index.html` and the hashed chunks under `dist/assets/` are ONE generation:
 * the entry chunk's filename changes on every build, and every `lazy()` route
 * resolves to a hashed filename baked into that generation's module graph. A
 * self-update that replaces the package while a copy of `dist` is locked (AV,
 * a still-running instance, an interrupted Windows replace) can leave the two
 * copies electron-builder ships — the one inside `app.asar` and the one in
 * `app.asar.unpacked`, both produced by `asarUnpack: dist/**` — from DIFFERENT
 * generations. The window then loads an `index.html` whose chunks are gone and
 * dies on the first lazy import:
 *
 *   Failed to fetch dynamically imported module:
 *   …/app.asar/dist/assets/shiki-block-COiz1pEN.js
 *
 * The app looks permanently broken (a restart reloads the same torn copy), yet
 * the OTHER copy is usually intact. This module makes that checkable: read the
 * modules an index.html declares and report which ones are missing next to it,
 * so the loader can prefer a complete generation over a torn one and only fall
 * back to a repair when BOTH copies are torn.
 *
 * Pure + injectable so it is testable without booting Electron. Note `fs` here
 * is Electron's asar-aware fs: paths inside `app.asar` read like real files.
 */

import fs from 'node:fs'
import path from 'node:path'

/** `<script type="module" src>` and `<link rel="modulepreload" href>` targets —
 *  the modules the browser fetches before any app code runs. Vite emits both
 *  with relative (`./assets/…`) URLs under `base: './'`. */
const MODULE_REF = /<(?:script[^>]*\ssrc|link[^>]*\shref)=["']([^"']+)["'][^>]*>/gi
const MODULE_TAG = /^<script[^>]*\btype=["']module["']|^<link[^>]*\brel=["']modulepreload["']/i

export function parseModuleAssetRefs(html: string): string[] {
  const refs: string[] = []

  for (const match of String(html ?? '').matchAll(MODULE_REF)) {
    const [tag, href] = match

    if (!MODULE_TAG.test(tag)) {
      continue
    }

    // Only same-bundle relative refs are ours to verify; a CDN/absolute URL is
    // not a generation-consistency question.
    if (/^[a-z]+:|^\/\//i.test(href)) {
      continue
    }

    refs.push(href.replace(/^\.\//, '').split(/[?#]/)[0])
  }

  return refs
}

export interface RendererBundleDeps {
  readFileSync?: (file: string, encoding: 'utf8') => string
  existsSync?: (file: string) => boolean
}

/**
 * The module files `indexPath` declares but that do not exist beside it.
 *
 * Empty array ⇒ this copy is a complete generation (or declares nothing we can
 * check — an unreadable/empty index is reported by the caller's own existence
 * check, not here). A non-empty array ⇒ torn: loading it produces the
 * "Failed to fetch dynamically imported module" crash.
 */
export function missingRendererAssets(indexPath: string, deps: RendererBundleDeps = {}): string[] {
  const readFileSync = deps.readFileSync ?? fs.readFileSync
  const existsSync = deps.existsSync ?? fs.existsSync
  const dir = path.dirname(indexPath)

  let html: string

  try {
    html = readFileSync(indexPath, 'utf8')
  } catch {
    // Unreadable index: the caller's fileExists gate owns that case.
    return []
  }

  return parseModuleAssetRefs(html).filter(ref => !existsSync(path.join(dir, ref)))
}
