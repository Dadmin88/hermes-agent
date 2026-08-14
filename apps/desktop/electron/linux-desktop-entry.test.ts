import assert from 'node:assert/strict'
import path from 'node:path'

import { test } from 'vitest'

import {
  type DesktopEntryFs,
  installLinuxDesktopEntry,
  type LinuxDesktopEntry,
  quoteDesktopExecEscape,
  resolveLauncherExec
} from './linux-desktop-entry'

// ── resolveLauncherExec ─────────────────────────────────────────────

test('AppImage env wins over execPath', () => {
  assert.equal(
    resolveLauncherExec({ APPIMAGE: '/apps/Hermes.AppImage' }, '/tmp/mount/hermes', true),
    '/apps/Hermes.AppImage'
  )
})

test('packaged non-AppImage uses execPath', () => {
  assert.equal(resolveLauncherExec({}, '/opt/hermes/hermes-desktop', true), '/opt/hermes/hermes-desktop')
})

test('dev runs resolve no launcher exec', () => {
  assert.equal(resolveLauncherExec({}, '/usr/bin/electron', false), null)
  assert.equal(resolveLauncherExec({ APPIMAGE: '  ' }, '/usr/bin/electron', false), null)
})

// ── quoteDesktopExecEscape ──────────────────────────────────────────

test('escapes the four reserved Exec characters only', () => {
  assert.equal(quoteDesktopExecEscape('/plain/path'), '/plain/path')
  assert.equal(quoteDesktopExecEscape('/a "b" $c `d` \\e'), '/a \\"b\\" \\$c \\`d\\` \\\\e')
})

// ── installLinuxDesktopEntry ────────────────────────────────────────

const ENTRY: LinuxDesktopEntry = {
  fileName: 'com.nousresearch.hermes.desktop',
  content: '[Desktop Entry]\nName=Hermes\nExec="@@EXEC@@" %U\nIcon=@@ICON@@\n'
}

interface FakeFsState {
  files: Map<string, string>
  dirs: string[]
}

function fakeFs(initial: Record<string, string> = {}): { fs: DesktopEntryFs; state: FakeFsState } {
  const state: FakeFsState = { files: new Map(Object.entries(initial)), dirs: [] }

  const fs: DesktopEntryFs = {
    mkdirSync: ((dir: string) => {
      state.dirs.push(dir)

      return undefined
    }) as DesktopEntryFs['mkdirSync'],
    readFileSync: ((file: string) => {
      const hit = state.files.get(file)

      if (hit === undefined) {
        throw new Error(`ENOENT: ${file}`)
      }

      return hit
    }) as DesktopEntryFs['readFileSync'],
    writeFileSync: ((file: string, content: string) => {
      state.files.set(file, content)
    }) as DesktopEntryFs['writeFileSync'],
    copyFileSync: ((src: string, dest: string) => {
      state.files.set(dest, `copy-of:${src}`)
    }) as DesktopEntryFs['copyFileSync'],
    existsSync: ((file: string) => state.files.has(file)) as DesktopEntryFs['existsSync']
  }

  return { fs, state }
}

test('writes entry + icon under XDG_DATA_HOME and substitutes placeholders', () => {
  const { fs, state } = fakeFs()
  const refreshed: string[] = []

  const result = installLinuxDesktopEntry({
    entry: ENTRY,
    execPath: '/apps/Hermes.AppImage',
    iconPath: '/mount/icon.png',
    env: { XDG_DATA_HOME: '/data' },
    fs,
    refreshMenuCache: dir => void refreshed.push(dir)
  })

  const entryPath = path.join('/data', 'applications', ENTRY.fileName)
  assert.deepEqual(result, { installed: true, entryPath, changed: true })
  const written = state.files.get(entryPath)
  assert.ok(written)
  assert.match(written, /Exec="\/apps\/Hermes\.AppImage" %U/)
  const iconDest = path.join('/data', 'icons', 'hicolor', '1024x1024', 'apps', 'com.nousresearch.hermes.png')
  assert.match(written, new RegExp(`Icon=${iconDest.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`))
  assert.equal(state.files.get(iconDest), 'copy-of:/mount/icon.png')
  assert.deepEqual(refreshed, [path.join('/data', 'applications')])
})

test('unchanged entry is not rewritten and skips the cache refresh', () => {
  const first = fakeFs()

  const write = installLinuxDesktopEntry({
    entry: ENTRY,
    execPath: '/apps/Hermes.AppImage',
    iconPath: null,
    env: { HOME: '/home/u' },
    fs: first.fs,
    refreshMenuCache: () => undefined
  })

  assert.equal(write.changed, true)

  const refreshed: string[] = []

  const again = installLinuxDesktopEntry({
    entry: ENTRY,
    execPath: '/apps/Hermes.AppImage',
    iconPath: null,
    env: { HOME: '/home/u' },
    fs: first.fs,
    refreshMenuCache: dir => void refreshed.push(dir)
  })

  assert.deepEqual(again, { installed: true, entryPath: write.entryPath, changed: false })
  assert.deepEqual(refreshed, [])
})

test('HOME fallback derives ~/.local/share; missing both is a no-op', () => {
  const { fs, state } = fakeFs()

  const result = installLinuxDesktopEntry({
    entry: ENTRY,
    execPath: '/x',
    iconPath: null,
    env: { HOME: '/home/u' },
    fs,
    refreshMenuCache: () => undefined
  })

  assert.equal(result.entryPath, path.join('/home/u', '.local', 'share', 'applications', ENTRY.fileName))
  assert.ok(state.files.has(result.entryPath as string))

  assert.deepEqual(installLinuxDesktopEntry({ entry: ENTRY, execPath: '/x', iconPath: null, env: {}, fs }), {
    installed: false,
    entryPath: null,
    changed: false
  })
})

test('a throwing filesystem never propagates', () => {
  const throwing: DesktopEntryFs = {
    mkdirSync: () => {
      throw new Error('read-only')
    },
    readFileSync: () => {
      throw new Error('read-only')
    },
    writeFileSync: () => {
      throw new Error('read-only')
    },
    copyFileSync: () => {
      throw new Error('read-only')
    },
    existsSync: () => false
  }

  assert.deepEqual(
    installLinuxDesktopEntry({ entry: ENTRY, execPath: '/x', iconPath: null, env: { HOME: '/h' }, fs: throwing }),
    { installed: false, entryPath: null, changed: false }
  )
})
