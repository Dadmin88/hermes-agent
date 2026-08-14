import assert from 'node:assert/strict'

import { test } from 'vitest'

import { applyAppUpdate, describeFeedCheck, shouldUseAppUpdater } from './app-updater'

// ── shouldUseAppUpdater ─────────────────────────────────────────────

test('app updater runs for packaged embedded builds', () => {
  assert.equal(shouldUseAppUpdater({ stampPayload: 'bundled', isPackaged: true }), true)
})

test('app updater runs for packaged light builds', () => {
  assert.equal(shouldUseAppUpdater({ stampPayload: 'light', isPackaged: true }), true)
})

test('a bootstrap build never uses the app updater', () => {
  assert.equal(shouldUseAppUpdater({ stampPayload: 'bootstrap', isPackaged: true }), false)
})

test('dev runs never use the app updater', () => {
  assert.equal(shouldUseAppUpdater({ stampPayload: 'bundled', isPackaged: false }), false)
  assert.equal(shouldUseAppUpdater({ stampPayload: 'light', isPackaged: false }), false)
})

// ── describeFeedCheck ───────────────────────────────────────────────

test('feed check reports an available update when versions differ', () => {
  const out = describeFeedCheck('0.17.0', { version: '0.18.0' })

  assert.equal(out.supported, true)
  assert.equal(out.mechanism, 'app-updater')
  assert.equal(out.channel, 'stable')
  assert.equal(out.currentVersion, '0.17.0')
  assert.equal(out.latestVersion, '0.18.0')
  assert.equal(out.latestTag, 'v0.18.0')
  assert.equal(out.updateAvailable, true)
  assert.ok(out.fetchedAt > 0)
})

test('feed check reports up to date when versions match', () => {
  const out = describeFeedCheck('0.17.0', { version: '0.17.0' })

  assert.equal(out.updateAvailable, false)
  assert.equal(out.latestVersion, '0.17.0')
})

test('feed check tolerates a missing update info payload', () => {
  const out = describeFeedCheck('0.17.0', null)

  assert.equal(out.updateAvailable, false)
  assert.equal(out.latestVersion, null)
})

// ── applyAppUpdate ──────────────────────────────────────────────────

function fakeUpdater(calls: string[], failDownload = false) {
  return {
    on: () => void 0,
    removeListener: () => void 0,
    downloadUpdate: async () => {
      calls.push('download')

      if (failDownload) {
        throw new Error('download failed')
      }
    },
    quitAndInstall: () => void calls.push('install')
  } as any
}

test('apply runs beforeInstall between the download and the install', async () => {
  const calls: string[] = []

  await applyAppUpdate(undefined, () => void calls.push('teardown'), fakeUpdater(calls))

  assert.deepEqual(calls, ['download', 'teardown', 'install'])
})

test('a failed download installs nothing and skips beforeInstall', async () => {
  const calls: string[] = []

  await assert.rejects(applyAppUpdate(undefined, () => void calls.push('teardown'), fakeUpdater(calls, true)))

  assert.deepEqual(calls, ['download'])
})
