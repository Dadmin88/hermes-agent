import assert from 'node:assert/strict'

import { test } from 'vitest'

import { describeFeedCheck, shouldUseAppUpdater } from './app-updater'

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
