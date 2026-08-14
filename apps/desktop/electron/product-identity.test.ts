// product-identity.cjs is the single derivation of the desktop product
// identity; electron/product-identity.ts re-exports it (dev/test) or the
// baked define (packaged). These tests hold the identity contract: the
// TS accessor resolves to the .cjs object, and the two variants disagree
// on every OS-visible marker (side-by-side installs must not collide).
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'

import { afterEach, beforeEach, test, vi } from 'vitest'

const require = createRequire(import.meta.url)

beforeEach(() => {
  vi.resetModules()
})

afterEach(() => {
  delete process.env.HERMES_DESKTOP_VARIANT
  vi.resetModules()
})

async function identityForVariant(variant: string | undefined) {
  if (variant === undefined) {
    delete process.env.HERMES_DESKTOP_VARIANT
  } else {
    process.env.HERMES_DESKTOP_VARIANT = variant
  }

  delete require.cache[require.resolve('../product-identity.cjs')]
  vi.resetModules()

  return (await import('./product-identity')).PRODUCT_IDENTITY
}

test('light identity is fully distinct from the full identity', async () => {
  const full = await identityForVariant(undefined)
  const light = await identityForVariant('light')

  assert.equal(light.light, true)

  // Every OS-visible identity marker must differ, or side-by-side
  // installs collide (userData dir, handler registration, updater feed).
  for(const prop of [...Object.keys(light), ...Object.keys(full)]) {
    assert.notEqual(light[prop], full[prop])
  }
})
