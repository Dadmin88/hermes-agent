import assert from 'node:assert/strict'
import path from 'node:path'

import { test } from 'vitest'

import { classifyUpdateRoot, managedInstallRoots, unmanagedCheckoutMessage } from './update-root-policy'

const deps = (overrides = {}) => ({
  isGitCheckout: () => true,
  managedRoots: ['/home/u/.hermes/hermes-agent', '/usr/local/lib/hermes-agent'],
  canonicalize: (p: string) => p,
  ...overrides
})

test('managedInstallRoots lists the per-user and FHS roots', () => {
  assert.deepEqual(managedInstallRoots('/home/u/.hermes', path.posix.join), [
    '/home/u/.hermes/hermes-agent',
    '/usr/local/lib/hermes-agent'
  ])
  assert.deepEqual(managedInstallRoots('C:\\Users\\u\\.hermes', path.win32.join), [
    'C:\\Users\\u\\.hermes\\hermes-agent',
    '/usr/local/lib/hermes-agent'
  ])
})

test('a checkout at a managed root is managed', () => {
  assert.equal(classifyUpdateRoot('/home/u/.hermes/hermes-agent', deps()), 'managed-checkout')
  assert.equal(classifyUpdateRoot('/usr/local/lib/hermes-agent', deps()), 'managed-checkout')
})

test('a checkout anywhere else is unmanaged', () => {
  assert.equal(classifyUpdateRoot('/home/u/src/hermes-agent', deps()), 'unmanaged-checkout')
  assert.equal(classifyUpdateRoot('/home/u/src/hermes-agent/.worktrees/wt', deps()), 'unmanaged-checkout')
})

test('no .git means not a git checkout, wherever it sits', () => {
  const d = deps({ isGitCheckout: () => false })
  assert.equal(classifyUpdateRoot('/home/u/.hermes/hermes-agent', d), 'not-a-git-checkout')
  assert.equal(classifyUpdateRoot('/home/u/src/hermes-agent', d), 'not-a-git-checkout')
})

test('comparison happens on canonical paths (symlinked HERMES_HOME)', () => {
  const d = deps({
    canonicalize: (p: string) => p.replace('/home/u/dotfiles/hermes-home', '/home/u/.hermes')
  })

  assert.equal(classifyUpdateRoot('/home/u/dotfiles/hermes-home/hermes-agent', d), 'managed-checkout')
})

test('case-insensitive filesystems compare folded', () => {
  const d = deps({
    caseInsensitive: true,
    managedRoots: ['C:\\Users\\U\\.hermes\\hermes-agent']
  })

  assert.equal(classifyUpdateRoot('c:\\users\\u\\.hermes\\hermes-agent', d), 'managed-checkout')
  assert.equal(
    classifyUpdateRoot('c:\\users\\u\\.hermes\\hermes-agent', deps({ managedRoots: ['C:\\Users\\U\\.hermes\\hermes-agent'] })),
    'unmanaged-checkout'
  )
})

test('the refusal message names the root and points at git', () => {
  const message = unmanagedCheckoutMessage('/home/u/src/hermes-agent')
  assert.match(message, /\/home\/u\/src\/hermes-agent/)
  assert.match(message, /git pull/)
})
