// The electron-builder configuration. It IS package.json's "build" field —
// this file exists only because one option cannot be expressed in JSON:
// mac.sign.ignore as a FUNCTION. osx-sign's walk selects files to sign with
// a generic binary-content probe, which flags plain binary resources (the
// payload CPython's idlelib GIFs, wheels, .zip) as signable. Signing those
// is wrong (non-Mach-O resources are covered by the bundle's CodeResources
// seal) and each bogus signing hits Apple's timestamp service — thousands
// of payload files flooded it until it refused ("The timestamp service is
// not available"). The function scopes signing to real Mach-O files.
"use strict"

const fs = require("node:fs")

const build = require("./package.json").build

// The four magics that open a Mach-O or universal (fat) binary, in both
// byte orders: MH_MAGIC(_64) and FAT_MAGIC read big-endian at offset 0.
const MACHO_MAGICS = new Set([
  0xfeedface, // MH_MAGIC (32-bit)
  0xcefaedfe, // MH_CIGAM
  0xfeedfacf, // MH_MAGIC_64
  0xcffaedfe, // MH_CIGAM_64
  0xcafebabe, // FAT_MAGIC (universal)
  0xbebafeca, // FAT_CIGAM
])

function isMachO(file) {
  const buf = Buffer.alloc(4)
  const fd = fs.openSync(file, "r")
  try {
    if (fs.readSync(fd, buf, 0, 4, 0) !== 4) {
      return false
    }
  } finally {
    fs.closeSync(fd)
  }
  return MACHO_MAGICS.has(buf.readUInt32BE(0))
}

module.exports = {
  ...build,
  mac: {
    ...build.mac,
    sign: {
      ...build.mac.sign,
      // true → skip. Directories pass through (the walk hands over .app and
      // .framework bundles, which codesign must see whole); every regular
      // file must prove it is Mach-O to be signed individually.
      ignore: (file) => {
        try {
          if (fs.lstatSync(file).isDirectory()) {
            return false
          }
          return !isMachO(file)
        } catch {
          // Unreadable/vanished: nothing to sign either way.
          return true
        }
      },
    },
  },
}
