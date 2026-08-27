// Automation package file (.jauto) serialization.
//
// A package is a manifest plus one bundled script, which is small enough that this is a
// client-side blob rather than a multipart upload: GET /automation/scripts/{id} and
// POST /automation/scripts already carry both halves, so a download and an upload need no
// new route. Mirrors lib/deaddrop.ts — gzip when CompressionStream exists, sniff the gzip
// magic bytes on the way back in, and validate field by field so a partial file cannot
// produce undefined at render time.

import type { AutomationManifest, Trigger } from './api'

export const PACKAGE_TYPE = 'joro-automation'
// 2 added `triggers`. A manifest names its triggers by reference, so a package that uses
// a custom one is no longer closed over — what it names has to travel with it or the
// package arrives on another machine pointing at a definition that does not exist.
export const PACKAGE_VERSION = 2

export interface AutomationBundle {
  type: typeof PACKAGE_TYPE
  version: number
  exportedAt: string
  manifest: AutomationManifest
  source: string
  /** Definitions for the custom triggers this manifest references. Absent in a v1 file,
   *  and absent in a v2 file whose automation only names built-in events. */
  triggers?: Trigger[]
}

/** exportPackage serializes a package to a Blob for download as a .jauto file. */
export async function exportPackage(bundle: AutomationBundle): Promise<Blob> {
  const json = JSON.stringify(bundle)
  if (typeof CompressionStream === 'undefined') {
    return new Blob([json], { type: 'application/json' })
  }
  const stream = new Blob([json]).stream().pipeThrough(new CompressionStream('gzip'))
  return new Blob([await new Response(stream).arrayBuffer()], { type: 'application/gzip' })
}

/** importPackage reads a .jauto file and returns the validated bundle. */
export async function importPackage(file: File): Promise<AutomationBundle> {
  const buf = new Uint8Array(await file.arrayBuffer())
  let json: string
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    if (typeof DecompressionStream === 'undefined') {
      throw new Error('This browser cannot decompress gzipped .jauto files')
    }
    const stream = new Blob([buf]).stream().pipeThrough(new DecompressionStream('gzip'))
    json = await new Response(stream).text()
  } else {
    json = new TextDecoder().decode(buf)
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    throw new Error('Not a valid .jauto file (invalid JSON)')
  }

  const b = parsed as Partial<AutomationBundle>
  if (!b || b.type !== PACKAGE_TYPE || !b.manifest || typeof b.source !== 'string') {
    throw new Error('Not a valid Joro automation package')
  }
  if (!b.manifest.id) {
    throw new Error('The package has no automation id')
  }
  // A file from a newer Joro is refused rather than read for the fields this build
  // recognizes. Silently dropping what it does not understand is how an automation gets
  // installed with a trigger it was never meant to run without.
  if (typeof b.version === 'number' && b.version > PACKAGE_VERSION) {
    throw new Error(
      `This package was written by a newer Joro (format ${b.version}, this build reads ${PACKAGE_VERSION})`
    )
  }
  // The server validates the manifest properly; this only guarantees the shape the
  // editor is about to render, so a missing optional field is filled rather than fatal.
  return {
    type: PACKAGE_TYPE,
    version: typeof b.version === 'number' ? b.version : PACKAGE_VERSION,
    exportedAt: b.exportedAt ?? '',
    manifest: {
      ...b.manifest,
      name: b.manifest.name || b.manifest.id,
      version: b.manifest.version || '0.0.0',
      sdkVersion: b.manifest.sdkVersion || '1',
      triggers: b.manifest.triggers ?? ['manual'],
    },
    source: b.source,
    ...(Array.isArray(b.triggers) && b.triggers.length > 0 && { triggers: b.triggers }),
  }
}

/** downloadPackage triggers a browser download of one automation.
 *
 *  `catalog` is the full trigger list; the custom ones this manifest references are
 *  resolved out of it and embedded. Passing the catalog rather than the definitions keeps
 *  every call site from having to work out which ones matter. */
export async function downloadPackage(
  manifest: AutomationManifest,
  source: string,
  catalog: Trigger[] = []
) {
  const refs = new Set(manifest.triggers ?? [])
  const triggers = catalog.filter((t) => !t.builtin && refs.has(t.id))
  const blob = await exportPackage({
    type: PACKAGE_TYPE,
    version: PACKAGE_VERSION,
    exportedAt: new Date().toISOString(),
    manifest,
    source,
    ...(triggers.length > 0 && { triggers }),
  })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${manifest.id}-${manifest.version}.jauto`
  a.click()
  URL.revokeObjectURL(url)
}

/** pickPackage opens a file chooser and returns the parsed bundle, or null if cancelled. */
export function pickPackage(): Promise<AutomationBundle | null> {
  return new Promise((resolve, reject) => {
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = '.jauto,application/gzip,application/json'
    input.onchange = async () => {
      const file = input.files?.[0]
      if (!file) {
        resolve(null)
        return
      }
      try {
        resolve(await importPackage(file))
      } catch (e) {
        reject(e)
      }
    }
    input.click()
  })
}
