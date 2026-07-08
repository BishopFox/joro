// Dead Drop file (.jord) serialization. A drop is a self-contained bundle of
// captured requests (raw bytes as base64) that can be shared as a file and
// opened by any Joro instance — no team server required.
//
// On export we gzip the JSON when the browser exposes CompressionStream,
// otherwise we fall back to plain JSON. On import we sniff the gzip magic
// bytes (0x1f 0x8b) and inflate, otherwise parse as plain JSON — mirroring the
// backend's gunzipIfNeeded (internal/api/handlers_configs.go).

export interface DropItem {
  host: string
  method: string
  url: string
  status: number
  note: string
  reqRaw: string // base64
  respRaw: string // base64
  truncated: boolean
}

export interface DropBundle {
  type: 'joro-deaddrop'
  version: number
  exportedAt: string
  author: string
  title: string
  note: string
  items: DropItem[]
}

export const DROP_TYPE = 'joro-deaddrop'
export const DROP_VERSION = 1

// exportDrop serializes a bundle to a Blob suitable for download as a .jord file.
export async function exportDrop(bundle: DropBundle): Promise<Blob> {
  const json = JSON.stringify(bundle)
  if (typeof CompressionStream === 'undefined') {
    return new Blob([json], { type: 'application/json' })
  }
  const stream = new Blob([json]).stream().pipeThrough(new CompressionStream('gzip'))
  const gzipped = await new Response(stream).arrayBuffer()
  return new Blob([gzipped], { type: 'application/gzip' })
}

// importDrop reads a .jord file and returns the parsed, validated bundle.
export async function importDrop(file: File): Promise<DropBundle> {
  const buf = new Uint8Array(await file.arrayBuffer())
  let json: string
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    if (typeof DecompressionStream === 'undefined') {
      throw new Error('This browser cannot decompress gzipped .jord files')
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
    throw new Error('Not a valid .jord file (invalid JSON)')
  }

  const b = parsed as Partial<DropBundle>
  if (!b || b.type !== DROP_TYPE || !Array.isArray(b.items)) {
    throw new Error('Not a valid Joro Dead Drop file')
  }
  return {
    type: DROP_TYPE,
    version: typeof b.version === 'number' ? b.version : DROP_VERSION,
    exportedAt: b.exportedAt ?? '',
    author: b.author ?? '',
    title: b.title ?? '',
    note: b.note ?? '',
    items: b.items as DropItem[],
  }
}
