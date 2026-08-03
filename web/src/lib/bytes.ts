/**
 * Byte-level helpers shared by the WebSocket manipulator and the response
 * renderer. Raw HTTP bytes reach the frontend as base64 and are usually
 * decoded with `atob`, which yields a latin-1 string (one char per byte) —
 * these convert between that representation and real bytes.
 */

/** Decode base64 to bytes. */
export function b64ToBytes(s: string): Uint8Array {
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** Encode bytes to base64. */
export function bytesToB64(b: Uint8Array): string {
  let s = ''
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i])
  return btoa(s)
}

/** Convert a latin-1 string (as returned by `atob`) to its bytes. */
export function latin1ToBytes(s: string): Uint8Array {
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff
  return out
}

/** Space-separated lowercase hex. */
export function bytesToHex(b: Uint8Array): string {
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join(' ')
}

/** Parse hex (whitespace and `0x` tolerated). Returns null if malformed. */
export function hexToBytes(hex: string): Uint8Array | null {
  const clean = hex.replace(/\s+|0x/g, '')
  if (clean.length % 2 !== 0) return null
  if (!/^[0-9a-fA-F]*$/.test(clean)) return null
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16)
  return out
}

/**
 * Heuristic for "this body is not text". Mirrors the server-side sniff in
 * internal/detect/parse.go: a NUL in the first KiB, else a high ratio of
 * non-printable bytes.
 */
export function looksBinary(b: Uint8Array): boolean {
  const head = b.subarray(0, 1024)
  if (head.length === 0) return false
  let odd = 0
  for (let i = 0; i < head.length; i++) {
    const c = head[i]
    if (c === 0) return true
    // Printable ASCII, plus tab/LF/CR/FF and anything >= 0x80 (possible UTF-8).
    if (c < 0x09 || (c > 0x0d && c < 0x20) || c === 0x7f) odd++
  }
  return odd / head.length > 0.1
}

/** Default cap on how many bytes hexDump renders, to keep the iframe responsive. */
export const HEX_DUMP_LIMIT = 64 * 1024

/**
 * Classic columnar hex dump: 8-digit offset, 16 bytes per row split into two
 * groups of 8, and an ASCII gutter. Output beyond `limit` is elided with a
 * footer rather than truncated silently.
 */
export function hexDump(b: Uint8Array, limit = HEX_DUMP_LIMIT): string {
  const shown = b.subarray(0, limit)
  const rows: string[] = []

  for (let off = 0; off < shown.length; off += 16) {
    const row = shown.subarray(off, off + 16)
    let hex = ''
    let ascii = ''
    for (let i = 0; i < 16; i++) {
      hex += i < row.length ? row[i].toString(16).padStart(2, '0') + ' ' : '   '
      if (i === 7) hex += ' '
      if (i < row.length) {
        const c = row[i]
        ascii += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : '.'
      }
    }
    rows.push(`${off.toString(16).padStart(8, '0')}  ${hex} |${ascii}|`)
  }

  if (b.length > shown.length) {
    rows.push('')
    rows.push(`... ${b.length - shown.length} more bytes not shown`)
  }
  return rows.join('\n')
}

/** Human-readable byte count, e.g. "1.4 KB". */
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} ${n === 1 ? 'byte' : 'bytes'}`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}
