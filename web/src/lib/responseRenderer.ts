import { formatBytes, hexDump, latin1ToBytes, looksBinary, bytesToHex } from './bytes'
import {
  aeadName,
  kdfName,
  kemName,
  ohttpKind,
  parseOhttpKeys,
  parseOhttpRequest,
  parseOhttpResponse,
} from './ohttp'

const PRE_FONT = 'font: 12px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;'
/** Wrapped, for prose-like text bodies. */
const PRE_OPEN_WRAP = `<pre style="white-space: pre-wrap; word-wrap: break-word; margin: 0; padding: 8px; ${PRE_FONT}">`
/** Unwrapped, so hex-dump columns stay aligned. */
const PRE_OPEN = `<pre style="margin: 0; padding: 8px; ${PRE_FONT}">`

/** Parse raw HTTP response into headers and body, extracting Content-Type. */
export function parseRawResponse(raw: string): { contentType: string; body: string } {
  let headerEnd = raw.indexOf('\r\n\r\n')
  let bodyStart = headerEnd >= 0 ? headerEnd + 4 : -1

  if (headerEnd < 0) {
    headerEnd = raw.indexOf('\n\n')
    bodyStart = headerEnd >= 0 ? headerEnd + 2 : -1
  }

  if (headerEnd < 0) return { contentType: 'text/plain', body: raw }

  const headerBlock = raw.substring(0, headerEnd)
  const body = raw.substring(bodyStart)

  const ctMatch = headerBlock.match(/^content-type:\s*([^\r\n]+)/im)
  const contentType = ctMatch ? ctMatch[1].trim() : 'text/plain'

  return { contentType, body }
}

/**
 * Summary rows for an OHTTP body, or null if this is not OHTTP (or the
 * envelope does not parse, in which case the hex dump stands alone).
 */
function ohttpSummary(mime: string, bytes: Uint8Array): { title: string; rows: string[][] } | null {
  const kind = ohttpKind(mime)
  if (!kind) return null

  if (kind === 'req') {
    const r = parseOhttpRequest(bytes)
    if (!r) return null
    return {
      title: 'OHTTP encapsulated request',
      rows: [
        ['Key ID', String(r.keyId)],
        ['KEM', kemName(r.kemId)],
        ['KDF', kdfName(r.kdfId)],
        ['AEAD', aeadName(r.aeadId)],
        ['enc', `${r.encLength} bytes`],
        ['Ciphertext', `${r.ciphertextLength} bytes — encrypted to the gateway, not readable here`],
      ],
    }
  }

  if (kind === 'res') {
    const r = parseOhttpResponse(bytes)
    if (!r) return null
    return {
      title: 'OHTTP encapsulated response',
      rows: [
        ['Body', `${r.totalLength} bytes`],
        ['Nonce', `leading max(Nn, Nk) bytes — ${r.nonceNote}`],
        ['Ciphertext', 'the remainder — encrypted to the gateway, not readable here'],
      ],
    }
  }

  const configs = parseOhttpKeys(bytes)
  if (!configs) return null
  const rows: string[][] = []
  configs.forEach((c, i) => {
    const label = configs.length > 1 ? `[${i}] ` : ''
    rows.push([`${label}Key ID`, String(c.keyId)])
    rows.push([`${label}KEM`, kemName(c.kemId)])
    rows.push([`${label}Public key`, `${c.publicKey.length} bytes  ${bytesToHex(c.publicKey)}`])
    c.suites.forEach((s) => rows.push([`${label}Suite`, `${kdfName(s.kdfId)} / ${aeadName(s.aeadId)}`]))
  })
  return { title: `OHTTP key configuration (${configs.length})`, rows }
}

/** Build the HTML document shown for a binary body: optional summary + hex. */
function binaryDocument(mime: string, bytes: Uint8Array): string {
  const summary = ohttpSummary(mime, bytes)
  const heading = summary?.title ?? 'Binary content'
  const width = summary ? Math.max(...summary.rows.map((r) => r[0].length)) : 0
  const detail = summary
    ? summary.rows.map(([k, v]) => `  ${escapeHtml(k.padEnd(width))}  ${escapeHtml(v)}`).join('\n')
    : ''

  const header =
    `${escapeHtml(heading)}\n` +
    `${escapeHtml(mime || 'unknown type')} · ${formatBytes(bytes.length)}\n` +
    (detail ? `\n${detail}\n` : '')

  return (
    '<!doctype html>' +
    '<meta name="color-scheme" content="light dark">' +
    PRE_OPEN +
    header +
    '\n' +
    escapeHtml(hexDump(bytes)) +
    '</pre>'
  )
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/** Create a blob URL from a raw HTTP response for rendering in an iframe. */
export function createResponseBlobUrl(raw: string, opts?: { prettyJson?: boolean }): string {
  const { contentType, body } = parseRawResponse(raw)
  const mimeOnly = contentType.split(';')[0].trim().toLowerCase()

  // Binary content types: convert from latin-1 string to proper bytes.
  if (mimeOnly.startsWith('image/') || mimeOnly === 'application/pdf' || mimeOnly.startsWith('audio/') || mimeOnly.startsWith('video/')) {
    const bytes = new Uint8Array(body.length)
    for (let i = 0; i < body.length; i++) bytes[i] = body.charCodeAt(i)
    return URL.createObjectURL(new Blob([bytes], { type: contentType }))
  }

  // HTML-like content: serve as-is so the browser parses it.
  if (mimeOnly === 'text/html' || mimeOnly === 'application/xhtml+xml') {
    return URL.createObjectURL(new Blob([body], { type: contentType }))
  }

  // Pretty-print JSON when requested. Falls back to raw body on parse error
  // (NDJSON, truncated payloads, etc.) so we never blank the iframe.
  let textBody = body
  if (opts?.prettyJson && /(^|[+/])json($|;)/i.test(mimeOnly)) {
    try {
      textBody = JSON.stringify(JSON.parse(body), null, 2)
    } catch {
      // not valid JSON — render as-is
    }
  }

  // OHTTP and other non-text bodies: a hex dump, plus whatever cleartext
  // envelope we can decode. Without this they reach the <pre> below as
  // latin-1 mojibake. OHTTP is checked by media type as well as by sniffing,
  // since a short ciphertext can look textual by chance.
  const bytes = latin1ToBytes(body)
  if (ohttpKind(mimeOnly) || looksBinary(bytes)) {
    return URL.createObjectURL(
      new Blob([binaryDocument(mimeOnly, bytes)], { type: 'text/html; charset=utf-8' }),
    )
  }

  // Everything else (JSON, plain text, XML, CSS, JS, ...): wrap in a minimal
  // HTML envelope that opts the document into `color-scheme: light dark`, so
  // the browser's preferred color scheme drives bg + text colors.
  const wrapped =
    '<!doctype html>' +
    '<meta name="color-scheme" content="light dark">' +
    PRE_OPEN_WRAP +
    escapeHtml(textBody) +
    '</pre>'
  return URL.createObjectURL(new Blob([wrapped], { type: 'text/html; charset=utf-8' }))
}
