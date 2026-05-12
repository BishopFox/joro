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

  // Everything else (JSON, plain text, XML, CSS, JS, ...): wrap in a minimal
  // HTML envelope that opts the document into `color-scheme: light dark`, so
  // the browser's preferred color scheme drives bg + text colors.
  const wrapped =
    '<!doctype html>' +
    '<meta name="color-scheme" content="light dark">' +
    '<pre style="white-space: pre-wrap; word-wrap: break-word; margin: 0; padding: 8px; font: 12px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;">' +
    escapeHtml(textBody) +
    '</pre>'
  return URL.createObjectURL(new Blob([wrapped], { type: 'text/html; charset=utf-8' }))
}
