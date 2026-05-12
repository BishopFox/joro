// Pure functions for parsing and transforming raw HTTP requests

interface ParsedRequest {
  method: string
  path: string
  queryString: string
  httpVersion: string
  headers: [string, string][]
  body: string
  // Preserved from the input so that serialize round-trips don't flip CRLF↔LF.
  // CodeMirror normalizes to LF on every edit, so the editor will usually feed
  // us LF-only content even though the wire format is CRLF.
  lineSep: string
}

function findHeaderIndex(headers: [string, string][], name: string): number {
  const lower = name.toLowerCase()
  return headers.findIndex(([k]) => k.toLowerCase() === lower)
}

function getHeader(headers: [string, string][], name: string): string | undefined {
  const idx = findHeaderIndex(headers, name)
  return idx >= 0 ? headers[idx][1] : undefined
}

function setHeader(headers: [string, string][], name: string, value: string): [string, string][] {
  const idx = findHeaderIndex(headers, name)
  const result = [...headers]
  if (idx >= 0) {
    result[idx] = [result[idx][0], value]
  } else {
    // Insert after Host if present, otherwise at end
    const hostIdx = findHeaderIndex(result, 'Host')
    result.splice(hostIdx >= 0 ? hostIdx + 1 : result.length, 0, [name, value])
  }
  return result
}

function removeHeader(headers: [string, string][], name: string): [string, string][] {
  const lower = name.toLowerCase()
  return headers.filter(([k]) => k.toLowerCase() !== lower)
}

export function parseRawRequest(raw: string): ParsedRequest | null {
  try {
    const crlfIdx = raw.indexOf('\r\n\r\n')
    const lfIdx = raw.indexOf('\n\n')
    let headerEnd: number
    let bodySepLen: number
    let lineSep: string
    if (crlfIdx >= 0 && (lfIdx < 0 || crlfIdx <= lfIdx)) {
      headerEnd = crlfIdx
      bodySepLen = 4
      lineSep = '\r\n'
    } else if (lfIdx >= 0) {
      headerEnd = lfIdx
      bodySepLen = 2
      lineSep = '\n'
    } else {
      headerEnd = -1
      bodySepLen = 0
      lineSep = raw.includes('\r\n') ? '\r\n' : '\n'
    }

    const headerBlock = headerEnd >= 0 ? raw.slice(0, headerEnd) : raw
    const body = headerEnd >= 0 ? raw.slice(headerEnd + bodySepLen) : ''

    const lines = headerBlock.split(/\r?\n/)
    if (lines.length === 0) return null

    const requestLine = lines[0]
    const parts = requestLine.split(' ')
    if (parts.length < 3) return null

    const method = parts[0]
    const fullPath = parts[1]
    const httpVersion = parts.slice(2).join(' ')

    const qIdx = fullPath.indexOf('?')
    const path = qIdx >= 0 ? fullPath.slice(0, qIdx) : fullPath
    const queryString = qIdx >= 0 ? fullPath.slice(qIdx + 1) : ''

    const headers: [string, string][] = []
    for (let i = 1; i < lines.length; i++) {
      const colonIdx = lines[i].indexOf(':')
      if (colonIdx > 0) {
        headers.push([lines[i].slice(0, colonIdx), lines[i].slice(colonIdx + 1).trimStart()])
      }
    }

    return { method, path, queryString, httpVersion, headers, body, lineSep }
  } catch {
    return null
  }
}

export function serializeRequest(req: ParsedRequest): string {
  const fullPath = req.queryString ? `${req.path}?${req.queryString}` : req.path
  const lines = [`${req.method} ${fullPath} ${req.httpVersion}`]
  for (const [k, v] of req.headers) {
    lines.push(`${k}: ${v}`)
  }
  return lines.join(req.lineSep) + req.lineSep + req.lineSep + req.body
}

function parseUrlEncoded(body: string): [string, string][] {
  if (!body.trim()) return []
  return body.split('&').map((pair) => {
    const eqIdx = pair.indexOf('=')
    if (eqIdx < 0) return [decodeURIComponent(pair), ''] as [string, string]
    return [decodeURIComponent(pair.slice(0, eqIdx)), decodeURIComponent(pair.slice(eqIdx + 1))] as [string, string]
  })
}

function serializeUrlEncoded(params: [string, string][]): string {
  return params.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&')
}

function parseJsonBody(body: string): [string, string][] {
  const obj = JSON.parse(body)
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) return []
  return Object.entries(obj).map(([k, v]) => [k, typeof v === 'string' ? v : JSON.stringify(v)] as [string, string])
}

function serializeJsonBody(params: [string, string][]): string {
  const obj: Record<string, string> = {}
  for (const [k, v] of params) obj[k] = v
  return JSON.stringify(obj, null, 2)
}

function escapeXml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;')
}

function parseXmlBody(body: string): [string, string][] {
  const params: [string, string][] = []
  const re = /<(\w+)>([\s\S]*?)<\/\1>/g
  let match
  // Skip the root element wrapper and parse children
  const inner = body.replace(/^\s*<\w+>\s*/, '').replace(/\s*<\/\w+>\s*$/, '')
  while ((match = re.exec(inner)) !== null) {
    params.push([match[1], match[2]])
  }
  return params
}

function serializeXmlBody(params: [string, string][]): string {
  const lines = ['<root>']
  for (const [k, v] of params) {
    lines.push(`  <${k}>${escapeXml(v)}</${k}>`)
  }
  lines.push('</root>')
  return lines.join('\n')
}

type ContentFormat = 'urlencoded' | 'json' | 'xml'

function detectFormat(contentType: string | undefined): ContentFormat {
  if (!contentType) return 'urlencoded'
  const ct = contentType.toLowerCase()
  if (ct.includes('json')) return 'json'
  if (ct.includes('xml')) return 'xml'
  return 'urlencoded'
}

function parseBody(body: string, format: ContentFormat): [string, string][] {
  try {
    switch (format) {
      case 'json': return parseJsonBody(body)
      case 'xml': return parseXmlBody(body)
      default: return parseUrlEncoded(body)
    }
  } catch {
    return parseUrlEncoded(body)
  }
}

function serializeBody(params: [string, string][], format: ContentFormat): string {
  switch (format) {
    case 'json': return serializeJsonBody(params)
    case 'xml': return serializeXmlBody(params)
    default: return serializeUrlEncoded(params)
  }
}

const CONTENT_TYPE_MAP: Record<ContentFormat, string> = {
  urlencoded: 'application/x-www-form-urlencoded',
  json: 'application/json',
  xml: 'application/xml',
}

export function getMethod(raw: string): string {
  const spaceIdx = raw.indexOf(' ')
  return spaceIdx > 0 ? raw.slice(0, spaceIdx).toUpperCase() : 'GET'
}

export function getContentType(raw: string): ContentFormat {
  const parsed = parseRawRequest(raw)
  if (!parsed) return 'urlencoded'
  return detectFormat(getHeader(parsed.headers, 'Content-Type'))
}

export function changeRequestType(raw: string): string {
  const parsed = parseRawRequest(raw)
  if (!parsed) return raw

  try {
    if (parsed.method.toUpperCase() === 'GET') {
      // GET → POST: move query params to body
      const params = parseUrlEncoded(parsed.queryString)
      parsed.method = 'POST'
      parsed.body = params.length > 0 ? serializeUrlEncoded(params) : ''
      parsed.queryString = ''
      parsed.headers = setHeader(parsed.headers, 'Content-Type', 'application/x-www-form-urlencoded')
      parsed.headers = setHeader(parsed.headers, 'Content-Length', new TextEncoder().encode(parsed.body).length.toString())
    } else {
      // POST/other → GET: move body params to query string
      const format = detectFormat(getHeader(parsed.headers, 'Content-Type'))
      const params = parseBody(parsed.body, format)
      parsed.method = 'GET'
      parsed.queryString = params.length > 0 ? serializeUrlEncoded(params) : ''
      parsed.body = ''
      parsed.headers = removeHeader(parsed.headers, 'Content-Type')
      parsed.headers = removeHeader(parsed.headers, 'Content-Length')
    }
    return serializeRequest(parsed)
  } catch {
    return raw
  }
}

function shellEscape(s: string): string {
  return s.replace(/'/g, "'\\''")
}

export function rawToCurl(rawRequest: string, requestUrl: string): string {
  const parsed = parseRawRequest(rawRequest)
  if (!parsed) return `curl '${shellEscape(requestUrl)}'`

  const parts = [`curl -X ${parsed.method} '${shellEscape(requestUrl)}'`]

  for (const [name, value] of parsed.headers) {
    const lower = name.toLowerCase()
    if (lower === 'host' || lower === 'content-length') continue
    parts.push(`  -H '${shellEscape(name)}: ${shellEscape(value)}'`)
  }

  if (parsed.body) {
    parts.push(`  --data-raw '${shellEscape(parsed.body)}'`)
  }

  return parts.join(' \\\n')
}

// Recalculate the Content-Length header from the body byte size in a raw HTTP
// request. Tolerant of both CRLF (\r\n\r\n) and LF (\n\n) header/body
// boundaries — CodeMirror emits LF after any edit — and preserves whichever
// style the input uses so that feeding the result back into the editor does
// not ping-pong line endings on every keystroke.
export function updateContentLengthInRaw(raw: string): string {
  const crlfIdx = raw.indexOf('\r\n\r\n')
  const lfIdx = raw.indexOf('\n\n')
  let headerEnd: number
  let bodySep: string
  let lineSep: string
  if (crlfIdx >= 0 && (lfIdx < 0 || crlfIdx <= lfIdx)) {
    headerEnd = crlfIdx
    bodySep = '\r\n\r\n'
    lineSep = '\r\n'
  } else if (lfIdx >= 0) {
    headerEnd = lfIdx
    bodySep = '\n\n'
    lineSep = '\n'
  } else {
    return raw
  }

  const headers = raw.slice(0, headerEnd)
  const body = raw.slice(headerEnd + bodySep.length)
  const bodyLen = new TextEncoder().encode(body).length

  const lines = headers.split(/\r?\n/)
  let found = false
  const updated = lines.map((line) => {
    if (/^content-length:/i.test(line)) {
      found = true
      return `Content-Length: ${bodyLen}`
    }
    return line
  })
  if (!found) {
    if (bodyLen === 0) return raw
    updated.push(`Content-Length: ${bodyLen}`)
  }

  return updated.join(lineSep) + bodySep + body
}

export function changeContentType(raw: string, target: ContentFormat): string {
  const parsed = parseRawRequest(raw)
  if (!parsed) return raw

  try {
    const currentFormat = detectFormat(getHeader(parsed.headers, 'Content-Type'))
    const params = parseBody(parsed.body, currentFormat)
    parsed.body = params.length > 0 ? serializeBody(params, target) : ''
    parsed.headers = setHeader(parsed.headers, 'Content-Type', CONTENT_TYPE_MAP[target])
    parsed.headers = setHeader(parsed.headers, 'Content-Length', new TextEncoder().encode(parsed.body).length.toString())
    return serializeRequest(parsed)
  } catch {
    return raw
  }
}
