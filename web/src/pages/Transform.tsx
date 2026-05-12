import { useState, useCallback, useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { copyText } from '../lib/clipboard'

type Encoding = 'url' | 'base64' | 'hex' | 'html'

// Inline MD5 implementation (Web Crypto doesn't support MD5)
function md5(input: string): string {
  const bytes = new TextEncoder().encode(input)
  const words = new Array<number>(Math.ceil((bytes.length + 9) / 64) * 16).fill(0)
  for (let i = 0; i < bytes.length; i++) words[i >> 2] |= bytes[i] << ((i % 4) * 8)
  words[bytes.length >> 2] |= 0x80 << ((bytes.length % 4) * 8)
  words[words.length - 2] = (bytes.length * 8) & 0xffffffff
  words[words.length - 1] = Math.floor((bytes.length * 8) / 0x100000000)

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476
  const S = [
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21,
  ]
  const K = Array.from({length: 64}, (_, i) =>
    Math.floor(0x100000000 * Math.abs(Math.sin(i + 1)))
  )

  for (let chunk = 0; chunk < words.length; chunk += 16) {
    let a = a0, b = b0, c = c0, d = d0
    for (let i = 0; i < 64; i++) {
      let f: number, g: number
      if (i < 16)      { f = (b & c) | (~b & d); g = i }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16 }
      else if (i < 48) { f = b ^ c ^ d;           g = (3 * i + 5) % 16 }
      else              { f = c ^ (b | ~d);        g = (7 * i) % 16 }
      const temp = d; d = c; c = b
      const x = (a + f + K[i] + (words[chunk + g] >>> 0)) >>> 0
      b = (b + ((x << S[i]) | (x >>> (32 - S[i])))) >>> 0
      a = temp
    }
    a0 = (a0 + a) >>> 0; b0 = (b0 + b) >>> 0; c0 = (c0 + c) >>> 0; d0 = (d0 + d) >>> 0
  }

  return [a0, b0, c0, d0].map(v =>
    Array.from({length: 4}, (_, i) => ((v >>> (i * 8)) & 0xff).toString(16).padStart(2, '0')).join('')
  ).join('')
}

async function sha(algo: string, input: string): Promise<string> {
  const buf = await crypto.subtle.digest(algo, new TextEncoder().encode(input))
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('')
}

interface HashResults {
  md5: string; sha1: string; sha256: string; sha512: string
}

function useHashes(input: string): HashResults {
  const [results, setResults] = useState<HashResults>({ md5: '', sha1: '', sha256: '', sha512: '' })

  useEffect(() => {
    if (!input) { setResults({ md5: '', sha1: '', sha256: '', sha512: '' }); return }
    let cancelled = false
    const m = md5(input)
    Promise.all([sha('SHA-1', input), sha('SHA-256', input), sha('SHA-512', input)]).then(
      ([s1, s256, s512]) => { if (!cancelled) setResults({ md5: m, sha1: s1, sha256: s256, sha512: s512 }) }
    )
    return () => { cancelled = true }
  }, [input])

  return results
}

interface Section {
  id: number
  text: string
  encoding: Encoding
}

const ENCODINGS: { value: Encoding; label: string }[] = [
  { value: 'url', label: 'URL' },
  { value: 'base64', label: 'Base64' },
  { value: 'hex', label: 'Hex' },
  { value: 'html', label: 'HTML Entities' },
]

const HTML_ENTITIES: Record<string, string> = {
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}

const HTML_DECODE_MAP: Record<string, string> = {
  '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'",
  '&#x27;': "'", '&apos;': "'",
}

function encode(text: string, encoding: Encoding): string {
  switch (encoding) {
    case 'url':
      return Array.from(new TextEncoder().encode(text))
        .map((b) => '%' + b.toString(16).toUpperCase().padStart(2, '0'))
        .join('')
    case 'base64':
      return btoa(
        new Uint8Array(new TextEncoder().encode(text)).reduce(
          (s, b) => s + String.fromCharCode(b), ''
        )
      )
    case 'hex':
      return Array.from(new TextEncoder().encode(text))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
    case 'html':
      return text.replace(/[&<>"']/g, (ch) => HTML_ENTITIES[ch] ?? ch)
  }
}

function decode(text: string, encoding: Encoding): string {
  switch (encoding) {
    case 'url':
      return decodeURIComponent(text)
    case 'base64': {
      const bin = atob(text)
      const bytes = new Uint8Array(bin.length)
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
      return new TextDecoder().decode(bytes)
    }
    case 'hex': {
      const bytes = new Uint8Array(
        (text.match(/.{1,2}/g) ?? []).map((b) => parseInt(b, 16))
      )
      return new TextDecoder().decode(bytes)
    }
    case 'html':
      return text.replace(
        /&(?:amp|lt|gt|quot|apos|#39|#x27);/g,
        (ent) => HTML_DECODE_MAP[ent] ?? ent
      )
  }
}

let nextId = 1

export default function Transform() {
  const location = useLocation()
  const navigate = useNavigate()

  const [sections, setSections] = useState<Section[]>([
    { id: nextId++, text: '', encoding: 'base64' },
    { id: nextId++, text: '', encoding: 'base64' },
  ])

  useEffect(() => {
    const state = location.state as { text?: string } | null
    if (state?.text) {
      setSections([
        { id: nextId++, text: state.text, encoding: 'base64' },
        { id: nextId++, text: '', encoding: 'base64' },
      ])
      navigate('/transform', { replace: true })
    }
  }, [location.state]) // eslint-disable-line

  const updateText = useCallback((id: number, text: string) => {
    setSections((prev) => {
      const idx = prev.findIndex((s) => s.id === id)
      if (idx === -1) return prev
      return prev.map((s) => (s.id === id ? { ...s, text } : s))
    })
  }, [])

  const updateEncoding = useCallback((id: number, encoding: Encoding) => {
    setSections((prev) =>
      prev.map((s) => (s.id === id ? { ...s, encoding } : s))
    )
  }, [])

  const transform = useCallback(
    (id: number, direction: 'encode' | 'decode') => {
      setSections((prev) => {
        const idx = prev.findIndex((s) => s.id === id)
        if (idx === -1) return prev
        const section = prev[idx]
        let result: string
        try {
          result =
            direction === 'encode'
              ? encode(section.text, section.encoding)
              : decode(section.text, section.encoding)
        } catch {
          result = `[Error: invalid ${section.encoding} input]`
        }
        // If there's a next section, populate it; otherwise append a new one
        if (idx + 1 < prev.length) {
          return prev.map((s, i) => (i === idx + 1 ? { ...s, text: result } : s))
        }
        const newSection: Section = {
          id: nextId++,
          text: result,
          encoding: 'base64',
        }
        return [...prev, newSection]
      })
    },
    []
  )

  const clear = useCallback(() => {
    setSections([
      { id: nextId++, text: '', encoding: 'base64' },
      { id: nextId++, text: '', encoding: 'base64' },
    ])
  }, [])

  const [hashInput, setHashInput] = useState('')
  const hashes = useHashes(hashInput)
  const [copied, setCopied] = useState<string | null>(null)

  const copyHash = useCallback((label: string, value: string) => {
    copyText(value)
    setCopied(label)
    setTimeout(() => setCopied(null), 1500)
  }, [])

  const copyAll = useCallback(() => {
    const text = `MD5:    ${hashes.md5}\nSHA-1:  ${hashes.sha1}\nSHA-256:${hashes.sha256}\nSHA-512:${hashes.sha512}`
    copyText(text)
    setCopied('all')
    setTimeout(() => setCopied(null), 1500)
  }, [hashes])

  const hashEntries: { label: string; key: keyof HashResults }[] = [
    { label: 'MD5', key: 'md5' },
    { label: 'SHA-1', key: 'sha1' },
    { label: 'SHA-256', key: 'sha256' },
    { label: 'SHA-512', key: 'sha512' },
  ]

  const [jwtInput, setJwtInput] = useState('')
  const [jwtHeader, setJwtHeader] = useState('')
  const [jwtPayload, setJwtPayload] = useState('')
  const [jwtError, setJwtError] = useState<string | null>(null)

  const base64urlDecode = (s: string): string => {
    let b = s.replace(/-/g, '+').replace(/_/g, '/')
    while (b.length % 4) b += '='
    return atob(b)
  }

  const base64urlEncode = (s: string): string =>
    btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

  const jwtDecode = useCallback(() => {
    setJwtError(null)
    try {
      const parts = jwtInput.trim().split('.')
      if (parts.length !== 3) throw new Error('JWT must have 3 dot-separated parts')
      const header = JSON.parse(base64urlDecode(parts[0]))
      const payload = JSON.parse(base64urlDecode(parts[1]))
      setJwtHeader(JSON.stringify(header, null, 2))
      setJwtPayload(JSON.stringify(payload, null, 2))
    } catch (e) {
      setJwtError(e instanceof Error ? e.message : 'Failed to decode JWT')
    }
  }, [jwtInput])

  const jwtEncode = useCallback(() => {
    setJwtError(null)
    try {
      const h = JSON.parse(jwtHeader)
      const p = JSON.parse(jwtPayload)
      const token = base64urlEncode(JSON.stringify(h)) + '.' + base64urlEncode(JSON.stringify(p)) + '.'
      setJwtInput(token)
    } catch (e) {
      setJwtError(e instanceof Error ? e.message : 'Invalid JSON in header or payload')
    }
  }, [jwtHeader, jwtPayload])

  const jwtAlgNone = useCallback(() => {
    setJwtError(null)
    try {
      const h = jwtHeader ? JSON.parse(jwtHeader) : {}
      const p = jwtPayload ? JSON.parse(jwtPayload) : {}
      h.alg = 'none'
      setJwtHeader(JSON.stringify(h, null, 2))
      const token = base64urlEncode(JSON.stringify(h)) + '.' + base64urlEncode(JSON.stringify(p)) + '.'
      setJwtInput(token)
    } catch (e) {
      setJwtError(e instanceof Error ? e.message : 'Invalid JSON in header or payload')
    }
  }, [jwtHeader, jwtPayload])

  return (
    <div className="flex gap-4 p-4 overflow-auto h-full">
      {/* Left: Transform */}
      <div className="flex-[3] min-w-0 flex flex-col">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold uppercase tracking-wide">
            Transform
          </h2>
          <button
            onClick={clear}
            className="px-3 py-1 rounded-sm text-xs text-content-secondary hover:text-content-primary hover:bg-surface-hover"
          >
            Clear
          </button>
        </div>

        <div className="flex flex-col flex-1 min-h-0">
          {sections.map((section, idx) => (
            <div key={section.id} className="flex flex-col flex-1 min-h-0">
              {idx > 0 && (
                <div className="flex items-center justify-center py-1 flex-shrink-0">
                  <div className="text-content-muted text-xs">&#9660;</div>
                </div>
              )}
              <div className="bg-surface-card border border-border rounded p-3 flex flex-col flex-1 min-h-0">
                <textarea
                  value={section.text}
                  onChange={(e) => updateText(section.id, e.target.value)}
                  placeholder={idx === 0 ? 'Enter text to transform...' : 'Result'}
                  rows={4}
                  className="w-full flex-1 min-h-[6rem] bg-surface-input text-content-primary text-sm font-mono rounded p-2 border border-border placeholder:text-content-muted resize-y focus:outline-none focus:border-accent-secondary"
                />
                <div className="flex items-center gap-2 mt-2">
                  <select
                    value={section.encoding}
                    onChange={(e) =>
                      updateEncoding(section.id, e.target.value as Encoding)
                    }
                    className="bg-surface-input text-content-primary text-xs rounded px-2 py-1.5 border border-border focus:outline-none focus:border-accent-secondary"
                  >
                    {ENCODINGS.map((enc) => (
                      <option key={enc.value} value={enc.value}>
                        {enc.label}
                      </option>
                    ))}
                  </select>
                  <button
                    onClick={() => transform(section.id, 'encode')}
                    disabled={!section.text}
                    className="px-3 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold disabled:opacity-50"
                  >
                    Encode
                  </button>
                  <button
                    onClick={() => transform(section.id, 'decode')}
                    disabled={!section.text}
                    className="px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold disabled:opacity-50"
                  >
                    Decode
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Right column */}
      <div className="flex-[2] min-w-0 flex flex-col gap-4">
        {/* Hash Generator */}
        <div>
          <h2 className="text-sm font-semibold uppercase tracking-wide mb-4">
            Hash Generator
          </h2>
          <div className="bg-surface-card border border-border rounded p-3">
            <textarea
              value={hashInput}
              onChange={(e) => setHashInput(e.target.value)}
              placeholder="Enter text to hash..."
              rows={4}
              className="w-full bg-surface-input text-content-primary text-sm font-mono rounded p-2 border border-border placeholder:text-content-muted resize-y focus:outline-none focus:border-accent-secondary"
            />
            {hashInput && (
              <div className="mt-3 space-y-2">
                {hashEntries.map(({ label, key }) => (
                  <div key={key}>
                    <div className="flex items-center justify-between mb-0.5">
                      <span className="text-xs text-content-secondary font-semibold">{label}</span>
                      <button
                        onClick={() => copyHash(key, hashes[key])}
                        className="text-xs text-accent-secondary hover:text-content-primary"
                      >
                        {copied === key ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                    <div
                      onClick={() => copyHash(key, hashes[key])}
                      className="bg-surface-input text-content-primary text-xs font-mono rounded p-1.5 border border-border break-all cursor-pointer hover:border-accent-secondary select-all"
                    >
                      {hashes[key] || '\u00a0'}
                    </div>
                  </div>
                ))}
                <button
                  onClick={copyAll}
                  className="w-full mt-1 px-3 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold"
                >
                  {copied === 'all' ? 'Copied All' : 'Copy All'}
                </button>
              </div>
            )}
          </div>
        </div>

        {/* JWT Tampering */}
        <div className="flex-1 min-h-0 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold uppercase tracking-wide">
              JWT
            </h2>
            <button
              onClick={() => { setJwtInput(''); setJwtHeader(''); setJwtPayload(''); setJwtError(null) }}
              className="px-3 py-1 rounded-sm text-xs text-content-secondary hover:text-content-primary hover:bg-surface-hover"
            >
              Clear
            </button>
          </div>
          <div className="bg-surface-card border border-border rounded p-3 flex-1 flex flex-col min-h-0">
            <textarea
              value={jwtInput}
              onChange={(e) => setJwtInput(e.target.value)}
              placeholder="Paste a JWT (eyJ...)..."
              rows={3}
              className="w-full bg-surface-input text-content-primary text-sm font-mono rounded p-2 border border-border placeholder:text-content-muted resize-y focus:outline-none focus:border-accent-secondary"
            />
            {jwtError && (
              <div className="text-semantic-error text-xs mt-1">{jwtError}</div>
            )}
            <label className="text-xs text-content-secondary font-semibold mt-3 mb-1">Header</label>
            <textarea
              value={jwtHeader}
              onChange={(e) => setJwtHeader(e.target.value)}
              placeholder='{"alg": "HS256", "typ": "JWT"}'
              rows={4}
              className="w-full bg-surface-input text-content-primary text-sm font-mono rounded p-2 border border-border placeholder:text-content-muted resize-y focus:outline-none focus:border-accent-secondary"
            />
            <label className="text-xs text-content-secondary font-semibold mt-3 mb-1">Payload</label>
            <textarea
              value={jwtPayload}
              onChange={(e) => setJwtPayload(e.target.value)}
              placeholder='{"sub": "1234567890", "name": "John Doe"}'
              rows={6}
              className="w-full bg-surface-input text-content-primary text-sm font-mono rounded p-2 border border-border placeholder:text-content-muted resize-y focus:outline-none focus:border-accent-secondary flex-1"
            />
            <div className="flex gap-2 mt-2">
              <button
                onClick={jwtDecode}
                disabled={!jwtInput.trim()}
                className="px-3 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold disabled:opacity-50"
              >
                Decode
              </button>
              <button
                onClick={jwtEncode}
                disabled={!jwtHeader.trim() && !jwtPayload.trim()}
                className="px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold disabled:opacity-50"
              >
                Encode
              </button>
              <button
                onClick={jwtAlgNone}
                disabled={!jwtPayload.trim()}
                className="px-3 py-1.5 rounded-sm bg-semantic-error-bg hover:bg-semantic-error-hover text-white text-xs font-semibold disabled:opacity-50"
              >
                alg:none
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
