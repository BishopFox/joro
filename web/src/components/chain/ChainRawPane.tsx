import { useCallback, useMemo, useRef } from 'react'
import { b64ToBytes, bytesToB64, formatBytes, HEX_DUMP_LIMIT } from '../../lib/bytes'

// A byte-addressed view of a recorded message.
//
// Not b64DecodeUTF8: it decodes with a non-fatal TextDecoder, so invalid bytes
// become U+FFFD and its atob fallback almost never runs — leaving a char-to-byte
// mapping that depends on the content. Right for prose, wrong for offsets.
//
// So the mode is picked once per message, from the bytes, and char index maps to
// byte index either way: fatal UTF-8 if it decodes, else latin-1 via atob, one
// char per byte. Spans then cut the byte array and each piece renders however
// reads best, because boundaries are never recovered from the rendered string.

/** RawMark is one highlighted byte range. */
export interface RawMark {
  start: number
  end: number
  id: string
  label: string
  tone: 'bound' | 'proposed' | 'conflict'
}

interface Props {
  /** base64 of the bytes being shown. */
  raw: string
  marks?: RawMark[]
  /** Dims every mark but this one — the inspector row under the pointer. */
  activeId?: string | null
  onSelect?: (sel: { start: number; end: number; valueB64: string }) => void
  onMarkClick?: (id: string) => void
  /** From the decode endpoint: "gzip", or "br (not decoded)". */
  decodedNote?: string
  maxBytes?: number
  className?: string
}

const toneClass: Record<RawMark['tone'], string> = {
  // Only semantic-error has a -bg token, so tone rides on the underline.
  bound: 'bg-surface-hover border-b-2 border-accent-secondary',
  proposed: 'bg-surface-hover border-b-2 border-semantic-warning',
  conflict: 'bg-surface-hover border-b-2 border-semantic-error text-semantic-error',
}

interface Piece {
  start: number
  text: string
  mark?: RawMark
}

export default function ChainRawPane({
  raw, marks = [], activeId, onSelect, onMarkClick, decodedNote, maxBytes = HEX_DUMP_LIMIT, className = '',
}: Props) {
  const preRef = useRef<HTMLPreElement>(null)

  const { bytes, utf8 } = useMemo(() => {
    const all = b64ToBytes(raw)
    let ok = true
    try {
      new TextDecoder('utf-8', { fatal: true }).decode(all)
    } catch {
      ok = false
    }
    return { bytes: all, utf8: ok }
  }, [raw])

  const render = useCallback(
    (b: Uint8Array) => {
      if (utf8) return new TextDecoder().decode(b)
      let s = ''
      for (const c of b) {
        s += c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) ? String.fromCharCode(c) : '·'
      }
      return s
    },
    [utf8],
  )

  // A step may hold a megabyte, so a mark past the cap pulls the window to
  // itself: "3 places" must never disagree with what is drawn.
  const { from, to, clipped } = useMemo(() => {
    if (bytes.length <= maxBytes) return { from: 0, to: bytes.length, clipped: false }
    const far = marks.filter((m) => m.start >= maxBytes)
    if (far.length === 0) return { from: 0, to: maxBytes, clipped: true }
    const first = Math.min(...far.map((m) => m.start))
    const start = Math.max(0, first - Math.floor(maxBytes / 4))
    return { from: start, to: Math.min(bytes.length, start + maxBytes), clipped: true }
  }, [bytes.length, maxBytes, marks])

  const pieces = useMemo(() => {
    const inWindow = marks
      .filter((m) => m.end > from && m.start < to && m.start < m.end)
      .sort((a, b) => a.start - b.start)
    const out: Piece[] = []
    let at = from
    for (const m of inWindow) {
      const s = Math.max(at, m.start)
      const e = Math.min(to, m.end)
      if (s >= e) continue
      if (s > at) out.push({ start: at, text: render(bytes.subarray(at, s)) })
      out.push({ start: s, text: render(bytes.subarray(s, e)), mark: m })
      at = e
    }
    if (at < to) out.push({ start: at, text: render(bytes.subarray(at, to)) })
    return out
  }, [marks, from, to, bytes, render])

  // Each piece carries its own byte start, so only the offset within it needs
  // converting — the one place the mode rule is applied.
  const charToByte = useCallback(
    (text: string, charOffset: number) =>
      utf8 ? new TextEncoder().encode(text.slice(0, charOffset)).length : charOffset,
    [utf8],
  )

  const handleSelect = useCallback(() => {
    if (!onSelect) return
    const sel = window.getSelection()
    if (!sel || sel.isCollapsed || !preRef.current) return
    const range = sel.getRangeAt(0)
    if (!preRef.current.contains(range.commonAncestorContainer)) return

    const off = (node: Node, offset: number): number | null => {
      let el: HTMLElement | null =
        node.nodeType === Node.TEXT_NODE ? node.parentElement : (node as HTMLElement)
      while (el && el.dataset.off === undefined) el = el.parentElement
      if (!el) return null
      return Number(el.dataset.off) + charToByte(el.textContent ?? '', offset)
    }
    const a = off(range.startContainer, range.startOffset)
    const b = off(range.endContainer, range.endOffset)
    if (a === null || b === null) return
    const [start, end] = a <= b ? [a, b] : [b, a]
    if (start >= end) return
    onSelect({ start, end, valueB64: bytesToB64(bytes.subarray(start, end)) })
  }, [onSelect, charToByte, bytes])

  return (
    <div className={`flex flex-col min-h-0 ${className}`}>
      {(decodedNote || clipped) && (
        <div className="text-[10px] text-content-muted px-1 pb-1 flex items-center gap-2 shrink-0">
          {decodedNote && <span>decoded: {decodedNote}</span>}
          {clipped && (
            <span>
              showing {formatBytes(to - from)} of {formatBytes(bytes.length)}
            </span>
          )}
          {!utf8 && <span>not UTF-8 - shown byte for byte</span>}
        </div>
      )}
      <pre
        ref={preRef}
        onMouseUp={handleSelect}
        className="flex-1 min-h-0 overflow-auto bg-surface-input border border-border rounded px-2 py-1 font-mono text-[11px] text-content-primary whitespace-pre-wrap break-all select-text"
      >
        {from > 0 && <span className="text-content-muted">… {formatBytes(from)} earlier …{'\n'}</span>}
        {pieces.map((p) =>
          p.mark ? (
            <span
              key={p.start}
              data-off={p.start}
              className={`${toneClass[p.mark.tone]} ${
                activeId && activeId !== p.mark.id ? 'opacity-40' : ''
              } cursor-pointer`}
              title={p.mark.label}
              onClick={() => onMarkClick?.(p.mark!.id)}
            >
              {p.text}
            </span>
          ) : (
            <span key={p.start} data-off={p.start}>
              {p.text}
            </span>
          ),
        )}
        {to < bytes.length && (
          <span className="text-content-muted">{'\n'}… {formatBytes(bytes.length - to)} more …</span>
        )}
      </pre>
    </div>
  )
}
