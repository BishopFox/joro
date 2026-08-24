// Streamer mode's redaction primitives.
//
// This is a display control against screen capture and shoulder-surfing, not a
// security control. It applies at the render boundary and nowhere else: stores,
// API payloads, project files and Dead Drop exports always hold the real value.
// Redacting any earlier would be worse than useless — the proxy cannot send a
// request to a row of blocks, and a project save would persist the bars.
//
// Two mechanisms exist, split by whether a value is read-only or editable, not
// by which page it sits on:
//
//   - Read-only text goes through redactValue, so the real string never enters
//     the DOM. This is the only mechanism that reaches an SVG <text> label or a
//     title= tooltip, neither of which any stylesheet can paint over.
//   - An editable <input> keeps its real value and is painted over by the
//     .joro-redact-field rule in index.css. Substituting the string there would
//     corrupt the value on the next keystroke.
//
// The bar is a run of U+2588 rather than a styled empty span so that the length
// survives a copy or a DOM inspection, matching the length-preserving masking in
// internal/httptools/redact.go. Adjacent block glyphs leave hairline seams in the
// system monospace stack, so .joro-redacted paints a solid background behind the
// run; the glyphs carry the length, the background makes it read as one bar.
//
// Coverage is deliberately limited to infrastructure and application chrome.
// Captured traffic is NOT redacted: the host and URL columns in History, Site
// Map, Detect, Intercept, Manipulate and Fuzz, the raw request/response editors,
// the rendered-response iframe, and plugin tab UIs all keep real values.

export const BLOCK = '█'

const MIN_BAR = 3
const MAX_BAR = 18

/**
 * Sensitivity is the kind of value being hidden. Every kind currently bars the
 * same way; the parameter exists so a later coverage tier can treat kinds
 * differently — keeping a URL's path, say — without revisiting every call site.
 */
export type Sensitivity = 'host' | 'ip' | 'url' | 'path' | 'secret' | 'identity' | 'text'

/** bar returns a run of full-block glyphs sized to n, clamped at both ends. */
export function bar(n: number): string {
  return BLOCK.repeat(Math.min(MAX_BAR, Math.max(MIN_BAR, n)))
}

/**
 * redactValue replaces a value with a length-preserving bar. An empty string
 * stays empty, so a "none"/"—" placeholder is not mistaken for hidden data.
 */
export function redactValue(v: string, kind: Sensitivity = 'text'): string {
  void kind
  if (!v) return ''
  return bar(v.length)
}
