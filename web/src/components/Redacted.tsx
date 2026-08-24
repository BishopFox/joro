import { redactValue, type Sensitivity } from '../lib/redact'
import { useStreamerStore } from '../stores/streamerStore'

interface RedactedProps {
  value: string | number | null | undefined
  kind?: Sensitivity
  /** Extra classes, applied whether or not the mode is on, so layout is stable. */
  className?: string
}

/**
 * Redacted renders a value as a black bar while streamer mode is on. Off, it is
 * the bare value with no wrapper, so an existing layout is untouched.
 *
 * SVG labels and title= attributes cannot use this — a stylesheet cannot paint
 * either one. Those call useRedact() and apply .joro-redacted-svg themselves.
 */
export function Redacted({ value, kind, className }: RedactedProps) {
  const on = useStreamerStore((s) => s.enabled)
  const text = value === null || value === undefined ? '' : String(value)
  if (!on) return <>{text}</>
  return <span className={`joro-redacted${className ? ` ${className}` : ''}`}>{redactValue(text, kind)}</span>
}
