import { ShieldAlert } from 'lucide-react'
import type { EchoSink, EchoTransform } from '../../lib/echoTypes'
import { CONTEXT_LABELS, TRANSFORM_LABELS } from '../../lib/echoTypes'

/**
 * Tone maps a transform to how much of the value reached the page intact. It is
 * a rendering choice only: whether a reflection can actually escape its context
 * is the server's verdict, carried on `breakout`.
 */
function transformTone(t: EchoTransform): string {
  switch (t) {
    case 'identity':
      return 'text-semantic-warning'
    case 'base64':
      return 'text-semantic-special'
    default:
      return 'text-semantic-info'
  }
}

export function EchoSinkPill({ sink }: { sink: EchoSink }) {
  const ctx =
    sink.context === 'attr_value' && sink.attr
      ? `${sink.attr}=`
      : sink.context === 'script' && sink.jsContext && sink.jsContext !== 'code'
        ? `script ${sink.jsContext.replace('_', ' ')}`
        : (CONTEXT_LABELS[sink.context] ?? sink.context)

  return (
    <span
      className={`inline-flex items-center gap-1 rounded border border-border-subtle
        bg-surface-input px-1.5 py-0.5 text-[11px] leading-none ${
          sink.breakout ? 'border-semantic-error' : ''
        }`}
      title={`${TRANSFORM_LABELS[sink.transform] ?? sink.transform} in ${
        CONTEXT_LABELS[sink.context] ?? sink.context
      }${sink.attr ? ` (${sink.attr})` : ''} - seen ${sink.count}x`}
    >
      {sink.breakout && <ShieldAlert size={11} className="text-semantic-error" />}
      <span className={transformTone(sink.transform)}>
        {TRANSFORM_LABELS[sink.transform] ?? sink.transform}
      </span>
      <span className="text-content-muted">in</span>
      <span className="text-content-secondary">{ctx}</span>
      {sink.count > 1 && <span className="text-content-muted">x{sink.count}</span>}
    </span>
  )
}
