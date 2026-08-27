import { useMemo } from 'react'
import { OP_HINT, OP_LABEL } from '../../lib/triggerGraph'
import type { TriggerFieldSpec, TriggerNode } from '../../lib/api'

/**
 * The field / operator / value controls for one condition.
 *
 * One component rather than two, because the canvas's inspector and the builder's rows ask
 * the same question and must not disagree about which operators a field takes. Both render
 * from the server's catalog, so neither can offer a pairing the server would refuse.
 *
 * The value control follows the field and the operator rather than always being a text
 * box: a closed set gets a dropdown, a number gets a number input, and a pattern gets
 * checked as it is typed. Typing "Critical" into a box that could have offered "critical"
 * is a trigger that silently never fires.
 */

const selectCls =
  'bg-surface-input text-[11px] px-1.5 py-1 rounded-sm border border-border text-content-primary'
const inputCls =
  'bg-surface-input text-[11px] px-2 py-1 rounded-sm border text-content-primary w-full font-mono'

/** Why this value will not do, or "" when it will.
 *
 *  Client-side and advisory — RE2 is not JavaScript's engine, and the server's answer is
 *  the one that decides. It catches the typo while the operator is still looking at it,
 *  which is the difference between a fix and a save-then-puzzle. */
function valueProblem(node: TriggerNode, spec?: TriggerFieldSpec): string {
  const value = node.value ?? ''
  if (node.op === 'exists') return ''
  if (value.trim() === '') return 'Needs a value'

  switch (node.op) {
    case 'matches':
      try {
        new RegExp(value)
      } catch (e) {
        return e instanceof Error ? e.message : 'Not a valid regular expression'
      }
      // RE2 has no lookaround or backreferences; JavaScript accepts both, so they compile
      // here and are refused on save. Named rather than left to the server, because the
      // message an operator gets back mid-edit is more use than one on the way out.
      if (/\(\?<?[=!]/.test(value)) return 'RE2 has no lookahead or lookbehind'
      if (/\\[1-9]/.test(value)) return 'RE2 has no backreferences'
      return ''

    case 'status':
      // classes, exact codes, inclusive ranges, and "none" for a request with no response.
      for (const part of value.split(',')) {
        const t = part.trim()
        if (t === '') continue
        if (!/^(none|0|[1-5]xx|[1-9]\d{2}|[1-9]\d{2}-[1-9]\d{2})$/i.test(t)) {
          return `"${t}" is not a status, class or range`
        }
      }
      return ''

    case 'gt':
    case 'lt':
    case 'gte':
    case 'lte':
      return Number.isFinite(Number(value.trim())) ? '' : 'Needs a number'

    default:
      // A value outside a closed set is storable — the set can grow — but it is almost
      // always a typo, so it is flagged rather than refused.
      //
      // Only for the operators that compare the whole value. `severity contains "crit"`
      // is a perfectly good condition and matching it against the set would flag it, and
      // `in` holds several values rather than one.
      if (spec?.values && EXACT_OPS.has(node.op ?? '') && !spec.values.includes(value)) {
        return `${spec.name} is usually one of: ${spec.values.join(', ')}`
      }
      return ''
  }
}

/** The operators that compare a whole value, and so can be offered as a closed choice.
 *  Everything else — contains, prefix, matches — takes a fragment or a pattern. */
const EXACT_OPS = new Set(['eq', 'ne'])

export default function TriggerConditionFields({
  fields,
  node,
  valueLen,
  layout = 'row',
  onChange,
}: {
  /** This event's vocabulary. Empty means the event carries nothing to test. */
  fields: TriggerFieldSpec[]
  node: TriggerNode
  valueLen: number
  /** 'row' packs the controls onto one line for the builder; 'stack' gives each its own
   *  line for the inspector rail, which is narrow. */
  layout?: 'row' | 'stack'
  onChange: (p: Partial<TriggerNode>) => void
}) {
  const spec = fields.find((f) => f.name === node.field)
  const ops = spec?.ops ?? []
  const needsValue = node.op !== 'exists'
  // Case folding means nothing for a number or a status expression, so the box is only
  // offered where it changes the answer.
  const foldable =
    needsValue && spec?.kind !== 'number' && spec?.kind !== 'bool' && node.op !== 'status'

  // A dropdown only where one whole value is being chosen from the set. `contains` and
  // the pattern operators take a fragment, and `in` takes several values, so both get the
  // text box — with the set as a hint where it helps.
  const asDropdown = needsValue && !!spec?.values && EXACT_OPS.has(node.op ?? '')
  const asNumber = needsValue && spec?.kind === 'number'

  const problem = useMemo(() => valueProblem(node, spec), [node, spec])
  const wrap = layout === 'stack' ? 'flex flex-col gap-1.5' : 'flex items-start gap-1'

  return (
    <div className={wrap}>
      <select
        value={node.field ?? ''}
        onChange={(e) => {
          // Changing the field can invalidate the operator and the value, so both fall
          // back rather than being left in a pairing the server would refuse or a value
          // the new field has never heard of.
          const next = fields.find((f) => f.name === e.target.value)
          const op = next?.ops.includes(node.op ?? '') ? node.op : (next?.ops[0] ?? 'eq')
          const constrained = !!next?.values && EXACT_OPS.has(op ?? '')
          const keep = !constrained || next!.values!.includes(node.value ?? '')
          onChange({
            field: e.target.value,
            op,
            value: keep ? node.value : (next?.values?.[0] ?? ''),
          })
        }}
        className={`${selectCls} font-mono ${layout === 'row' ? 'shrink-0 mt-px' : ''}`}
        title={spec?.description}
      >
        {fields.map((f) => (
          <option key={f.name} value={f.name}>
            {f.name}
          </option>
        ))}
      </select>

      <div className="flex items-center gap-1 shrink-0 mt-px">
        <label
          className="flex items-center gap-1 text-[10px] text-content-muted"
          title="Invert this condition"
        >
          <input
            type="checkbox"
            checked={!!node.negate}
            onChange={(e) => onChange({ negate: e.target.checked })}
          />
          not
        </label>

        <select
          value={node.op ?? ''}
          onChange={(e) => {
            const op = e.target.value
            // Switching into a set operator turns a chosen value into the first member of
            // a list; switching out of one keeps only the first, since the control that
            // follows can hold exactly one.
            const value =
              op === 'in' || node.op !== 'in' ? node.value : (node.value ?? '').split(',')[0].trim()
            onChange({ op, value })
          }}
          className={selectCls}
        >
          {ops.map((op) => (
            <option key={op} value={op}>
              {OP_LABEL[op] ?? op}
            </option>
          ))}
        </select>

        {foldable && (
          <label
            className="flex items-center gap-1 text-[10px] text-content-muted"
            title="Match case exactly. Off by default."
          >
            <input
              type="checkbox"
              checked={!!node.caseSensitive}
              onChange={(e) => onChange({ caseSensitive: e.target.checked })}
            />
            Aa
          </label>
        )}
      </div>

      {needsValue && (
        <div className="flex-1 min-w-0">
          {asDropdown ? (
            <select
              value={node.value ?? ''}
              onChange={(e) => onChange({ value: e.target.value })}
              className={`${selectCls} w-full font-mono`}
            >
              {/* A stored value the set does not carry is offered anyway, so opening an
                  older trigger does not silently rewrite it to the first option. */}
              {!spec!.values!.includes(node.value ?? '') && (
                <option value={node.value ?? ''}>{node.value || '—'}</option>
              )}
              {spec!.values!.map((v) => (
                <option key={v} value={v}>
                  {v}
                </option>
              ))}
            </select>
          ) : (
            <input
              type={asNumber ? 'number' : 'text'}
              value={node.value ?? ''}
              maxLength={valueLen}
              placeholder={
                spec?.values && node.op === 'in'
                  ? spec.values.slice(0, 3).join(', ')
                  : (OP_HINT[node.op ?? ''] ?? '')
              }
              onChange={(e) => onChange({ value: e.target.value })}
              className={`${inputCls} ${problem ? 'border-semantic-error' : 'border-border'}`}
            />
          )}
          {problem && (
            <p className="text-[10px] text-semantic-error mt-0.5 leading-snug break-words">
              {problem}
            </p>
          )}
          {!problem && !asDropdown && spec?.values && (
            <p className="text-[10px] text-content-muted mt-0.5 leading-snug">
              {node.op === 'in' ? 'Any of' : 'Known values'}: {spec.values.join(', ')}
            </p>
          )}
        </div>
      )}

      {spec && layout === 'stack' && (
        <p className="text-[10px] text-content-muted leading-snug">{spec.description}</p>
      )}
    </div>
  )
}
