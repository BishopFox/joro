import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router'
import { ExternalLink } from 'lucide-react'
import { api } from '../../lib/api'
import { b64DecodeUTF8 } from '../../lib/bytes'
import { cellPill } from '../../lib/chainStatus'
import type { ChainResult } from '../../lib/chainTypes'

interface Props {
  runId: string
  index: number | null
}

// Raw bytes are fetched on demand rather than streamed, as sj's and the fuzzer's
// detail panes are: a sweep's result rows are numerous and the bytes are large.
export default function ChainCellDetail({ runId, index }: Props) {
  const navigate = useNavigate()
  const [data, setData] = useState<{ result: ChainResult; reqRaw: string; respRaw: string } | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    if (index === null) {
      setData(null)
      return
    }
    let live = true
    setError('')
    api
      .chainGetResult(runId, index)
      .then((d) => live && setData(d))
      .catch((e) => live && setError(String((e as Error).message ?? e)))
    return () => {
      live = false
    }
  }, [runId, index])

  if (index === null) {
    return (
      <div className="flex-1 flex items-center justify-center text-content-muted text-xs px-4 text-center">
        Select a cell to see the request that was sent and what came back.
      </div>
    )
  }
  if (error) {
    return <div className="flex-1 p-3 text-xs text-semantic-error">{error}</div>
  }
  if (!data) {
    return <div className="flex-1 p-3 text-xs text-content-muted">Loading…</div>
  }

  const r = data.result

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="px-3 py-2 border-b border-border shrink-0">
        <div className="flex items-center gap-2 flex-wrap">
          {cellPill(r.cell, r.status, r.note)}
          <span className="text-content-primary text-xs">{r.label}</span>
          {r.occurrence > 0 && (
            <span className="text-[10px] text-content-muted">occurrence {r.occurrence + 1}</span>
          )}
          {r.seq ? (
            <button
              className="text-[10px] text-accent-secondary flex items-center gap-1"
              onClick={() => navigate('/history', { state: { focusRequestId: r.requestId } })}
            >
              <ExternalLink size={10} /> seq {r.seq}
            </button>
          ) : (
            r.seqNote && <span className="text-[10px] text-content-muted">{r.seqNote}</span>
          )}
        </div>
        <div className="text-[11px] text-content-muted mt-1 font-mono truncate">{r.url}</div>
        {r.durationMs > 0 && (
          <div className="text-[10px] text-content-muted mt-0.5">
            {r.durationMs}ms · {r.len} bytes
            {r.shash && ` · struct ${r.shash}`}
          </div>
        )}
      </div>

      {r.cell === 'unresolved' && r.missing && (
        <div className="px-3 py-2 bg-semantic-error-bg/40 border-b border-border text-xs shrink-0">
          <div className="text-content-primary mb-1">This step did not send.</div>
          <div className="text-content-secondary">
            It needs{' '}
            {r.missing.map((m, i) => (
              <span key={m.var}>
                {i > 0 && ', '}
                <span className="font-mono text-accent-secondary">{m.var}</span>
              </span>
            ))}
            , which nothing produced in this ordering. That says nothing about the application -
            set the binding to send its recorded value if replaying a stale one is the test.
          </div>
        </div>
      )}

      {r.error && (
        <div className="px-3 py-2 text-xs text-semantic-error border-b border-border shrink-0">
          {r.error}
        </div>
      )}

      {!!r.captured?.length && (
        <div className="px-3 py-2 text-xs border-b border-border shrink-0">
          <div className="text-semantic-warning mb-0.5">Values this step did not produce:</div>
          {r.captured.map((c) => (
            <div key={c} className="text-content-muted font-mono text-[10px]">
              {c}
            </div>
          ))}
        </div>
      )}

      <div className="flex-1 min-h-0 grid grid-rows-2">
        <div className="min-h-0 flex flex-col border-b border-border">
          <div className="px-3 py-1 text-[10px] text-content-secondary shrink-0">Request sent</div>
          <pre className="flex-1 min-h-0 overflow-auto px-3 pb-2 font-mono text-[11px] text-content-primary whitespace-pre-wrap break-all">
            {data.reqRaw ? b64DecodeUTF8(data.reqRaw) : '(not sent)'}
          </pre>
        </div>
        <div className="min-h-0 flex flex-col">
          <div className="px-3 py-1 text-[10px] text-content-secondary shrink-0">Response</div>
          <pre className="flex-1 min-h-0 overflow-auto px-3 pb-2 font-mono text-[11px] text-content-primary whitespace-pre-wrap break-all">
            {data.respRaw ? b64DecodeUTF8(data.respRaw) : '(no response)'}
          </pre>
        </div>
      </div>
    </div>
  )
}
