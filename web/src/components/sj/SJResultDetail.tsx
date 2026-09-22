import { useEffect, useState } from 'react'
import { api } from '../../lib/api'
import { b64DecodeUTF8 as b64Decode } from '../../lib/bytes'
import TabButton from '../TabButton'
import { ResponseRender, usePrettyJson } from '../ResponseRender'

/** Request and response for one run result.
 *
 *  Bodies are fetched on selection rather than streamed with the row, the way
 *  the fuzzer's detail pane works: a scan can hold thousands of responses, and
 *  pushing every body over the WebSocket would cost far more than the operator
 *  reads. */
export default function SJResultDetail({ runId, index }: { runId: string; index: number }) {
  const [detail, setDetail] = useState<{ req: string; resp: string } | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [pane, setPane] = useState<'response' | 'request'>('response')
  const [respTab, setRespTab] = useState<'render' | 'raw'>('render')
  const [prettyJson, setPrettyJson] = usePrettyJson()

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError('')
    api
      .sjGetResult(runId, index)
      .then((res) => {
        if (cancelled) return
        setDetail({ req: b64Decode(res.reqRaw || ''), resp: b64Decode(res.respRaw || '') })
      })
      .catch((e) => !cancelled && setError(String((e as Error).message ?? e)))
      .finally(() => !cancelled && setLoading(false))
    return () => {
      cancelled = true
    }
  }, [runId, index])

  return (
    <div className="flex flex-col h-full border-l border-border">
      <div className="flex items-center gap-1 px-2 py-1 border-b border-border shrink-0">
        <TabButton active={pane === 'request'} onClick={() => setPane('request')}>
          Request
        </TabButton>
        <TabButton active={pane === 'response'} onClick={() => setPane('response')}>
          Response
        </TabButton>
        {pane === 'response' && (
          <>
            <span className="w-px h-3 bg-border mx-1" />
            <TabButton active={respTab === 'render'} onClick={() => setRespTab('render')}>
              Render
            </TabButton>
            <TabButton active={respTab === 'raw'} onClick={() => setRespTab('raw')}>
              Raw
            </TabButton>
            <label className="ml-auto flex items-center gap-1 text-[10px] text-content-secondary">
              <input type="checkbox" checked={prettyJson} onChange={(e) => setPrettyJson(e.target.checked)} />
              pretty
            </label>
          </>
        )}
      </div>
      <div className="flex-1 relative min-h-0 overflow-auto p-2">
        {loading ? (
          <div className="text-[11px] text-content-muted">Loading…</div>
        ) : error ? (
          <div className="text-[11px] text-semantic-error">{error}</div>
        ) : !detail ? null : pane === 'request' ? (
          <pre className="text-[10px] font-mono whitespace-pre-wrap break-all text-content-secondary">{detail.req}</pre>
        ) : !detail.resp ? (
          <div className="text-[11px] text-content-muted">No response body was stored for this row.</div>
        ) : respTab === 'render' ? (
          <ResponseRender raw={detail.resp} prettyJson={prettyJson} />
        ) : (
          <pre className="text-[10px] font-mono whitespace-pre-wrap break-all text-content-secondary">{detail.resp}</pre>
        )}
      </div>
    </div>
  )
}
