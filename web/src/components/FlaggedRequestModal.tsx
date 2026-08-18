import { useEffect, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router'
import CodeMirror from '@uiw/react-codemirror'
import { EditorView } from '@codemirror/view'
import { oneDark } from '@codemirror/theme-one-dark'
import { Flag, X, WrapText } from 'lucide-react'
import { ResponseRender, usePrettyJson } from './ResponseRender'
import LensOutput from './LensOutput'
import TabButton from './TabButton'
import { useLenses } from '../lib/lenses'
import type { FlaggedRequest } from '../stores/teamFlaggedStore'

function b64Decode(s: string) {
  try {
    return atob(s)
  } catch {
    return s
  }
}

type Props = {
  flagged: FlaggedRequest
  onClose: () => void
  title?: string
  byline?: string
  icon?: ReactNode
}

export default function FlaggedRequestModal({
  flagged,
  onClose,
  title = 'Flagged Request',
  byline = 'flagged by',
  icon = <Flag size={13} aria-hidden="true" />,
}: Props) {
  const navigate = useNavigate()
  // 'raw' | 'render' | a lens automation id.
  const [respTab, setRespTab] = useState('raw')
  const respLenses = useLenses('response')
  const activeRespTab =
    respTab === 'raw' || respTab === 'render' || respLenses.some((l) => l.id === respTab) ? respTab : 'raw'
  const [prettyJson, setPrettyJson] = usePrettyJson()
  // Line wrapping defaults OFF: wrapping a large (up to 256KB) minified/binary
  // response locks the main thread. Operators can opt in per pane.
  const [wrapReq, setWrapReq] = useState(false)
  const [wrapResp, setWrapResp] = useState(false)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  function sendToManipulate() {
    let scheme = 'https'
    let host = flagged.host
    try {
      const u = new URL(flagged.url)
      scheme = u.protocol.replace(':', '')
      host = u.host
    } catch {
      // fall back to stored host
    }
    navigate('/manipulate', { state: { scheme, host, rawReq: flagged.reqRaw } })
    onClose()
  }

  const respRaw = b64Decode(flagged.respRaw)

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6"
      onMouseDown={onClose}
    >
      <div
        className="flex flex-col w-full max-w-5xl h-[85vh] bg-surface-card border border-border rounded shadow-lg overflow-hidden"
        onMouseDown={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="shrink-0 flex items-center gap-2 px-3 py-2 border-b border-border">
          <span className="flex items-center gap-1.5 text-xs font-semibold text-content-primary uppercase tracking-wide">
            {icon}
            {title}
          </span>
          <span className="text-xs text-content-secondary truncate max-w-[45%]">
            <span className="font-bold text-accent-secondary">{flagged.method}</span>{' '}
            {flagged.url}
          </span>
          {flagged.status > 0 && (
            <span
              className={`text-xs ${
                flagged.status < 300
                  ? 'text-semantic-success'
                  : flagged.status < 400
                  ? 'text-semantic-warning'
                  : 'text-semantic-error'
              }`}
            >
              {flagged.status}
            </span>
          )}
          <div className="flex items-center gap-2 ml-auto">
            <button
              onClick={sendToManipulate}
              className="px-3 py-1 bg-accent-secondary text-black text-xs font-medium rounded hover:bg-accent-secondary-hover"
            >
              Send to Manipulate
            </button>
            <button
              onClick={onClose}
              className="px-2 py-1 text-content-secondary hover:text-content-primary inline-flex items-center"
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Meta */}
        <div className="shrink-0 px-3 py-1.5 border-b border-border-subtle text-[11px] text-content-muted flex flex-wrap gap-x-4 gap-y-0.5">
          {flagged.author && (
            <span>
              {byline} <span className="text-content-secondary">{flagged.author}</span>
            </span>
          )}
          {flagged.createdAt && (
            <span>{new Date(flagged.createdAt).toLocaleString('en-US', { timeZone: 'UTC' })} UTC</span>
          )}
          {flagged.host && <span>host: {flagged.host}</span>}
          {flagged.note && <span className="text-content-secondary">“{flagged.note}”</span>}
        </div>

        {/* Body: request + response */}
        <div className="flex-1 min-h-0 flex flex-col">
          {/* Request */}
          <div className="flex flex-col flex-1 min-h-0 overflow-hidden">
            <div className="shrink-0 flex items-center gap-1 px-2 py-1.5 border-b border-border bg-surface-card">
              <span className="text-xs font-semibold text-content-primary">Request</span>
              <button
                onClick={() => setWrapReq((w) => !w)}
                title="Line wrapping"
                className={`ml-auto w-6 h-5 flex items-center justify-center rounded-sm leading-none ${
                  wrapReq ? 'bg-accent text-content-primary' : 'bg-surface-input text-content-secondary hover:bg-surface-hover'
                }`}
              >
                <WrapText size={12} />
              </button>
            </div>
            <div className="flex-1 relative min-h-0">
              <div className="absolute inset-0 overflow-hidden">
                <CodeMirror
                  value={b64Decode(flagged.reqRaw)}
                  theme={oneDark}
                  readOnly={true}
                  height="100%"
                  extensions={wrapReq ? [EditorView.lineWrapping] : []}
                  basicSetup={{ lineNumbers: true, foldGutter: false }}
                />
              </div>
            </div>
          </div>

          {/* Response */}
          <div className="flex flex-col flex-1 min-h-0 overflow-hidden border-t border-border">
            <div className="shrink-0 flex items-center gap-1 px-2 py-1.5 border-b border-border bg-surface-card">
              <span className="text-xs font-semibold text-content-primary">Response</span>
              <div className="flex items-center gap-0.5 ml-2">
                <TabButton active={activeRespTab === 'raw'} onClick={() => setRespTab('raw')}>
                  Raw
                </TabButton>
                <TabButton active={activeRespTab === 'render'} onClick={() => setRespTab('render')}>
                  Render
                </TabButton>
                {respLenses.map((l) => (
                  <TabButton key={l.id} active={activeRespTab === l.id} onClick={() => setRespTab(l.id)}>
                    {l.lens!.label}
                  </TabButton>
                ))}
              </div>
              {activeRespTab === 'raw' && (
                <button
                  onClick={() => setWrapResp((w) => !w)}
                  title="Line wrapping"
                  className={`ml-auto w-6 h-5 flex items-center justify-center rounded-sm leading-none ${
                    wrapResp ? 'bg-accent text-content-primary' : 'bg-surface-input text-content-secondary hover:bg-surface-hover'
                  }`}
                >
                  <WrapText size={12} />
                </button>
              )}
              {activeRespTab === 'render' && (
                <button
                  onClick={() => setPrettyJson(!prettyJson)}
                  className={`ml-auto w-6 h-5 flex items-center justify-center text-[10px] rounded-sm font-semibold leading-none ${
                    prettyJson ? 'bg-accent text-content-primary' : 'bg-surface-input text-content-secondary hover:bg-surface-hover'
                  }`}
                >
                  {'{ }'}
                </button>
              )}
            </div>
            {flagged.truncated && (
              <div className="shrink-0 px-2 py-1 text-[10px] text-semantic-warning bg-surface-input border-b border-border-subtle">
                Response truncated to 256KB
              </div>
            )}
            <div className="flex-1 relative min-h-0">
              {activeRespTab === 'raw' ? (
                <div className="absolute inset-0 overflow-hidden">
                  <CodeMirror
                    value={respRaw}
                    theme={oneDark}
                    readOnly={true}
                    height="100%"
                    extensions={wrapResp ? [EditorView.lineWrapping] : []}
                    basicSetup={{ lineNumbers: true, foldGutter: false }}
                  />
                </div>
              ) : !respRaw ? null : activeRespTab === 'render' ? (
                <ResponseRender raw={respRaw} prettyJson={prettyJson} />
              ) : (
                <LensOutput
                  scriptId={activeRespTab}
                  part="response"
                  raw={respRaw}
                  meta={{ host: flagged.host, url: flagged.url, method: flagged.method, status: flagged.status }}
                />
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
