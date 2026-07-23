import { useState, useRef, useEffect, useCallback } from 'react'
import { api } from '../lib/api'
import { onSliverEvent, onMythicEvent, onPluginEvent } from '../lib/ws'
import DynamicConfigForm from '../components/DynamicConfigForm'
import { useExecutorStore, type OutputLine } from '../stores/executorStore'

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id
}

const EMPTY_OUTPUT: OutputLine[] = []
const EMPTY_HISTORY: string[] = []

// Mythic version the GraphQL queries are validated against; surfaced in the
// connection UI so operators know when schema drift may cause errors.
const MYTHIC_SUPPORTED_VERSION = 'Mythic 3.3+'

// Built-in exec sub-tabs, always shown. Plugin providers (from the backend) are
// appended after these.
const BUILTIN_PROVIDERS = [
  { name: 'webshell', label: 'Web Shell', builtin: true, configSchema: [] },
  { name: 'sliver', label: 'Sliver C2', builtin: true, configSchema: [] },
  { name: 'mythic', label: 'Mythic C2', builtin: true, configSchema: [] },
]
const BUILTIN_NAMES = new Set(BUILTIN_PROVIDERS.map((p) => p.name))

export default function Executor() {
  const {
    execMode, providers, target, webshell, authKey,
    configText, sliverConnected, activeSessionName, pluginStatus, pluginConfigValues,
    mythicUrl, mythicUsername, mythicPassword, mythicApiToken, mythicConnected, activeCallbackName,
    setExecMode, setProviders, setTarget, setWebshell, setAuthKey,
    setConfigText, setSliverConnected, setActiveSessionName, setPluginStatus, setPluginConfigValue,
    setMythicUrl, setMythicUsername, setMythicPassword, setMythicApiToken, setMythicConnected, setActiveCallbackName,
    setCommand, appendOutput, popOutput, clearOutput, pushHistory,
  } = useExecutorStore()
  const output = useExecutorStore((s) => s.outputByMode[s.execMode] ?? EMPTY_OUTPUT)
  const history = useExecutorStore((s) => s.historyByMode[s.execMode] ?? EMPTY_HISTORY)
  const command = useExecutorStore((s) => s.commandByMode[s.execMode] ?? '')

  // Transient UI flags — intentionally local so they reset on remount
  const [connecting, setConnecting] = useState(false)
  const [pluginConnecting, setPluginConnecting] = useState<Record<string, boolean>>({})
  const [running, setRunning] = useState(false)

  const outputRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const historyIdxRef = useRef(-1)

  // Fetch available execution providers on mount.
  useEffect(() => {
    api.listExecProviders().then(setProviders).catch(() => {})
  }, [])

  // Hydrate connection state from backend on mount
  useEffect(() => {
    api.sliverStatus().then((res) => {
      if (res.connected) {
        setSliverConnected(true)
        if (res.sessionName) {
          setActiveSessionName(res.sessionName)
        }
      }
    }).catch(() => {})

    api.mythicStatus().then((res) => {
      if (res.connected) {
        setMythicConnected(true)
        if (res.callbackName) {
          setActiveCallbackName(res.callbackName)
        }
      }
    }).catch(() => {})

    // Hydrate plugin provider statuses.
    api.listExecProviders().then((provs) => {
      for (const p of provs) {
        if (!p.builtin) {
          api.pluginStatus(p.name).then((st) => {
            setPluginStatus(p.name, st)
          }).catch(() => {})
        }
      }
    }).catch(() => {})
  }, [])

  // Listen for Sliver teamserver events (new sessions, beacons, job changes)
  useEffect(() => {
    if (execMode !== 'sliver' || !sliverConnected) return
    return onSliverEvent((ev) => {
      let msg = ''
      switch (ev.eventType) {
        case 'session-connected':
          if (ev.session) {
            msg = `[*] Session ${ev.session.name || shortId(ev.session.id)} opened - ${ev.session.remoteAddress} (${ev.session.hostname}) - ${ev.session.os}/${ev.session.arch} - ${ev.session.transport}`
          }
          break
        case 'session-disconnected':
          if (ev.session) {
            msg = `[!] Lost session ${ev.session.name || shortId(ev.session.id)}`
          }
          break
        case 'beacon-registered':
          if (ev.beacon) {
            msg = `[*] Beacon ${ev.beacon.name || shortId(ev.beacon.id)} registered - ${ev.beacon.remoteAddress} (${ev.beacon.hostname}) - ${ev.beacon.os}/${ev.beacon.arch} - ${ev.beacon.transport}`
          }
          break
        case 'job-stopped':
          msg = `[*] Job ${ev.jobId} (${ev.jobName || 'unknown'}) stopped`
          break
        case 'job-started':
          msg = `[*] Job ${ev.jobId} (${ev.jobName || 'unknown'}) started`
          break
        case 'client-joined':
          break // noisy, skip
        case 'client-left':
          break
        default:
          break
      }
      if (msg) {
        appendOutput({ type: 'out', text: msg })
      }
    })
  }, [execMode, sliverConnected])

  // Listen for Mythic callback events (new callbacks checking in).
  useEffect(() => {
    if (execMode !== 'mythic' || !mythicConnected) return
    return onMythicEvent((ev) => {
      if (ev.eventType === 'callback-new' && ev.callback) {
        const cb = ev.callback
        appendOutput({
          type: 'out',
          text: `[*] New callback ${cb.display_id} (${cb.payload_type}) - ${cb.user}@${cb.host} - ${cb.os}/${cb.architecture} - ${cb.ip}`,
        })
      }
    })
  }, [execMode, mythicConnected])

  // Listen for plugin events when using a plugin provider.
  useEffect(() => {
    const currentProvider = providers.find((p) => p.name === execMode)
    if (!currentProvider || currentProvider.builtin) return
    if (!pluginStatus[execMode]?.connected) return
    return onPluginEvent((ev) => {
      const prefix = `plugin.${execMode}.`
      if (ev.type.startsWith(prefix)) {
        const eventType = ev.type.slice(prefix.length)
        appendOutput({ type: 'out', text: `[event: ${eventType}] ${JSON.stringify(ev.data)}` })
      }
    })
  }, [execMode, providers, pluginStatus])

  useEffect(() => {
    outputRef.current?.scrollTo(0, outputRef.current.scrollHeight)
  }, [output])

  useEffect(() => {
    historyIdxRef.current = -1
  }, [execMode])

  async function connectSliver() {
    setConnecting(true)
    try {
      const cfg = JSON.parse(configText)
      await api.sliverConnect(cfg)
      setSliverConnected(true)
      appendOutput({ type: 'out', text: '[*] Connected to Sliver teamserver' })
    } catch (e) {
      const msg = String(e)
      if (msg.includes('already connected')) {
        setSliverConnected(true)
        appendOutput({ type: 'out', text: '[*] Already connected to Sliver teamserver' })
      } else {
        appendOutput({ type: 'err', text: `Connection failed: ${msg}` })
      }
    } finally {
      setConnecting(false)
    }
  }

  async function disconnectSliver() {
    try {
      await api.sliverDisconnect()
    } catch { /* ignore */ }
    setSliverConnected(false)
    setActiveSessionName('')
    appendOutput({ type: 'out', text: '[*] Disconnected from Sliver teamserver' })
  }

  async function connectMythic() {
    setConnecting(true)
    try {
      await api.mythicConnect({
        url: mythicUrl.trim(),
        username: mythicUsername.trim() || undefined,
        password: mythicPassword || undefined,
        apiToken: mythicApiToken.trim() || undefined,
      })
      setMythicConnected(true)
      appendOutput({ type: 'out', text: '[*] Connected to Mythic' })
    } catch (e) {
      const msg = String(e)
      if (msg.includes('already connected')) {
        setMythicConnected(true)
        appendOutput({ type: 'out', text: '[*] Already connected to Mythic' })
      } else {
        appendOutput({ type: 'err', text: `Connection failed: ${msg}` })
      }
    } finally {
      setConnecting(false)
    }
  }

  async function disconnectMythic() {
    try {
      await api.mythicDisconnect()
    } catch { /* ignore */ }
    setMythicConnected(false)
    setActiveCallbackName('')
    appendOutput({ type: 'out', text: '[*] Disconnected from Mythic' })
  }

  function handleConfigFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => setConfigText(reader.result as string)
    reader.readAsText(file)
  }

  const handleUpload = useCallback(async (remotePath: string) => {
    const input = document.createElement('input')
    input.type = 'file'
    input.onchange = async () => {
      const file = input.files?.[0]
      if (!file) return
      appendOutput({ type: 'cmd', text: `> upload ${remotePath}` })
      setRunning(true)
      try {
        const res = await api.sliverUpload(remotePath, file)
        appendOutput({ type: 'out', text: `[*] Uploaded to ${res.path}` })
      } catch (e) {
        appendOutput({ type: 'err', text: String(e) })
      } finally {
        setRunning(false)
      }
    }
    input.click()
  }, [])

  async function run(e: React.FormEvent) {
    e.preventDefault()
    if (!command.trim() || running) return

    // Add to history
    pushHistory(command)
    historyIdxRef.current = -1

    appendOutput({ type: 'cmd', text: `${getPrompt()}${command}` })
    setRunning(true)
    const cmd = command
    setCommand('')

    try {
      if (execMode === 'sliver') {
        await runSliverCommand(cmd)
      } else if (execMode === 'mythic') {
        await runMythicCommand(cmd)
      } else if (execMode === 'webshell') {
        const res = await api.execute(target, webshell, authKey, cmd)
        if (res.error) {
          appendOutput({ type: 'err', text: res.error })
        } else {
          appendOutput({ type: 'out', text: res.output })
        }
      } else {
        // Plugin provider
        await runPluginCommand(execMode, cmd)
      }
    } catch (e) {
      appendOutput({ type: 'err', text: String(e) })
    } finally {
      setRunning(false)
      inputRef.current?.focus()
    }
  }

  async function runSliverCommand(input: string) {
    const trimmed = input.trim()
    const parts = trimmed.split(/\s+/)
    const cmd = parts[0]?.toLowerCase()

    // Client-side: clear
    if (cmd === 'clear') {
      clearOutput()
      return
    }

    // Client-side: upload triggers file picker
    if (cmd === 'upload') {
      const remotePath = parts[1]
      if (!remotePath) {
        appendOutput({ type: 'err', text: 'Usage: upload <remote_path>' })
        return
      }
      // Remove the command echo we already added, the handleUpload will add its own
      popOutput()
      await handleUpload(remotePath)
      return
    }

    // All other commands go to the backend
    const res = await api.sliverCommand(trimmed)

    // Handle session changes
    if (res.sessionChanged) {
      setActiveSessionName(res.sessionName || '')
    }

    // Handle disconnect
    if (res.disconnected) {
      setSliverConnected(false)
      setActiveSessionName('')
    }

    // Handle special __clear__ signal
    if (res.output === '__clear__') {
      clearOutput()
      return
    }

    // Handle download
    if (res.downloadId) {
      const a = document.createElement('a')
      a.href = `/api/v1/sliver/download/${res.downloadId}`
      a.download = res.filename || 'download'
      a.click()
    }

    // Display output
    if (res.error) {
      appendOutput({ type: 'err', text: res.error })
    }
    if (res.output) {
      appendOutput({ type: 'out', text: res.output })
    }
    if (!res.output && !res.error) {
      appendOutput({ type: 'out', text: '[no output]' })
    }
  }

  async function runMythicCommand(input: string) {
    const trimmed = input.trim()
    const parts = trimmed.split(/\s+/)
    const cmd = parts[0]?.toLowerCase()

    // Client-side: clear
    if (cmd === 'clear') {
      clearOutput()
      return
    }

    // Client-side: upload triggers a file picker
    if (cmd === 'upload') {
      const remotePath = parts[1]
      if (!remotePath) {
        appendOutput({ type: 'err', text: 'Usage: upload <remote_path>' })
        return
      }
      // Remove the command echo we already added; the picker adds its own.
      popOutput()
      const inputEl = document.createElement('input')
      inputEl.type = 'file'
      inputEl.onchange = async () => {
        const file = inputEl.files?.[0]
        if (!file) return
        appendOutput({ type: 'cmd', text: `> upload ${remotePath}` })
        setRunning(true)
        try {
          const res = await api.mythicUpload(remotePath, file)
          appendOutput({ type: 'out', text: `[*] Uploaded to ${res.path}` })
        } catch (e) {
          appendOutput({ type: 'err', text: String(e) })
        } finally {
          setRunning(false)
        }
      }
      inputEl.click()
      return
    }

    const res = await api.mythicCommand(trimmed)

    if (res.callbackChanged) {
      setActiveCallbackName(res.callbackName || '')
    }

    if (res.disconnected) {
      setMythicConnected(false)
      setActiveCallbackName('')
    }

    if (res.downloadId) {
      const a = document.createElement('a')
      a.href = `/api/v1/mythic/download/${res.downloadId}`
      a.download = res.filename || 'download'
      a.click()
    }

    if (res.error) {
      appendOutput({ type: 'err', text: res.error })
    }
    if (res.output) {
      appendOutput({ type: 'out', text: res.output })
    }
    if (!res.output && !res.error) {
      appendOutput({ type: 'out', text: '[no output]' })
    }
  }

  async function runPluginCommand(providerName: string, input: string) {
    const trimmed = input.trim()
    if (trimmed.toLowerCase() === 'clear') {
      clearOutput()
      return
    }

    const res = await api.pluginCommand(providerName, trimmed)

    if (res.clear) {
      clearOutput()
      return
    }

    if (res.downloadId) {
      const a = document.createElement('a')
      a.href = `/api/v1/plugin/${providerName}/download/${res.downloadId}`
      a.download = res.filename || 'download'
      a.click()
    }

    if (res.error) {
      appendOutput({ type: 'err', text: res.error! })
    }
    if (res.output) {
      appendOutput({ type: 'out', text: res.output })
    }
    if (!res.output && !res.error) {
      appendOutput({ type: 'out', text: '[no output]' })
    }
  }

  function getPrompt(): string {
    if (execMode === 'webshell') return '$ '
    if (execMode === 'sliver') {
      if (activeSessionName) return `sliver (${activeSessionName}) > `
      return 'sliver > '
    }
    if (execMode === 'mythic') {
      if (activeCallbackName) return `mythic (${activeCallbackName}) > `
      return 'mythic > '
    }
    // Plugin provider prompt
    return `${execMode} > `
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'ArrowUp') {
      e.preventDefault()
      if (history.length === 0) return
      if (historyIdxRef.current < 0) {
        historyIdxRef.current = history.length - 1
      } else if (historyIdxRef.current > 0) {
        historyIdxRef.current--
      }
      setCommand(history[historyIdxRef.current])
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (historyIdxRef.current < 0) return
      if (historyIdxRef.current < history.length - 1) {
        historyIdxRef.current++
        setCommand(history[historyIdxRef.current])
      } else {
        historyIdxRef.current = -1
        setCommand('')
      }
    }
  }

  const isConfigured = execMode === 'webshell'
    ? !!target && !!webshell && !!authKey
    : execMode === 'sliver'
      ? sliverConnected
      : execMode === 'mythic'
        ? mythicConnected
        : (pluginStatus[execMode]?.connected ?? false)
  const canRun = !running && isConfigured

  return (
    <div className="flex flex-col flex-1 min-h-0 p-3 gap-3">
      {/* Connection form */}
      <div className="bg-surface-card rounded border border-border p-3">
        <div className="flex items-center gap-3 mb-2">
          <h2 className="text-xs font-semibold text-content-muted uppercase tracking-wide">Connection</h2>
          <div className="flex gap-1 bg-surface-input rounded-sm p-0.5">
            {[...BUILTIN_PROVIDERS, ...providers.filter((p) => !BUILTIN_NAMES.has(p.name))].map((p) => (
              <button
                key={p.name}
                onClick={() => setExecMode(p.name)}
                className={`px-3 py-1 rounded-sm text-xs font-semibold ${
                  execMode === p.name ? 'bg-accent text-content-primary' : 'text-content-secondary hover:text-content-primary'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        {execMode === 'webshell' ? (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label className="text-xs text-content-muted block mb-1">Target URL</label>
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="https://example.com"
                className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
              />
            </div>
            <div>
              <label className="text-xs text-content-muted block mb-1">Web Shell Path</label>
              <input
                value={webshell}
                onChange={(e) => setWebshell(e.target.value)}
                placeholder="/uploads/joro.php"
                className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
              />
            </div>
            <div>
              <label className="text-xs text-content-muted block mb-1">Auth Key</label>
              <input
                value={authKey}
                onChange={(e) => setAuthKey(e.target.value)}
                placeholder="UUID auth key"
                className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
              />
            </div>
          </div>
        ) : execMode === 'sliver' ? (
          <div className="space-y-3">
            {!sliverConnected ? (
              <>
                <div>
                  <label className="text-xs text-content-muted block mb-1">Operator Config (JSON)</label>
                  <p className="text-xs text-content-secondary mb-2">
                    Export from Sliver teamserver: <code className="text-accent-secondary">new-player --operator joro --lhost &lt;teamserver-ip&gt; --save /tmp/joro.cfg</code>. Upload the resulting <code className="text-accent-secondary">.cfg</code> file or paste its contents below.
                  </p>
                  <div className="flex gap-2 items-start">
                    <textarea
                      value={configText}
                      onChange={(e) => setConfigText(e.target.value)}
                      placeholder='Paste operator config JSON or use file upload...'
                      rows={4}
                      className="flex-1 bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border font-mono resize-none"
                    />
                    <div className="flex flex-col gap-2">
                      <label className="px-3 py-1.5 rounded-sm bg-surface-input border border-border text-xs text-content-secondary hover:bg-surface-hover cursor-pointer text-center">
                        Upload
                        <input type="file" accept=".json,.cfg" onChange={handleConfigFile} className="hidden" />
                      </label>
                      <button
                        onClick={connectSliver}
                        disabled={connecting || !configText.trim()}
                        className="px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold disabled:opacity-50"
                      >
                        {connecting ? 'Connecting...' : 'Connect'}
                      </button>
                    </div>
                  </div>
                </div>
              </>
            ) : (
              <div className="flex items-center gap-3">
                <span className="text-xs text-semantic-success font-semibold">Connected</span>
                {activeSessionName && (
                  <span className="text-xs text-content-secondary">
                    Session: <span className="text-accent-secondary font-semibold">{activeSessionName}</span>
                  </span>
                )}
                <div className="flex-1" />
                <button
                  onClick={disconnectSliver}
                  className="px-3 py-1.5 rounded-sm bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary text-xs font-semibold"
                >
                  Disconnect
                </button>
              </div>
            )}
          </div>
        ) : execMode === 'mythic' ? (
          <div className="space-y-3">
            {!mythicConnected ? (
              <>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="md:col-span-2">
                    <label className="text-xs text-content-muted block mb-1">Server URL</label>
                    <input
                      value={mythicUrl}
                      onChange={(e) => setMythicUrl(e.target.value)}
                      placeholder="https://10.0.0.5:7443"
                      className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-content-muted block mb-1">Username</label>
                    <input
                      value={mythicUsername}
                      onChange={(e) => setMythicUsername(e.target.value)}
                      placeholder="mythic_admin"
                      className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-content-muted block mb-1">Password</label>
                    <input
                      type="password"
                      value={mythicPassword}
                      onChange={(e) => setMythicPassword(e.target.value)}
                      placeholder="password"
                      className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                    />
                  </div>
                  <div className="md:col-span-2">
                    <label className="text-xs text-content-muted block mb-1">API Token <span className="text-content-muted">(optional — used instead of username/password)</span></label>
                    <input
                      value={mythicApiToken}
                      onChange={(e) => setMythicApiToken(e.target.value)}
                      placeholder="apitoken value from Mythic operator settings"
                      className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border font-mono"
                    />
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <p className="text-xs text-content-secondary flex-1">
                    Tested against {MYTHIC_SUPPORTED_VERSION}. Older/newer GraphQL schemas may differ.
                  </p>
                  <button
                    onClick={connectMythic}
                    disabled={connecting || !mythicUrl.trim() || (!mythicApiToken.trim() && (!mythicUsername.trim() || !mythicPassword))}
                    className="px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold disabled:opacity-50"
                  >
                    {connecting ? 'Connecting...' : 'Connect'}
                  </button>
                </div>
              </>
            ) : (
              <div className="flex items-center gap-3">
                <span className="text-xs text-semantic-success font-semibold">Connected</span>
                {activeCallbackName && (
                  <span className="text-xs text-content-secondary">
                    Callback: <span className="text-accent-secondary font-semibold">{activeCallbackName}</span>
                  </span>
                )}
                <div className="flex-1" />
                <button
                  onClick={disconnectMythic}
                  className="px-3 py-1.5 rounded-sm bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary text-xs font-semibold"
                >
                  Disconnect
                </button>
              </div>
            )}
          </div>
        ) : (
          /* Plugin provider — render dynamic config form */
          (() => {
            const provider = providers.find((p) => p.name === execMode)
            if (!provider) return null
            return (
              <DynamicConfigForm
                schema={provider.configSchema}
                values={pluginConfigValues[execMode] ?? {}}
                onValueChange={(name, value) => setPluginConfigValue(execMode, name, value)}
                status={pluginStatus[execMode] ?? null}
                connecting={pluginConnecting[execMode] ?? false}
                onConnect={async () => {
                  const config = pluginConfigValues[execMode] ?? {}
                  setPluginConnecting((prev) => ({ ...prev, [execMode]: true }))
                  try {
                    await api.pluginConnect(execMode, config)
                    setPluginStatus(execMode, { connected: true })
                    appendOutput({ type: 'out', text: `[*] Connected to ${provider.label}` })
                    // Refresh full status
                    api.pluginStatus(execMode).then((st) => {
                      setPluginStatus(execMode, st)
                    }).catch(() => {})
                  } catch (e) {
                    appendOutput({ type: 'err', text: `Connection failed: ${String(e)}` })
                  } finally {
                    setPluginConnecting((prev) => ({ ...prev, [execMode]: false }))
                  }
                }}
                onDisconnect={async () => {
                  try {
                    await api.pluginDisconnect(execMode)
                  } catch { /* ignore */ }
                  setPluginStatus(execMode, { connected: false })
                  appendOutput({ type: 'out', text: `[*] Disconnected from ${provider.label}` })
                }}
              />
            )
          })()
        )}
      </div>

      {/* Terminal output */}
      <div
        ref={outputRef}
        className="flex-1 bg-surface-terminal rounded border border-border p-3 font-mono text-xs overflow-auto"
      >
        {output.length === 0 ? (
          <span className="text-content-muted">
            {execMode === 'webshell'
              ? 'Configure connection above and run commands below'
              : isConfigured
                ? "Type 'help' for available commands"
                : 'Connect above to execute commands below'}
          </span>
        ) : (
          output.map((line, i) => (
            <div
              key={i}
              className={line.type === 'cmd' ? 'text-accent' : line.type === 'err' ? 'text-semantic-error' : 'text-semantic-success'}
            >
              <pre className="whitespace-pre-wrap">{line.text}</pre>
            </div>
          ))
        )}
      </div>

      {/* Command input */}
      <form onSubmit={run} className="flex gap-2">
        <span className="text-accent self-center font-mono text-xs whitespace-nowrap">
          {getPrompt().trimEnd()}
        </span>
        <input
          ref={inputRef}
          value={command}
          onChange={(e) => setCommand(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={!isConfigured}
          placeholder={execMode === 'sliver' || execMode === 'mythic' ? 'help' : 'whoami'}
          className="flex-1 bg-surface-input text-xs px-3 py-1.5 rounded-sm border border-border disabled:opacity-50 font-mono"
        />
        <button
          type="submit"
          disabled={!canRun}
          className="px-4 py-1.5 rounded-sm bg-accent-secondary hover:bg-accent-secondary-hover text-black text-xs font-semibold disabled:opacity-50"
        >
          {running ? 'Running...' : 'Run'}
        </button>
      </form>
    </div>
  )
}
