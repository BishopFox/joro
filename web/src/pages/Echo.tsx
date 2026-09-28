import { useCallback, useEffect, useMemo, useState } from 'react'
import { Play, RefreshCw, ShieldAlert, Square, Trash2 } from 'lucide-react'
import { api } from '../lib/api'
import { useResizable } from '../lib/useResizable'
import { useToastStore } from '../stores/toastStore'
import { buildEchoQuery, useEchoStore } from '../stores/echoStore'
import MultiSelectDropdown from '../components/MultiSelectDropdown'
import { EchoSinkPill } from '../components/echo/EchoSinkPill'
import { EchoParamDetail } from '../components/echo/EchoParamDetail'
import type { EchoContext, EchoSource, EchoTransform } from '../lib/echoTypes'
import {
  CONTEXT_LABELS,
  CONTEXT_OPTIONS,
  SOURCE_LABELS,
  SOURCE_OPTIONS,
  TRANSFORM_LABELS,
  TRANSFORM_OPTIONS,
} from '../lib/echoTypes'

function formatTime(ts: string): string {
  if (!ts) return ''
  const d = new Date(ts)
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString()
}

export default function Echo() {
  const store = useEchoStore()
  const addToast = useToastStore((s) => s.addToast)
  const vSplit = useResizable('vertical', 0.55)
  const [busy, setBusy] = useState(false)

  const {
    enabled, config, summary, hosts, scan,
    items, total, loading, selected, filter, reloadCounter,
    setItems, setLoading, setSelected, setFilter, invalidate,
  } = store

  const query = useMemo(() => buildEchoQuery(filter), [filter])

  // Server-owned state is re-synced on mount and on reconnect: the hub
  // broadcast is non-blocking with no replay, so events emitted while the
  // socket was down are gone for good.
  const resync = useCallback(async () => {
    try {
      const st = await api.echoState()
      store.setConfig(st.config)
      store.setSummary(st.summary)
      store.setHosts(st.hosts)
      store.setScan(st.scan)
    } catch {
      // Leaves the last known state on screen.
    }
  }, [store])

  useEffect(() => {
    void resync()
    const onReconnect = () => void resync()
    window.addEventListener('joro:ws-reconnected', onReconnect)
    return () => window.removeEventListener('joro:ws-reconnected', onReconnect)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const d = await api.echoListParams({ ...query, limit: 300 })
      setItems(d.items ?? [], d.total ?? 0)
    } catch {
      // A failed load leaves the previous page on screen.
    } finally {
      setLoading(false)
    }
  }, [query, setItems, setLoading])

  useEffect(() => {
    void load()
  }, [load, reloadCounter])

  async function toggleEnabled(next: boolean) {
    setBusy(true)
    try {
      await api.echoSetEnabled(next)
      store.setEnabled(next)
      store.setConfig({ ...config, enabled: next })
      if (next && summary.scanned === 0) {
        addToast('Mapping is on. Run a backfill to map traffic already captured.', 'info')
      }
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    } finally {
      setBusy(false)
    }
  }

  async function backfill() {
    try {
      await api.echoStartScan({ scope: 'all' })
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    }
  }

  async function clearMap() {
    try {
      await api.echoClear()
      store.clearAll()
      invalidate()
      void resync()
    } catch (e) {
      addToast(String((e as Error).message ?? e), 'error')
    }
  }

  return (
    <div className="flex h-full flex-col overflow-hidden">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3 border-b border-border px-3 py-2">
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={enabled}
            disabled={busy}
            onChange={(e) => void toggleEnabled(e.target.checked)}
          />
          <span className="text-content-primary">Reflection mapping</span>
        </label>

        <span className="text-xs text-content-muted">
          {summary.params} parameter{summary.params === 1 ? '' : 's'} ·{' '}
          {summary.reflections} reflection{summary.reflections === 1 ? '' : 's'} ·{' '}
          {summary.hosts} host{summary.hosts === 1 ? '' : 's'} ·{' '}
          {summary.scanned} analyzed
        </span>
        {summary.breakouts > 0 && (
          <span className="inline-flex items-center gap-1 text-xs text-semantic-error">
            <ShieldAlert size={13} />
            {summary.breakouts} can leave context
          </span>
        )}

        <div className="ml-auto flex items-center gap-2">
          {scan.running ? (
            <>
              <span className="text-xs text-content-muted">
                mapping {scan.scanned}/{scan.total}
              </span>
              <button
                className="inline-flex items-center gap-1 rounded bg-semantic-error-bg px-2 py-1 text-xs"
                onClick={() => void api.echoCancelScan()}
              >
                <Square size={12} /> Stop
              </button>
            </>
          ) : (
            <button
              className="inline-flex items-center gap-1 rounded bg-accent-secondary px-2 py-1 text-xs text-black hover:bg-accent-secondary-hover disabled:opacity-50"
              disabled={!enabled}
              title={
                enabled
                  ? 'Analyze every captured response'
                  : 'Switch mapping on first'
              }
              onClick={() => void backfill()}
            >
              <Play size={12} /> Backfill
            </button>
          )}
          <button
            className="inline-flex items-center gap-1 rounded bg-surface-input px-2 py-1 text-xs text-content-secondary hover:bg-surface-hover"
            onClick={() => invalidate()}
          >
            <RefreshCw size={12} /> Refresh
          </button>
          <button
            className="inline-flex items-center gap-1 rounded bg-surface-input px-2 py-1 text-xs text-content-secondary hover:bg-surface-hover"
            onClick={() => void clearMap()}
          >
            <Trash2 size={12} /> Clear
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-3 py-1.5">
        <input
          className="w-48 rounded bg-surface-input px-2 py-1 text-xs text-content-primary"
          placeholder="Search name or value"
          value={filter.search}
          onChange={(e) => setFilter({ search: e.target.value })}
        />
        <select
          className="rounded bg-surface-input px-2 py-1 text-xs text-content-primary"
          value={filter.host}
          onChange={(e) => setFilter({ host: e.target.value })}
        >
          <option value="">All hosts</option>
          {hosts.map((h) => (
            <option key={h} value={h}>{h}</option>
          ))}
        </select>
        <MultiSelectDropdown
          label="Source"
          options={SOURCE_OPTIONS.map((k) => ({ key: k, label: SOURCE_LABELS[k] }))}
          selected={filter.sources}
          onChange={(next) => setFilter({ sources: next as EchoSource[] })}
        />
        <MultiSelectDropdown
          label="Context"
          options={CONTEXT_OPTIONS.map((k) => ({ key: k, label: CONTEXT_LABELS[k] }))}
          selected={filter.contexts}
          onChange={(next) => setFilter({ contexts: next as EchoContext[] })}
        />
        <MultiSelectDropdown
          label="Transform"
          options={TRANSFORM_OPTIONS.map((k) => ({
            key: k,
            label: TRANSFORM_LABELS[k] ?? k,
          }))}
          selected={filter.transforms}
          onChange={(next) => setFilter({ transforms: next as EchoTransform[] })}
        />
        <label className="flex items-center gap-1.5 text-xs text-content-secondary">
          <input
            type="checkbox"
            checked={filter.breakoutOnly}
            onChange={(e) => setFilter({ breakoutOnly: e.target.checked })}
          />
          Can leave context only
        </label>
        <span className="ml-auto text-xs text-content-muted">
          {items.length} of {total}
        </span>
      </div>

      {/* Table + detail */}
      <div ref={vSplit.containerRef} className="flex min-h-0 flex-1 flex-col">
        <div className="overflow-auto" style={{ height: `${vSplit.fraction * 100}%` }}>
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-surface-card">
              <tr className="border-b border-border text-left text-content-muted">
                <th className="px-2 py-1 font-normal">Parameter</th>
                <th className="px-2 py-1 font-normal">Source</th>
                <th className="px-2 py-1 font-normal">Host</th>
                <th className="px-2 py-1 font-normal">Lands in</th>
                <th className="px-2 py-1 text-right font-normal">Seen</th>
                <th className="px-2 py-1 text-right font-normal">Values</th>
                <th className="px-2 py-1 font-normal">Last</th>
              </tr>
            </thead>
            <tbody>
              {items.length === 0 && !loading && (
                <tr>
                  <td colSpan={7} className="px-2 py-8 text-center text-xs text-content-muted">
                    {!enabled
                      ? 'Reflection mapping is off. Switch it on, then browse through the proxy or run a backfill.'
                      : summary.params === 0
                        ? 'Nothing mapped yet - browse through the proxy, or run a backfill over captured history.'
                        : 'No parameters match the current filters.'}
                  </td>
                </tr>
              )}
              {items.map((e) => (
                <tr
                  key={e.id}
                  className={`cursor-pointer border-b border-border-subtle hover:bg-surface-hover ${
                    selected?.id === e.id ? 'bg-surface-hover' : ''
                  }`}
                  onClick={() => setSelected(e)}
                >
                  <td className="max-w-[16rem] truncate px-2 py-1 text-content-secondary">
                    {e.breakouts > 0 && (
                      <ShieldAlert size={12} className="mr-1 inline text-semantic-error" />
                    )}
                    {e.name}
                  </td>
                  <td className="px-2 py-1 text-content-muted">
                    {SOURCE_LABELS[e.source] ?? e.source}
                  </td>
                  <td className="max-w-[12rem] truncate px-2 py-1 text-content-muted">{e.host}</td>
                  <td className="px-2 py-1">
                    <div className="flex flex-wrap gap-1">
                      {e.sinks.slice(0, 4).map((s, i) => (
                        <EchoSinkPill key={i} sink={s} />
                      ))}
                      {e.sinks.length > 4 && (
                        <span className="text-[11px] text-content-muted">
                          +{e.sinks.length - 4}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-2 py-1 text-right text-content-muted">{e.observations}</td>
                  <td className="px-2 py-1 text-right text-content-muted">{e.distinctValues}</td>
                  <td className="px-2 py-1 text-content-muted">{formatTime(e.lastSeen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="drag-handle-v" {...vSplit.handleProps} />

        <div className="min-h-0 flex-1 overflow-hidden border-t border-border">
          {selected ? (
            <EchoParamDetail entry={selected} />
          ) : (
            <div className="px-3 py-6 text-center text-xs text-content-muted">
              Select a parameter to see where its values came back.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
