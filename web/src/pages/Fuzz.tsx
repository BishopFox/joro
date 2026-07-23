import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { WrapText, Pilcrow, CornerDownRight, ChevronUp, ChevronDown, X, Settings } from 'lucide-react'
import CodeMirror from '@uiw/react-codemirror'
import { EditorView, Decoration, DecorationSet, ViewPlugin, ViewUpdate, WidgetType } from '@codemirror/view'
import type { Range } from '@codemirror/state'
import { oneDark } from '@codemirror/theme-one-dark'
import { api } from '../lib/api'
import { useResizable } from '../lib/useResizable'
import { useFuzzStore, MAX_TABS, type FuzzSortColumn, type FilterType, type MatchFilterRule, type AttackMode } from '../stores/fuzzStore'
import ContextMenu from '../components/ContextMenu'
import { Tooltip } from '../components/Tooltip'
import { getSelectionMenuItems } from '../lib/selectionMenu'
import { copyText } from '../lib/clipboard'
import { rawToCurl, updateContentLengthInRaw } from '../lib/httpTransform'
import { ResponseRender, usePrettyJson } from '../components/ResponseRender'

function b64Encode(s: string) { try { return btoa(s) } catch { return s } }
function b64Decode(s: string) { try { return atob(s) } catch { return s } }

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatNumber(n: number): string {
  return n.toLocaleString()
}

// Detect FUZZ position markers in request text
function detectPositions(raw: string): string[] {
  const numbered = new Set<string>()
  const regex = /FUZZ(\d+)/g
  let match
  while ((match = regex.exec(raw)) !== null) {
    numbered.add(match[0])
  }
  if (numbered.size > 0) {
    return [...numbered].sort((a, b) => {
      const na = parseInt(a.replace('FUZZ', ''))
      const nb = parseInt(b.replace('FUZZ', ''))
      return na - nb
    })
  }
  // Check for plain FUZZ (not followed by a digit)
  if (/FUZZ(?!\d)/.test(raw)) {
    return ['FUZZ']
  }
  return []
}

const POSITION_CLASSES = [
  'cm-fuzz-pos-0', 'cm-fuzz-pos-1', 'cm-fuzz-pos-2',
  'cm-fuzz-pos-3', 'cm-fuzz-pos-4', 'cm-fuzz-pos-5',
]

// CodeMirror plugin to highlight FUZZ position markers with per-position colors
function fuzzHighlightPlugin(positions: string[]) {
  // Build a map of position label → CSS class
  const posClassMap = new Map<string, string>()
  // Sort positions by length descending so FUZZ10 is checked before FUZZ1
  const sorted = [...positions].sort((a, b) => b.length - a.length)
  for (const pos of sorted) {
    const idx = positions.indexOf(pos)
    posClassMap.set(pos, POSITION_CLASSES[idx % POSITION_CLASSES.length])
  }

  return ViewPlugin.fromClass(class {
    decorations: DecorationSet
    constructor(view: EditorView) { this.decorations = this.build(view) }
    update(update: ViewUpdate) {
      if (update.docChanged || update.viewportChanged) this.decorations = this.build(update.view)
    }
    build(view: EditorView): DecorationSet {
      const ranges: Range<Decoration>[] = []
      const doc = view.state.doc
      const text = doc.toString()
      // Search for each position keyword, longest first to avoid substring matches
      for (const pos of sorted) {
        const cls = posClassMap.get(pos)!
        let searchPos = 0
        while (true) {
          const idx = text.indexOf(pos, searchPos)
          if (idx < 0) break
          ranges.push(
            Decoration.mark({ class: cls }).range(idx, idx + pos.length)
          )
          searchPos = idx + pos.length
        }
      }
      ranges.sort((a, b) => a.from - b.from)
      return Decoration.set(ranges)
    }
  }, { decorations: v => v.decorations })
}

// Widget that renders a non-printable character marker inline
class NPWidget extends WidgetType {
  constructor(readonly label: string) { super() }
  toDOM() {
    const span = document.createElement('span')
    span.className = 'cm-nonprintable'
    span.textContent = this.label
    return span
  }
  ignoreEvent() { return false }
}

const crlfWidget = new NPWidget('\\r\\n')
const tabWidget = new NPWidget('\\t')
const nulWidget = new NPWidget('\\0')

function nonPrintablePlugin() {
  return ViewPlugin.fromClass(class {
    decorations: DecorationSet
    constructor(view: EditorView) { this.decorations = this.build(view) }
    update(update: ViewUpdate) {
      if (update.docChanged || update.viewportChanged) this.decorations = this.build(update.view)
    }
    build(view: EditorView): DecorationSet {
      const ranges: Range<Decoration>[] = []
      const doc = view.state.doc

      for (const { from, to } of view.visibleRanges) {
        const startLine = doc.lineAt(from).number
        const endLine = doc.lineAt(to).number

        for (let ln = startLine; ln <= endLine; ln++) {
          const line = doc.line(ln)
          const lineText = line.text

          for (let i = 0; i < lineText.length; i++) {
            const code = lineText.charCodeAt(i)
            if (code === 9) {
              ranges.push(Decoration.widget({ widget: tabWidget, side: 0 }).range(line.from + i))
            } else if (code === 0) {
              ranges.push(Decoration.widget({ widget: nulWidget, side: 0 }).range(line.from + i))
            } else if (code < 32 && code !== 10 && code !== 13 && code !== 9) {
              const w = new NPWidget('\\x' + code.toString(16).padStart(2, '0'))
              ranges.push(Decoration.widget({ widget: w, side: 0 }).range(line.from + i))
            }
          }

          if (ln < doc.lines) {
            ranges.push(Decoration.widget({ widget: crlfWidget, side: 1 }).range(line.to))
          }
        }
      }

      ranges.sort((a, b) => a.from - b.from || a.value.startSide - b.value.startSide)
      return Decoration.set(ranges)
    }
  }, { decorations: v => v.decorations })
}

const ATTACK_MODES: { value: AttackMode; label: string; title: string }[] = [
  { value: 'spray', label: 'Spray', title: 'Same payload in all positions' },
  { value: 'split', label: 'Split', title: 'One wordlist per position, iterate row by row' },
  { value: 'yolo', label: 'Yolo', title: 'All combinations (cartesian product)' },
]

export default function Fuzz() {
  const location = useLocation()
  const navigate = useNavigate()
  const { tabs, activeTabId, addTab, removeTab, renameTab, setActiveTab, ...store } = useFuzzStore()
  const tab = tabs.find((t) => t.id === activeTabId) ?? tabs[0]

  const fileInputRef = useRef<HTMLInputElement>(null)
  const posFileInputRef = useRef<HTMLInputElement>(null)
  const editorViewRef = useRef<EditorView | null>(null)

  // Tab rename state
  const [editingTabId, setEditingTabId] = useState<string | null>(null)
  const [editName, setEditName] = useState('')
  const renameInputRef = useRef<HTMLInputElement>(null)

  // Context menu state
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number } | null>(null)
  const ctxMenuCbRef = useRef<(x: number, y: number) => void>(() => {})
  ctxMenuCbRef.current = (x: number, y: number) => setCtxMenu({ x, y })
  const handleCloseCtxMenu = useCallback(() => setCtxMenu(null), [])

  // Detail panel state
  const [wrapDetailReq, setWrapDetailReq] = useState(true)
  const [wrapDetailResp, setWrapDetailResp] = useState(true)
  const [respTab, setRespTab] = useState<'raw' | 'render'>('raw')
  const [prettyJson, setPrettyJson] = usePrettyJson()

  const vSplit = useResizable('vertical', 0.4)
  const hSplit = useResizable('horizontal', 0.55)
  const detailSplit = useResizable('horizontal', 0.5)
  const detailHSplit = useResizable('horizontal', 0.5)
  const isRunning = tab.status === 'running'

  // Focus rename input
  useEffect(() => {
    if (editingTabId && renameInputRef.current) {
      renameInputRef.current.focus()
      renameInputRef.current.select()
    }
  }, [editingTabId])

  function commitRename() {
    if (editingTabId && editName.trim()) {
      renameTab(editingTabId, editName.trim())
    }
    setEditingTabId(null)
  }

  // Handle navigation state (from History -> "Fuzz")
  useEffect(() => {
    const state = location.state as { scheme?: string; host?: string; rawReq?: string } | null
    if (state?.rawReq) {
      addTab({
        scheme: state.scheme || 'https',
        host: state.host || 'example.com',
        rawReq: b64Decode(state.rawReq),
      })
      navigate('/fuzz', { replace: true })
    }
  }, [location.state]) // eslint-disable-line

  // Detect positions in the request template
  const detectedPositions = useMemo(() => detectPositions(tab.rawReq), [tab.rawReq])
  const isMultiPosition = detectedPositions.length > 1

  // Sync position wordlists when positions change
  useEffect(() => {
    if (isMultiPosition) {
      store.syncPositionWordlists(detectedPositions)
    }
  }, [detectedPositions.join(',')]) // eslint-disable-line

  const fuzzPlugin = useMemo(
    () => fuzzHighlightPlugin(detectedPositions.length > 0 ? detectedPositions : ['FUZZ']),
    [detectedPositions.join(',')], // eslint-disable-line
  )
  const npPlugin = useMemo(() => nonPrintablePlugin(), [])

  const contextMenuExt = useMemo(
    () => EditorView.domEventHandlers({
      contextmenu(event) {
        event.preventDefault()
        ctxMenuCbRef.current(event.clientX, event.clientY)
        return true
      },
    }),
    []
  )

  const reqExtensions = useMemo(() => {
    const exts: any[] = [fuzzPlugin, contextMenuExt] // eslint-disable-line
    if (tab.wrapReq) exts.push(EditorView.lineWrapping)
    if (tab.showNonPrintable) exts.push(npPlugin)
    return exts
  }, [tab.wrapReq, tab.showNonPrintable, fuzzPlugin, npPlugin, contextMenuExt])

  // Parse wordlist into lines (single-position)
  const wordlistLines = useMemo(() => {
    return tab.wordlist.split('\n').filter(l => l.trim() !== '')
  }, [tab.wordlist])

  // Determine if we can start based on wordlist state
  const canStart = useMemo(() => {
    if (detectedPositions.length === 0) return false
    if (!isMultiPosition) return wordlistLines.length > 0
    if (tab.attackMode === 'spray') return wordlistLines.length > 0
    // split/yolo: all position wordlists must have content
    return tab.positionWordlists.every(pw => pw.wordlist.split('\n').some(l => l.trim() !== ''))
  }, [detectedPositions, isMultiPosition, wordlistLines, tab.attackMode, tab.positionWordlists])

  // Estimated total for display
  const estimatedTotal = useMemo(() => {
    if (!canStart) return 0
    if (!isMultiPosition) return wordlistLines.length
    switch (tab.attackMode) {
      case 'spray':
        return wordlistLines.length
      case 'split': {
        const lengths = tab.positionWordlists.map(pw => pw.wordlist.split('\n').filter(l => l.trim()).length)
        return Math.min(...lengths)
      }
      case 'yolo': {
        let product = 1
        for (const pw of tab.positionWordlists) {
          product *= pw.wordlist.split('\n').filter(l => l.trim()).length
        }
        return product
      }
    }
  }, [canStart, isMultiPosition, wordlistLines, tab.attackMode, tab.positionWordlists])

  // Compute speed
  const speedRef = useRef({ times: [] as number[] })
  useEffect(() => {
    if (tab.status === 'running' && tab.completedPayloads > 0) {
      speedRef.current.times.push(Date.now())
      if (speedRef.current.times.length > 100) {
        speedRef.current.times = speedRef.current.times.slice(-100)
      }
    }
    if (tab.status === 'idle') {
      speedRef.current.times = []
    }
  }, [tab.completedPayloads, tab.status])

  const speed = useMemo(() => {
    const times = speedRef.current.times
    if (times.length < 2) return 0
    const elapsed = (times[times.length - 1] - times[0]) / 1000
    if (elapsed <= 0) return 0
    return Math.round((times.length - 1) / elapsed)
  }, [tab.completedPayloads]) // eslint-disable-line

  // Client-side filtering & sorting
  const visibleResults = useMemo(() => {
    let filtered = tab.results

    const activeFilters = tab.filters.filter(f => f.enabled)
    if (activeFilters.length > 0) {
      filtered = filtered.filter(r => {
        const checks = activeFilters.map(f => matchesRule(r, f))
        const shouldHide = tab.filterMode === 'and' ? checks.every(Boolean) : checks.some(Boolean)
        return !shouldHide
      })
    }

    const activeMatchers = tab.matchers.filter(m => m.enabled)
    if (activeMatchers.length > 0) {
      filtered = filtered.filter(r => {
        const checks = activeMatchers.map(m => matchesRule(r, m))
        return tab.matcherMode === 'and' ? checks.every(Boolean) : checks.some(Boolean)
      })
    }

    const col = tab.sortColumn
    const dir = tab.sortDir === 'asc' ? 1 : -1
    return [...filtered].sort((a, b) => {
      const av = a[col] ?? 0
      const bv = b[col] ?? 0
      if (typeof av === 'string' && typeof bv === 'string') return av.localeCompare(bv) * dir
      return ((av as number) - (bv as number)) * dir
    })
  }, [tab.results, tab.filters, tab.filterMode, tab.matchers, tab.matcherMode, tab.sortColumn, tab.sortDir])

  // Fetch result detail when selectedIndex changes
  useEffect(() => {
    if (tab.selectedIndex === null || !tab.campaignId) return
    store.setSelectedDetailLoading(true)
    api.fuzzGetResult(tab.campaignId, tab.selectedIndex)
      .then((detail) => store.setSelectedDetail(detail))
      .catch(() => store.setSelectedDetail(null))
  }, [tab.selectedIndex, tab.campaignId]) // eslint-disable-line

  async function handleStart() {
    if (!canStart) return
    const rawToSend = tab.updateContentLength ? updateContentLengthInRaw(tab.rawReq) : tab.rawReq
    if (rawToSend !== tab.rawReq) store.setRawReq(rawToSend)
    store.reset()
    store.setStatus('running')
    try {
      const enabledMatchers = tab.matchers.filter(m => m.enabled).map(m => ({ type: m.type, value: m.value }))
      const enabledFilters = tab.filters.filter(f => f.enabled).map(f => ({ type: f.type, value: f.value }))

      const baseParams = {
        raw: b64Encode(rawToSend),
        scheme: tab.scheme,
        host: tab.host,
        threads: tab.concurrency,
        rateLimit: tab.rateLimit,
        followRedirects: tab.followRedirects,
        updateContentLength: tab.updateContentLength,
        matchers: enabledMatchers,
        filters: enabledFilters,
        matcherMode: tab.matcherMode,
        filterMode: tab.filterMode,
        maxStoredBodies: tab.maxStoredBodies,
      }

      let res: { campaignId: string; total: number }
      if (!isMultiPosition) {
        // Single-position
        res = await api.fuzzStart({
          ...baseParams,
          wordlist: wordlistLines,
          fuzzKeyword: tab.fuzzKeyword || 'FUZZ',
        })
      } else if (tab.attackMode === 'spray') {
        // Multi-position spray: same wordlist for all
        res = await api.fuzzStart({
          ...baseParams,
          wordlist: wordlistLines,
          attackMode: 'spray',
        })
      } else {
        // Multi-position split/yolo: per-position wordlists
        const wordlists: Record<string, string[]> = {}
        for (const pw of tab.positionWordlists) {
          wordlists[pw.position] = pw.wordlist.split('\n').filter(l => l.trim() !== '')
        }
        res = await api.fuzzStart({
          ...baseParams,
          wordlists,
          attackMode: tab.attackMode,
        })
      }

      store.setCampaignId(res.campaignId)
      store.setTotalPayloads(res.total)
    } catch (e) {
      store.setStatus('idle')
    }
  }

  async function handleStop() {
    if (tab.campaignId) {
      try {
        await api.fuzzStop(tab.campaignId)
      } catch { /* ignore */ }
    }
  }

  function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => store.setWordlist(reader.result as string, file.name)
    reader.readAsText(file)
    e.target.value = ''
  }

  function handlePositionFileUpload(position: string, e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => store.setPositionWordlist(position, reader.result as string, file.name)
    reader.readAsText(file)
    e.target.value = ''
  }

  function addFuzzLocation() {
    const view = editorViewRef.current
    if (!view) return
    const sel = view.state.selection.main
    const text = view.state.doc.toString()
    const positions = detectPositions(text)
    const changes: { from: number; to: number; insert: string }[] = []

    if (positions.length === 0) {
      changes.push({ from: sel.from, to: sel.to, insert: 'FUZZ' })
    } else if (positions.length === 1 && positions[0] === 'FUZZ') {
      // Rename existing plain FUZZ → FUZZ1, insert FUZZ2 at selection
      const regex = /FUZZ(?!\d)/g
      let match
      while ((match = regex.exec(text)) !== null) {
        if (match.index >= sel.from && match.index + 4 <= sel.to) continue
        changes.push({ from: match.index, to: match.index + 4, insert: 'FUZZ1' })
      }
      changes.push({ from: sel.from, to: sel.to, insert: 'FUZZ2' })
    } else {
      let maxNum = 0
      for (const p of positions) {
        const n = parseInt(p.replace('FUZZ', ''))
        if (!isNaN(n) && n > maxNum) maxNum = n
      }
      changes.push({ from: sel.from, to: sel.to, insert: `FUZZ${maxNum + 1}` })
    }

    changes.sort((a, b) => a.from - b.from)
    view.dispatch({ changes })
    view.focus()
  }

  function removeFuzzLocation() {
    const view = editorViewRef.current
    if (!view) return
    const cursor = view.state.selection.main.from
    const text = view.state.doc.toString()

    // Find all FUZZ markers and check which one the cursor is inside
    const allMarkers: { from: number; to: number; label: string }[] = []
    const regex = /FUZZ\d*/g
    let match
    while ((match = regex.exec(text)) !== null) {
      allMarkers.push({ from: match.index, to: match.index + match[0].length, label: match[0] })
    }

    const target = allMarkers.find(m => cursor >= m.from && cursor <= m.to)
    if (!target) return

    const changes: { from: number; to: number; insert: string }[] = [
      { from: target.from, to: target.to, insert: '' },
    ]

    // If only one numbered marker will remain, rename it to plain FUZZ
    const remaining = allMarkers.filter(m => m !== target && /FUZZ\d+/.test(m.label))
    if (remaining.length === 1) {
      changes.push({ from: remaining[0].from, to: remaining[0].to, insert: 'FUZZ' })
    }

    changes.sort((a, b) => a.from - b.from)
    view.dispatch({ changes })
    view.focus()
  }

  function clearFuzzLocations() {
    const view = editorViewRef.current
    if (!view) return
    const text = view.state.doc.toString()
    const changes: { from: number; to: number; insert: string }[] = []
    const regex = /FUZZ\d*/g
    let match
    while ((match = regex.exec(text)) !== null) {
      changes.push({ from: match.index, to: match.index + match[0].length, insert: '' })
    }
    if (changes.length === 0) return
    view.dispatch({ changes })
    view.focus()
  }

  function sendToManipulate() {
    navigate('/manipulate', { state: { scheme: tab.scheme, host: tab.host, rawReq: b64Encode(tab.rawReq) } })
  }

  function getRequestUrl(): string {
    const firstLine = tab.rawReq.split('\n')[0] || ''
    const path = firstLine.split(/\s+/)[1] || '/'
    return `${tab.scheme}://${tab.host}${path}`
  }

  function copyUrl() {
    copyText(getRequestUrl())
  }

  function copyCurl() {
    copyText(rawToCurl(tab.rawReq, getRequestUrl()))
  }

  function copyRawRequest() {
    copyText(tab.rawReq)
  }

  function toggleSort(col: FuzzSortColumn) {
    if (tab.sortColumn === col) {
      store.setSort(col, tab.sortDir === 'asc' ? 'desc' : 'asc')
    } else {
      store.setSort(col, 'asc')
    }
  }

  const sortArrow = (col: FuzzSortColumn): ReactNode => {
    if (tab.sortColumn !== col) return null
    return tab.sortDir === 'asc'
      ? <ChevronUp size={11} className="inline ml-0.5 align-[-1px]" />
      : <ChevronDown size={11} className="inline ml-0.5 align-[-1px]" />
  }

  const pct = tab.totalPayloads > 0 ? (tab.completedPayloads / tab.totalPayloads) * 100 : 0

  // Determine which wordlist panel to show
  const showSingleWordlist = !isMultiPosition || tab.attackMode === 'spray'
  const activeWlTab = tab.selectedPositionTab || (tab.positionWordlists[0]?.position ?? '')
  const activePositionWl = tab.positionWordlists.find(pw => pw.position === activeWlTab)

  function payloadTooltip(r: { payload: string; payloads?: Record<string, string> }): string {
    if (!r.payloads) return r.payload
    return Object.entries(r.payloads).map(([k, v]) => `${k}: ${v}`).join('\n')
  }

  const hasDetail = tab.selectedIndex !== null

  return (
    <div className="flex flex-col flex-1 min-h-0">
      {/* Tab bar */}
      <div className="flex items-center border-b border-border bg-surface-card shrink-0 overflow-x-auto">
        {tabs.map((t) => (
          <div
            key={t.id}
            className={`flex items-center gap-1 px-3 py-1.5 text-xs cursor-pointer border-b-2 shrink-0 ${
              t.id === activeTabId
                ? 'text-accent border-accent'
                : 'text-content-muted hover:text-content-secondary border-transparent'
            }`}
            onClick={() => setActiveTab(t.id)}
            onDoubleClick={() => { setEditingTabId(t.id); setEditName(t.name) }}
          >
            {t.status === 'running' && (
              <span className="w-1.5 h-1.5 rounded-full bg-accent-secondary animate-pulse" />
            )}
            {editingTabId === t.id ? (
              <input
                ref={renameInputRef}
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
                onBlur={commitRename}
                onKeyDown={(e) => { if (e.key === 'Enter') commitRename(); if (e.key === 'Escape') setEditingTabId(null) }}
                onClick={(e) => e.stopPropagation()}
                className="bg-surface-input text-xs px-1 py-0 rounded-sm border border-border w-16 outline-none"
              />
            ) : (
              <span>{t.name}</span>
            )}
            {tabs.length > 1 && (
              <button
                onClick={(e) => { e.stopPropagation(); removeTab(t.id) }}
                className="text-content-muted hover:text-semantic-error ml-1 leading-none inline-flex items-center"
              >
                <X size={12} />
              </button>
            )}
          </div>
        ))}
        {tabs.length < MAX_TABS && (
          <button
            onClick={() => addTab()}
            className="px-2 py-1.5 text-xs text-content-muted hover:text-content-secondary shrink-0"
          >
            +
          </button>
        )}
      </div>

      {/* Toolbar */}
      <div className="flex items-center gap-2 px-2 py-1.5 border-b border-border bg-surface-card shrink-0 flex-wrap">
        <select
          value={tab.scheme}
          onChange={(e) => store.setScheme(e.target.value)}
          className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
          disabled={isRunning}
        >
          <option value="https">HTTPS</option>
          <option value="http">HTTP</option>
        </select>
        <input
          value={tab.host}
          onChange={(e) => store.setHost(e.target.value)}
          className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border flex-1 max-w-xs"
          placeholder="host:port"
          disabled={isRunning}
        />
        <label className="text-xs text-content-muted">Threads:</label>
        <input
          type="number"
          min={1}
          max={100}
          value={tab.concurrency}
          onChange={(e) => store.setConcurrency(Math.max(1, Math.min(100, parseInt(e.target.value) || 1)))}
          className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-14"
          disabled={isRunning}
        />
        <label className="text-xs text-content-muted">Rate:</label>
        <Tooltip content="Requests per second (0 = unlimited)">
          <input
            type="number"
            min={0}
            value={tab.rateLimit}
            onChange={(e) => store.setRateLimit(Math.max(0, parseInt(e.target.value) || 0))}
            className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-16"
            placeholder="0=unlimited"
            disabled={isRunning}
          />
        </Tooltip>
        <label className="text-xs text-content-muted">Save:</label>
        <Tooltip content="Max results to store full request/response for">
          <input
            type="number"
            min={0}
            value={tab.maxStoredBodies}
            onChange={(e) => store.setMaxStoredBodies(Math.max(0, parseInt(e.target.value) || 0))}
            className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-16"
            disabled={isRunning}
          />
        </Tooltip>
        {/* Attack mode selector (multi-position only) */}
        {isMultiPosition && (
          <div className="flex items-center gap-0.5">
            {ATTACK_MODES.map((mode) => (
              <Tooltip key={mode.value} content={mode.title}>
                <button
                  onClick={() => store.setAttackMode(mode.value)}
                  disabled={isRunning}
                  className={`px-2 py-1 text-[10px] rounded-sm font-semibold ${
                    tab.attackMode === mode.value
                      ? 'bg-accent text-content-primary'
                      : 'bg-surface-input text-content-secondary hover:bg-surface-hover'
                  } disabled:opacity-50`}
                >
                  {mode.label}
                </button>
              </Tooltip>
            ))}
          </div>
        )}
        {!isRunning ? (
          <button
            onClick={handleStart}
            disabled={!canStart}
            className="text-xs px-4 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black font-semibold disabled:opacity-50"
          >
            Start
          </button>
        ) : (
          <button
            onClick={handleStop}
            className="text-xs px-4 py-1.5 rounded-sm bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary font-semibold"
          >
            Stop
          </button>
        )}
      </div>

      {/* Position & total info bar (multi-position only) */}
      {isMultiPosition && (
        <div className="flex items-center gap-2 px-2 py-0.5 border-b border-border bg-surface-card shrink-0">
          <span className="text-[10px] text-content-muted">
            Positions: {detectedPositions.join(', ')}
          </span>
          {canStart && (
            <span className="text-[10px] text-content-secondary">
              — Est. {formatNumber(estimatedTotal)} requests
            </span>
          )}
        </div>
      )}

      {/* Main content: vertical split */}
      <div className="flex flex-col flex-1 overflow-hidden min-h-0" ref={vSplit.containerRef}>
        {/* Top half: editor + wordlist */}
        <div className="flex overflow-hidden min-h-0" style={{ flex: vSplit.fraction }}>
          <div className="flex overflow-hidden min-h-0 flex-1" ref={hSplit.containerRef}>
            {/* Request editor */}
            <div className="flex flex-col overflow-hidden min-h-0" style={{ flex: hSplit.fraction }}>
              <div className="flex items-center gap-1 px-2 py-1 bg-surface-card border-b border-border shrink-0">
                <span className="text-xs text-content-muted">Request</span>
                <div className="flex items-center gap-1 ml-1">
                  <Tooltip content="Add fuzz position at selection">
                    <button
                      onClick={addFuzzLocation}
                      disabled={isRunning}
                      className="text-[10px] px-1.5 py-0.5 rounded-sm bg-surface-input text-accent-secondary hover:bg-surface-hover font-semibold disabled:opacity-50"
                    >
                      Add
                    </button>
                  </Tooltip>
                  <Tooltip content="Remove fuzz position at cursor">
                    <button
                      onClick={removeFuzzLocation}
                      disabled={isRunning || detectedPositions.length === 0}
                      className="text-[10px] px-1.5 py-0.5 rounded-sm bg-surface-input text-content-secondary hover:bg-surface-hover font-semibold disabled:opacity-50"
                    >
                      Remove
                    </button>
                  </Tooltip>
                  <Tooltip content="Clear all fuzz positions">
                    <button
                      onClick={clearFuzzLocations}
                      disabled={isRunning || detectedPositions.length === 0}
                      className="text-[10px] px-1.5 py-0.5 rounded-sm bg-surface-input text-content-secondary hover:bg-surface-hover font-semibold disabled:opacity-50"
                    >
                      Clear
                    </button>
                  </Tooltip>
                </div>
                <div className="flex items-center gap-1 ml-auto">
                  <SquareToggle label={<WrapText size={12} />} title="Line wrapping" active={tab.wrapReq} onClick={() => store.setWrapReq(!tab.wrapReq)} />
                  <SquareToggle label="CL" title="Auto-update Content-Length" active={tab.updateContentLength} onClick={() => store.setUpdateContentLength(!tab.updateContentLength)} />
                  <SquareToggle label={<Pilcrow size={12} />} title="Show non-printable characters" active={tab.showNonPrintable} onClick={() => store.setShowNonPrintable(!tab.showNonPrintable)} />
                  <SquareToggle label={<CornerDownRight size={12} />} title="Follow redirects" active={tab.followRedirects} onClick={() => store.setFollowRedirects(!tab.followRedirects)} />
                </div>
              </div>
              <div className="flex-1 relative min-h-0">
                <div className="absolute inset-0 overflow-hidden">
                  <CodeMirror
                    value={tab.rawReq}
                    theme={oneDark}
                    height="100%"
                    onChange={(v) => store.setRawReq(v)}
                    onCreateEditor={(view) => { editorViewRef.current = view }}
                    extensions={reqExtensions}
                    basicSetup={{ lineNumbers: true, foldGutter: false }}
                    readOnly={isRunning}
                  />
                </div>
              </div>
            </div>

            {/* Horizontal drag handle */}
            <div className="drag-handle-h" onMouseDown={hSplit.onMouseDown} />

            {/* Wordlist panel */}
            <div className="flex flex-col overflow-hidden min-h-0" style={{ flex: 1 - hSplit.fraction }}>
              {showSingleWordlist ? (
                <>
                  {/* Single wordlist header */}
                  <div className="flex items-center gap-1 px-2 py-1 bg-surface-card border-b border-border shrink-0">
                    <span className="text-xs text-content-muted">
                      Wordlist ({formatNumber(wordlistLines.length)} payloads)
                    </span>
                    {tab.wordlistFileName && (
                      <span className="text-xs text-content-secondary ml-1 truncate max-w-32">{tab.wordlistFileName}</span>
                    )}
                    <div className="flex items-center gap-1 ml-auto">
                      <label className="text-xs px-2 py-0.5 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary cursor-pointer">
                        Upload
                        <input
                          ref={fileInputRef}
                          type="file"
                          accept=".txt,.lst,.list,.wordlist,text/*"
                          onChange={handleFileUpload}
                          className="hidden"
                          disabled={isRunning}
                        />
                      </label>
                      {tab.wordlist && (
                        <Tooltip content="Clear wordlist">
                          <button
                            onClick={() => store.setWordlist('')}
                            className="text-xs text-content-muted hover:text-semantic-error px-1 inline-flex items-center"
                            disabled={isRunning}
                          >
                            <X size={12} />
                          </button>
                        </Tooltip>
                      )}
                    </div>
                  </div>
                  <textarea
                    value={tab.wordlist}
                    onChange={(e) => store.setWordlist(e.target.value)}
                    className="flex-1 bg-surface-input text-xs font-mono px-2 py-1 resize-none outline-none text-content-primary"
                    placeholder="Paste wordlist here (one payload per line) or upload a file..."
                    readOnly={isRunning}
                    spellCheck={false}
                  />
                </>
              ) : (
                <>
                  {/* Multi-position wordlist tabs */}
                  <div className="flex items-center bg-surface-card border-b border-border shrink-0 overflow-x-auto">
                    {tab.positionWordlists.map((pw, idx) => {
                      const lines = pw.wordlist.split('\n').filter(l => l.trim()).length
                      return (
                        <button
                          key={pw.position}
                          onClick={() => store.setSelectedPositionTab(pw.position)}
                          className={`flex items-center gap-1 px-3 py-1 text-xs border-b-2 shrink-0 ${
                            activeWlTab === pw.position
                              ? 'text-content-primary border-accent'
                              : 'text-content-muted hover:text-content-secondary border-transparent'
                          }`}
                        >
                          <span
                            className="inline-block w-2 h-2 rounded-sm"
                            style={{ background: positionTabColor(idx) }}
                          />
                          {pw.position}
                          <span className="text-[10px] text-content-muted">({lines})</span>
                        </button>
                      )
                    })}
                  </div>
                  {/* Active position wordlist */}
                  {activePositionWl && (
                    <>
                      <div className="flex items-center gap-1 px-2 py-1 bg-surface-card border-b border-border shrink-0">
                        <span className="text-xs text-content-muted">
                          {activeWlTab} ({formatNumber(activePositionWl.wordlist.split('\n').filter(l => l.trim()).length)} payloads)
                        </span>
                        {activePositionWl.wordlistFileName && (
                          <span className="text-xs text-content-secondary ml-1 truncate max-w-32">{activePositionWl.wordlistFileName}</span>
                        )}
                        <div className="flex items-center gap-1 ml-auto">
                          <label className="text-xs px-2 py-0.5 rounded-sm bg-surface-input hover:bg-surface-hover text-content-secondary cursor-pointer">
                            Upload
                            <input
                              ref={posFileInputRef}
                              type="file"
                              accept=".txt,.lst,.list,.wordlist,text/*"
                              onChange={(e) => handlePositionFileUpload(activeWlTab, e)}
                              className="hidden"
                              disabled={isRunning}
                            />
                          </label>
                          {activePositionWl.wordlist && (
                            <Tooltip content="Clear wordlist">
                              <button
                                onClick={() => store.setPositionWordlist(activeWlTab, '')}
                                className="text-xs text-content-muted hover:text-semantic-error px-1 inline-flex items-center"
                                disabled={isRunning}
                              >
                                <X size={12} />
                              </button>
                            </Tooltip>
                          )}
                        </div>
                      </div>
                      <textarea
                        value={activePositionWl.wordlist}
                        onChange={(e) => store.setPositionWordlist(activeWlTab, e.target.value)}
                        className="flex-1 bg-surface-input text-xs font-mono px-2 py-1 resize-none outline-none text-content-primary"
                        placeholder={`Paste wordlist for ${activeWlTab} (one payload per line) or upload a file...`}
                        readOnly={isRunning}
                        spellCheck={false}
                      />
                    </>
                  )}
                </>
              )}
            </div>
          </div>
        </div>

        {/* Vertical drag handle */}
        <div className="drag-handle-v" onMouseDown={vSplit.onMouseDown} />

        {/* Bottom half: progress + config + results + detail */}
        <div className="flex flex-col overflow-hidden min-h-0" style={{ flex: 1 - vSplit.fraction }}>
          {/* Progress bar */}
          {(isRunning || tab.status === 'completed' || tab.status === 'stopped') && (
            <div className="shrink-0 border-b border-border bg-surface-card">
              <div className="flex items-center gap-2 px-2 py-1">
                <div className="flex-1 h-1.5 bg-surface-input rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 rounded-full ${
                      tab.status === 'completed' ? 'bg-semantic-success' :
                      tab.status === 'stopped' ? 'bg-semantic-warning' :
                      'bg-accent-secondary'
                    }`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <span className="text-[10px] text-content-muted shrink-0">
                  {formatNumber(tab.completedPayloads)} / {formatNumber(tab.totalPayloads)}
                  {' '}({pct.toFixed(1)}%)
                  {speed > 0 && isRunning && ` — ~${formatNumber(speed)} req/s`}
                </span>
                <span className={`text-[10px] font-semibold ${
                  tab.status === 'completed' ? 'text-semantic-success' :
                  tab.status === 'stopped' ? 'text-semantic-warning' :
                  'text-accent-secondary'
                }`}>
                  {tab.status === 'completed' ? 'Done' :
                   tab.status === 'stopped' ? 'Stopped' : 'Running'}
                </span>
                <Tooltip content="Matchers & Filters">
                  <button
                    onClick={store.toggleConfigPanel}
                    className={`text-xs px-1.5 py-0.5 rounded-sm inline-flex items-center ${tab.configPanelOpen ? 'bg-accent text-content-primary' : 'bg-surface-input text-content-secondary hover:bg-surface-hover'}`}
                  >
                    <Settings size={13} />
                  </button>
                </Tooltip>
              </div>
            </div>
          )}

          {/* Config panel (collapsible) */}
          {tab.configPanelOpen && (
            <div className="shrink-0 border-b border-border bg-surface-card px-2 py-1.5 overflow-y-auto max-h-48">
              <FilterSection
                title="Filters (hide matching)"
                borderColor="border-semantic-error"
                rules={tab.filters}
                mode={tab.filterMode}
                onModeChange={store.setFilterMode}
                onAdd={() => store.addFilter({ id: String(Date.now()), type: 'status', value: '', enabled: true })}
                onUpdate={store.updateFilter}
                onRemove={store.removeFilter}
              />
              <FilterSection
                title="Matchers (show only matching)"
                borderColor="border-semantic-success"
                rules={tab.matchers}
                mode={tab.matcherMode}
                onModeChange={store.setMatcherMode}
                onAdd={() => store.addMatcher({ id: String(Date.now()), type: 'status', value: '', enabled: true })}
                onUpdate={store.updateMatcher}
                onRemove={store.removeMatcher}
              />
            </div>
          )}

          {/* Results count */}
          <div className="flex items-center gap-2 px-2 py-1 bg-surface-card border-b border-border shrink-0">
            <span className="text-[10px] text-content-muted">
              Showing {formatNumber(visibleResults.length)} of {formatNumber(tab.results.length)} results
            </span>
            {tab.results.length > 0 && !isRunning && (
              <button
                onClick={() => store.reset()}
                className="text-[10px] text-semantic-error hover:underline ml-auto"
              >
                Clear
              </button>
            )}
          </div>

          {/* Results table + detail panel */}
          <div className="flex flex-1 overflow-hidden min-h-0" ref={detailSplit.containerRef}>
            {/* Results table */}
            <div className="overflow-auto min-h-0" style={{ flex: hasDetail ? detailSplit.fraction : 1 }}>
              <table className="w-full text-xs">
                <thead className="sticky top-0 bg-surface-card z-10">
                  <tr className="border-b border-border">
                    <th className="px-2 py-1 text-left w-12 cursor-pointer select-none text-content-muted" onClick={() => toggleSort('index')}>#{sortArrow('index')}</th>
                    <th className="px-2 py-1 text-left cursor-pointer select-none text-content-muted" onClick={() => toggleSort('payload')}>Payload{sortArrow('payload')}</th>
                    <th className="px-2 py-1 text-left w-16 cursor-pointer select-none text-content-muted" onClick={() => toggleSort('statusCode')}>Status{sortArrow('statusCode')}</th>
                    <th className="px-2 py-1 text-right w-16 cursor-pointer select-none text-content-muted" onClick={() => toggleSort('size')}>Size{sortArrow('size')}</th>
                    <th className="px-2 py-1 text-right w-16 cursor-pointer select-none text-content-muted" onClick={() => toggleSort('words')}>Words{sortArrow('words')}</th>
                    <th className="px-2 py-1 text-right w-16 cursor-pointer select-none text-content-muted" onClick={() => toggleSort('lines')}>Lines{sortArrow('lines')}</th>
                    <th className="px-2 py-1 text-right w-16 cursor-pointer select-none text-content-muted" onClick={() => toggleSort('durationMs')}>ms{sortArrow('durationMs')}</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleResults.map((r) => (
                    <tr
                      key={r.index}
                      className={`border-b border-border-subtle hover:bg-surface-hover cursor-pointer ${
                        tab.selectedIndex === r.index ? 'bg-surface-hover' : ''
                      }`}
                      onClick={() => store.setSelectedIndex(tab.selectedIndex === r.index ? null : r.index)}
                    >
                      <td className="px-2 py-1 text-content-muted text-right">{r.index}</td>
                      <td className="px-2 py-1 text-content-primary truncate max-w-xs" title={payloadTooltip(r)}>
                        {r.error ? (
                          <span className="text-semantic-error">{r.payload} <span className="text-[10px]">({r.error})</span></span>
                        ) : r.payload}
                      </td>
                      <td className="px-2 py-1">
                        <StatusBadge status={r.statusCode} />
                      </td>
                      <td className="px-2 py-1 text-right text-content-secondary">{formatSize(r.size)}</td>
                      <td className="px-2 py-1 text-right text-content-secondary">{r.words}</td>
                      <td className="px-2 py-1 text-right text-content-secondary">{r.lines}</td>
                      <td className="px-2 py-1 text-right text-content-secondary">{r.durationMs}</td>
                    </tr>
                  ))}
                  {visibleResults.length === 0 && tab.status !== 'running' && (
                    <tr>
                      <td colSpan={7} className="px-2 py-8 text-center text-content-muted text-xs">
                        {tab.results.length === 0 ? 'No results yet. Configure a request with FUZZ keyword and start fuzzing.' : 'All results filtered out.'}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Detail panel (right side, shown when a result is selected) */}
            {hasDetail && (
              <>
                <div className="drag-handle-h" onMouseDown={detailSplit.onMouseDown} />
                <div className="flex flex-col min-h-0 overflow-hidden" style={{ flex: 1 - detailSplit.fraction }}>
                  {tab.selectedDetailLoading ? (
                    <div className="flex-1 flex items-center justify-center text-content-muted text-xs">
                      Loading...
                    </div>
                  ) : tab.selectedDetail ? (
                    tab.selectedDetail.hasBody ? (
                      /* Request / Response split */
                      <div className="flex flex-1 min-h-0 overflow-hidden" ref={detailHSplit.containerRef}>
                        {/* Request panel */}
                        <div className="flex flex-col min-h-0 overflow-hidden" style={{ flex: detailHSplit.fraction }}>
                          <div className="flex items-center gap-1 px-2 py-1 border-b border-border bg-surface-card shrink-0">
                            <span className="text-xs font-semibold text-content-primary">Request</span>
                            <div className="flex items-center gap-1 ml-auto">
                              <SquareToggle label={<WrapText size={12} />} title="Line wrapping" active={wrapDetailReq} onClick={() => setWrapDetailReq(w => !w)} />
                            </div>
                          </div>
                          <div className="flex-1 relative min-h-0">
                            <div className="absolute inset-0 overflow-hidden">
                              <CodeMirror
                                value={tab.selectedDetail.reqRaw ? b64Decode(tab.selectedDetail.reqRaw) : ''}
                                theme={oneDark}
                                readOnly={true}
                                height="100%"
                                extensions={wrapDetailReq ? [EditorView.lineWrapping] : []}
                                basicSetup={{ lineNumbers: true, foldGutter: false }}
                              />
                            </div>
                          </div>
                        </div>

                        <div className="drag-handle-h" onMouseDown={detailHSplit.onMouseDown} />

                        {/* Response panel */}
                        <div className="flex flex-col min-h-0 overflow-hidden" style={{ flex: 1 - detailHSplit.fraction }}>
                          <div className="flex items-center gap-1 px-2 py-1 border-b border-border bg-surface-card shrink-0">
                            <span className="text-xs font-semibold text-content-primary">Response</span>
                            <div className="flex items-center gap-0.5 ml-2">
                              <button
                                onClick={() => setRespTab('raw')}
                                className={`px-2 py-0.5 rounded-sm text-[10px] font-semibold transition-colors ${
                                  respTab === 'raw'
                                    ? 'bg-accent text-content-primary'
                                    : 'text-content-secondary hover:text-content-primary hover:bg-surface-input'
                                }`}
                              >
                                Raw
                              </button>
                              <button
                                onClick={() => setRespTab('render')}
                                className={`px-2 py-0.5 rounded-sm text-[10px] font-semibold transition-colors ${
                                  respTab === 'render'
                                    ? 'bg-accent text-content-primary'
                                    : 'text-content-secondary hover:text-content-primary hover:bg-surface-input'
                                }`}
                              >
                                Render
                              </button>
                            </div>
                            <div className="flex items-center gap-1 ml-auto">
                              {respTab === 'raw' ? (
                                <SquareToggle label={<WrapText size={12} />} title="Line wrapping" active={wrapDetailResp} onClick={() => setWrapDetailResp(w => !w)} />
                              ) : (
                                <SquareToggle label="{ }" title="Pretty-print JSON" active={prettyJson} onClick={() => setPrettyJson(!prettyJson)} />
                              )}
                            </div>
                          </div>
                          <div className="flex-1 relative min-h-0">
                            {respTab === 'raw' ? (
                              <div className="absolute inset-0 overflow-hidden">
                                <CodeMirror
                                  value={tab.selectedDetail.respRaw ? b64Decode(tab.selectedDetail.respRaw) : ''}
                                  theme={oneDark}
                                  readOnly={true}
                                  height="100%"
                                  extensions={wrapDetailResp ? [EditorView.lineWrapping] : []}
                                  basicSetup={{ lineNumbers: true, foldGutter: false }}
                                />
                              </div>
                            ) : tab.selectedDetail.respRaw ? (
                              <ResponseRender raw={b64Decode(tab.selectedDetail.respRaw)} prettyJson={prettyJson} />
                            ) : null}
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="flex-1 flex items-center justify-center text-content-muted text-xs px-4 text-center">
                        Request/response not stored for this result.<br />
                        Increase the "Save" limit to capture more.
                      </div>
                    )
                  ) : (
                    <div className="flex-1 flex items-center justify-center text-content-muted text-xs">
                      Select a result to view details
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      </div>
      {ctxMenu && (
        <ContextMenu x={ctxMenu.x} y={ctxMenu.y} onClose={handleCloseCtxMenu} items={[
          ...getSelectionMenuItems(navigate),
          { label: 'Manipulate', onClick: sendToManipulate },
          { label: 'Add Position', onClick: addFuzzLocation, disabled: isRunning },
          { label: 'Remove Position', onClick: removeFuzzLocation, disabled: isRunning },
          { label: 'Clear Positions', onClick: clearFuzzLocations, disabled: isRunning || detectedPositions.length === 0 },
          { label: 'Copy URL', onClick: copyUrl },
          { label: 'Copy as curl', onClick: copyCurl },
          { label: 'Copy Raw Request', onClick: copyRawRequest },
        ]} />
      )}
    </div>
  )
}

// Color for position tab indicators (matches CSS highlight classes)
function positionTabColor(idx: number): string {
  const colors = ['var(--color-accent)', 'var(--color-accent-secondary)', '#FF7F11', '#BF1363', 'var(--color-accent-tertiary)', '#FFBA49']
  return colors[idx % colors.length]
}

function StatusBadge({ status }: { status: number }) {
  if (!status) return <span className="text-content-muted">-</span>
  const color = status < 300 ? 'text-semantic-success' :
                status < 400 ? 'text-semantic-warning' :
                status < 500 ? 'text-accent' : 'text-semantic-error'
  return <span className={color}>{status}</span>
}

function SquareToggle({ label, title, active, onClick }: { label: ReactNode; title: string; active: boolean; onClick: () => void }) {
  return (
    <Tooltip content={title}>
      <button
        onClick={onClick}
        className={`w-6 h-5 flex items-center justify-center text-[10px] rounded-sm font-semibold leading-none ${
          active ? 'bg-accent text-content-primary' : 'bg-surface-input text-content-secondary hover:bg-surface-hover'
        }`}
      >
        {label}
      </button>
    </Tooltip>
  )
}

function FilterSection({ title, borderColor, rules, mode, onModeChange, onAdd, onUpdate, onRemove }: {
  title: string
  borderColor: string
  rules: MatchFilterRule[]
  mode: 'or' | 'and'
  onModeChange: (mode: 'or' | 'and') => void
  onAdd: () => void
  onUpdate: (id: string, updates: Partial<MatchFilterRule>) => void
  onRemove: (id: string) => void
}) {
  return (
    <div className={`border-l-2 ${borderColor} pl-2 mb-2`}>
      <div className="flex items-center gap-2 mb-1">
        <span className="text-[10px] text-content-muted font-semibold">{title}</span>
        <div className="flex items-center gap-0.5 ml-auto">
          <button
            onClick={() => onModeChange('or')}
            className={`px-1.5 py-0.5 text-[10px] rounded-sm ${mode === 'or' ? 'bg-accent text-content-primary' : 'bg-surface-input text-content-secondary'}`}
          >
            OR
          </button>
          <button
            onClick={() => onModeChange('and')}
            className={`px-1.5 py-0.5 text-[10px] rounded-sm ${mode === 'and' ? 'bg-accent text-content-primary' : 'bg-surface-input text-content-secondary'}`}
          >
            AND
          </button>
        </div>
      </div>
      {rules.map((rule) => (
        <div key={rule.id} className="flex items-center gap-1 mb-0.5">
          <input
            type="checkbox"
            checked={rule.enabled}
            onChange={(e) => onUpdate(rule.id, { enabled: e.target.checked })}
            className="w-3 h-3"
          />
          <select
            value={rule.type}
            onChange={(e) => onUpdate(rule.id, { type: e.target.value as FilterType })}
            className="bg-surface-input text-[10px] px-1 py-0.5 rounded-sm border border-border"
          >
            <option value="status">Status</option>
            <option value="size">Size</option>
            <option value="words">Words</option>
            <option value="lines">Lines</option>
            <option value="regex">Regex</option>
          </select>
          <input
            value={rule.value}
            onChange={(e) => onUpdate(rule.id, { value: e.target.value })}
            className="bg-surface-input text-[10px] px-1 py-0.5 rounded-sm border border-border flex-1 max-w-24"
            placeholder={rule.type === 'regex' ? 'pattern' : 'e.g. 200,301'}
          />
          <button
            onClick={() => onRemove(rule.id)}
            className="text-content-muted hover:text-semantic-error text-xs px-0.5 inline-flex items-center"
          >
            <X size={12} />
          </button>
        </div>
      ))}
      <button
        onClick={onAdd}
        className="text-[10px] text-accent-secondary hover:text-accent-secondary-hover"
      >
        + Add
      </button>
    </div>
  )
}

// Client-side match evaluation (mirrors backend logic)
function matchesRule(r: { statusCode: number; size: number; words: number; lines: number }, rule: MatchFilterRule): boolean {
  const val = rule.value.trim()
  if (!val) return false
  switch (rule.type) {
    case 'status':
      return val.split(',').some(s => parseInt(s.trim()) === r.statusCode)
    case 'size':
      return val.split(',').some(s => parseInt(s.trim()) === r.size)
    case 'words':
      return val.split(',').some(s => parseInt(s.trim()) === r.words)
    case 'lines':
      return val.split(',').some(s => parseInt(s.trim()) === r.lines)
    case 'regex':
      try { return new RegExp(val).test(String(r.statusCode)) } catch { return false }
    default:
      return false
  }
}
