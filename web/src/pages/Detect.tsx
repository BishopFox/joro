import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { useNavigate } from 'react-router'
import {
  ChevronDown,
  ChevronUp,
  Eye,
  EyeOff,
  Radio,
  Scan,
  ShieldAlert,
  Trash2,
  WrapText,
} from 'lucide-react'
import CodeMirror from '@uiw/react-codemirror'
import {
  Decoration,
  EditorView,
  ViewPlugin,
  type DecorationSet,
  type ViewUpdate,
} from '@codemirror/view'
import type { Range } from '@codemirror/state'
import { oneDark } from '@codemirror/theme-one-dark'
import { api, type ActiveScanRun, type ActiveScanRule, type SignatureCatalogItem } from '../lib/api'
import { useActiveScanStore } from '../stores/activeScanStore'
import { ResponseRender, usePrettyJson } from '../components/ResponseRender'
import LensOutput from '../components/LensOutput'
import TabButton from '../components/TabButton'
import { useLenses } from '../lib/lenses'
import { rawToCurl } from '../lib/httpTransform'
import { copyText } from '../lib/clipboard'
import { useResizable } from '../lib/useResizable'
import ContextMenu, { type MenuItem } from '../components/ContextMenu'
import ConfirmModal from '../components/ConfirmModal'
import DetectRuleModal from '../components/DetectRuleModal'
import SignatureDetail from '../components/SignatureDetail'
import RuleTableSection, { type RuleGroupVM } from '../components/RuleTableSection'
import MultiSelectDropdown from '../components/MultiSelectDropdown'
import { Tooltip } from '../components/Tooltip'
import { getSelectionMenuItems } from '../lib/selectionMenu'
import { useToastStore } from '../stores/toastStore'
import { useDeadDropStore } from '../stores/deadDropStore'
import type { RequestDetail } from '../stores/requestStore'
import {
  useDetectStore,
  type DetectRule,
  type Finding,
  type FindingSortColumn,
} from '../stores/detectStore'
import { buildFindingQuery, CATEGORY_OPTIONS } from '../lib/detectFilters'
import {
  categoryPill,
  severityBadge,
  severityTextClass,
  SEVERITY_OPTIONS,
  SEVERITY_ORDER,
  type Severity,
} from '../lib/severity'

// b64Decode mirrors the helper in History and Fuzz. atob yields one JS character
// per byte, so the decoded string is byte-indexed.
function b64Decode(b64: string): string {
  try {
    return atob(b64)
  } catch {
    return ''
  }
}

// byteOffsetToPos converts a byte offset in the raw message into a CodeMirror
// document position. The two differ: atob gives one character per byte, but
// EditorState.create splits the doc on /\r\n?|\n/ and rejoins with "\n"
// (@codemirror/state, DefaultSplit), so every CRLF collapses to one character
// and a CRLF-framed message is short by one per header line. A lone \r is also a
// split point but becomes one \n, so it costs nothing.
function byteOffsetToPos(raw: string, byteOff: number): number {
  let crlf = 0
  for (let i = raw.indexOf('\r\n'); i >= 0 && i < byteOff; i = raw.indexOf('\r\n', i + 2)) {
    crlf++
  }
  return byteOff - crlf
}

function methodBadge(method: string): ReactNode {
  const colors: Record<string, string> = {
    GET: 'text-semantic-info',
    POST: 'text-semantic-success',
    PUT: 'text-semantic-warning',
    DELETE: 'text-semantic-error',
    PATCH: 'text-semantic-special',
  }
  return (
    <span className={`font-bold ${colors[method] ?? 'text-content-secondary'}`}>{method}</span>
  )
}

// shortPath renders just the path and query of a URL, keeping the table readable.
function shortPath(url: string): string {
  try {
    const u = new URL(url)
    return u.pathname + (u.search || '')
  } catch {
    return url
  }
}

function formatTime(iso: string): string {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  return d.toISOString().slice(11, 19)
}

// Collapsed rule categories persist to localStorage, as the findings sort order
// does.
// Tracks which groups the operator has opened. Default-empty means every group
// (active and passive) starts collapsed; their choices then persist.
const EXPANDED_KEY = 'joro-detect-expanded'

function loadExpanded(): Set<string> {
  try {
    const raw = localStorage.getItem(EXPANDED_KEY)
    if (raw) return new Set(JSON.parse(raw) as string[])
  } catch {
    // Ignore malformed storage and start all-collapsed.
  }
  return new Set()
}

function persistExpanded(v: Set<string>) {
  try {
    localStorage.setItem(EXPANDED_KEY, JSON.stringify([...v]))
  } catch {
    // Storage is best-effort.
  }
}

// Active techniques are grouped into families in the Active Rules tab. Family is a
// UI-only mapping from a rule's finding category; unmapped → "Other".
const ACTIVE_FAMILY: Record<string, string> = {
  'reflected-xss': 'Injection',
  sqli: 'Injection',
  ssti: 'Injection',
  'command-injection': 'Injection',
  'open-redirect': 'Injection',
  'path-traversal': 'Injection',
  template: 'Signatures',
  'dom-xss': 'Browser-driven',
}
const ACTIVE_FAMILY_ORDER = ['Injection', 'Signatures', 'Browser-driven', 'Other']

// evidenceHighlightPlugin marks the matched evidence inside the raw view.
//
// The backend offset is preferred over a text search, which mis-highlights when
// the evidence appears more than once. The offset is translated out of byte
// space and then verified against the document; a range that does not contain
// the evidence falls back to a text search.
//
// `verify` is off for analyzer findings, whose Evidence is a synthesized
// description rather than a slice of the document — basic-auth-header points at
// the base64 credential while its evidence reads as prose.
function evidenceHighlightPlugin(
  raw: string,
  evidence: string,
  offset: number,
  length: number,
  verify: boolean
) {
  return ViewPlugin.fromClass(
    class {
      decorations: DecorationSet
      constructor(view: EditorView) {
        this.decorations = this.build(view)
      }
      update(update: ViewUpdate) {
        if (update.docChanged || update.viewportChanged) this.decorations = this.build(update.view)
      }
      build(view: EditorView): DecorationSet {
        const ranges: Range<Decoration>[] = []
        const docLen = view.state.doc.length
        const mark = Decoration.mark({ class: 'cm-detect-match' })
        // Compare in document space. Evidence is captured from the raw bytes, so
        // a match spanning a header break holds a CRLF the document does not.
        const expected = evidence.replace(/\r\n/g, '\n')

        if (offset >= 0 && length > 0) {
          // Translate both endpoints, so a match that spans a CRLF stays intact.
          const from = byteOffsetToPos(raw, offset)
          const to = byteOffsetToPos(raw, offset + length)
          const inBounds = to <= docLen && from < to
          const trusted =
            inBounds && (!verify || !expected || view.state.sliceDoc(from, to) === expected)
          if (trusted) {
            ranges.push(mark.range(from, to))
            return Decoration.set(ranges)
          }
        }
        if (expected) {
          // No usable offset, or one that failed verification: a URL rule, a
          // decompressed body, or a bad offset.
          const idx = view.state.doc.toString().indexOf(expected)
          if (idx >= 0) ranges.push(mark.range(idx, idx + expected.length))
        }
        return Decoration.set(ranges)
      }
    },
    { decorations: (v) => v.decorations }
  )
}

export default function Detect() {
  const [tab, setTab] = useState<'findings' | 'passive-rules' | 'active-rules' | 'scans'>('findings')
  const scanRunning = useActiveScanStore((s) => s.runs.some((r) => r.status === 'running'))

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <div className="flex items-center gap-0.5 px-2 py-1 bg-surface-card border-b border-border shrink-0">
        {(
          [
            ['findings', 'Findings'],
            ['passive-rules', 'Passive Rules'],
            ['active-rules', 'Active Rules'],
            ['scans', 'Scans'],
          ] as const
        ).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`px-3 py-1 rounded-sm text-xs font-semibold transition-colors ${
              tab === key
                ? 'bg-accent text-content-primary'
                : 'text-content-secondary hover:text-content-primary hover:bg-surface-input'
            }`}
          >
            {label}
            {key === 'scans' && scanRunning && (
              <span className="ml-1.5 inline-block w-1.5 h-1.5 rounded-full bg-accent-tertiary animate-pulse align-middle" />
            )}
          </button>
        ))}
      </div>
      {tab === 'findings' ? (
        <FindingsView />
      ) : tab === 'passive-rules' ? (
        <RulesView mode="passive" />
      ) : tab === 'active-rules' ? (
        <RulesView mode="active" />
      ) : (
        <ScansView />
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

function FindingsView() {
  const navigate = useNavigate()
  const addToast = useToastStore((s) => s.addToast)
  const stageDeadDrop = useDeadDropStore((s) => s.add)
  const {
    items,
    total,
    truncated,
    loading,
    selected,
    occurrences,
    selectedRule,
    selectedNotes,
    filter,
    sortColumn,
    sortDir,
    reloadCounter,
    livePaused,
    pending,
    summary,
    scan,
    enabled,
    setItems,
    setSelected,
    setSelectedDetail,
    setFilter,
    setSort,
    setLoading,
    setSummary,
    setScan,
    setEnabled,
    clearAll,
    togglePaused,
    flushPending,
    markFalsePositive,
    setNotes,
    overrideSeverity,
    removeFinding,
  } = useDetectStore()

  const vSplit = useResizable('vertical', 0.5)
  const hSplit = useResizable('horizontal', 0.4)

  const [rowMenu, setRowMenu] = useState<{ x: number; y: number; finding: Finding } | null>(null)
  const [detailMenu, setDetailMenu] = useState<{ x: number; y: number } | null>(null)
  const [confirmClear, setConfirmClear] = useState(false)
  const [detailRaw, setDetailRaw] = useState<RequestDetail | null>(null)
  // 'response' | 'request' | 'rendered' | a lens automation id.
  const [detailTab, setDetailTab] = useState('response')
  // Both halves: a lens tab renders whichever part it declares, so the panel's own
  // request/response toggle does not have to agree with it.
  const reqLenses = useLenses('request')
  const respLenses = useLenses('response')
  const detailLenses = useMemo(
    () => [...respLenses, ...reqLenses.filter((l) => !respLenses.some((r) => r.id === l.id))],
    [respLenses, reqLenses]
  )
  const activeDetailTab = detailLenses.some((l) => l.id === detailTab)
    ? detailTab
    : (['response', 'request', 'rendered'] as string[]).includes(detailTab)
      ? detailTab
      : 'response'
  const activeLens = detailLenses.find((l) => l.id === activeDetailTab) ?? null
  const [wrap, setWrap] = useState(true)
  // Reveal is per-finding and per-visit; it resets whenever the selection
  // changes.
  const [revealed, setRevealed] = useState(false)
  const [noteDraft, setNoteDraft] = useState('')
  const tableRef = useRef<HTMLDivElement>(null)
  const [prettyJson] = usePrettyJson()

  // Load the overall state once, so the header is populated before any finding
  // arrives.
  useEffect(() => {
    api
      .getDetect()
      .then((d) => {
        setEnabled(d.enabled)
        setSummary(d.summary)
        setScan(d.scan)
      })
      .catch(() => {})
  }, [setEnabled, setSummary, setScan])

  const query = useMemo(
    () => buildFindingQuery(filter, sortColumn, sortDir),
    [filter, sortColumn, sortDir]
  )

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api.listFindings(query)
      setItems(data.items ?? [], data.total ?? 0)
    } catch {
      // A failed load leaves the previous page on screen.
    } finally {
      setLoading(false)
    }
  }, [query, setItems, setLoading])

  useEffect(() => {
    void load()
  }, [load, reloadCounter])

  // Fetch the detail for the selected finding: its occurrences, its rule, and the
  // raw bytes of the most recent sighting.
  useEffect(() => {
    setRevealed(false)
    if (!selected) {
      setDetailRaw(null)
      setNoteDraft('')
      return
    }
    let cancelled = false
    api
      .getFinding(selected.id)
      .then((d) => {
        if (cancelled) return
        setSelectedDetail(d.occurrences ?? [], d.rule ?? null, d.notes ?? '')
        setNoteDraft(d.notes ?? '')
      })
      .catch(() => {})

    if (selected.requestId) {
      api
        .getRequest(selected.requestId)
        .then((d) => {
          if (!cancelled) setDetailRaw(d as RequestDetail)
        })
        .catch(() => {
          // The request may have been evicted from the ring buffer; the finding
          // survives, since its evidence is self-contained.
          if (!cancelled) setDetailRaw(null)
        })
    } else {
      setDetailRaw(null)
    }
    return () => {
      cancelled = true
    }
  }, [selected, setSelectedDetail])

  // Keyboard row navigation, with an input guard so typing in a filter box does
  // not move the selection.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return
      const tag = (e.target as HTMLElement | null)?.tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
      if (items.length === 0) return
      e.preventDefault()
      const idx = selected ? items.findIndex((f) => f.id === selected.id) : -1
      const next = e.key === 'ArrowDown' ? Math.min(items.length - 1, idx + 1) : Math.max(0, idx - 1)
      setSelected(items[next])
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [items, selected, setSelected])

  useEffect(() => {
    if (!selected || !tableRef.current) return
    const row = tableRef.current.querySelector(`[data-fid="${selected.id}"]`)
    row?.scrollIntoView({ block: 'nearest' })
  }, [selected])

  const sortIndicator = (col: FindingSortColumn) =>
    sortColumn !== col ? null : sortDir === 'asc' ? (
      <ChevronUp size={11} className="inline ml-0.5 align-[-1px]" />
    ) : (
      <ChevronDown size={11} className="inline ml-0.5 align-[-1px]" />
    )

  const th = (col: FindingSortColumn, label: string, cls = '') => (
    <th
      className={`px-2 py-1 text-left cursor-pointer select-none hover:text-content-primary ${cls}`}
      onClick={() => setSort(col)}
    >
      {label}
      {sortIndicator(col)}
    </th>
  )

  async function startScan() {
    try {
      const st = await api.startDetectScan({ scope: 'all' })
      setScan(st)
    } catch (err) {
      addToast((err as Error).message, 'error')
    }
  }

  async function stopScan() {
    try {
      await api.cancelDetectScan()
    } catch (err) {
      addToast((err as Error).message, 'error')
    }
  }

  async function doClear() {
    setConfirmClear(false)
    try {
      await api.clearFindings()
      clearAll()
    } catch (err) {
      addToast((err as Error).message, 'error')
    }
  }

  async function toggleEnabled() {
    const next = !enabled
    setEnabled(next)
    try {
      await api.setDetectEnabled(next)
    } catch (err) {
      setEnabled(!next)
      addToast((err as Error).message, 'error')
    }
  }

  // sendRaw fetches the bytes for a finding's request before handing them to
  // another page. Fails once the ring buffer has evicted the request.
  async function withRaw(f: Finding, fn: (d: RequestDetail) => void) {
    if (!f.requestId) {
      addToast('This finding has no associated request', 'error')
      return
    }
    try {
      const d = (await api.getRequest(f.requestId)) as RequestDetail
      fn(d)
    } catch {
      addToast('Request no longer in history', 'error')
    }
  }

  function rowMenuItems(f: Finding): MenuItem[] {
    return [
      {
        label: f.falsePositive ? 'Unmark false positive' : 'Mark false positive',
        checked: f.falsePositive,
        onClick: () => markFalsePositive(f.id, !f.falsePositive),
      },
      {
        label: 'Set severity',
        children: SEVERITY_ORDER.map((sev) => ({
          label: sev.charAt(0).toUpperCase() + sev.slice(1),
          checked: f.severity === sev,
          onClick: () => overrideSeverity(f.id, sev),
        })),
      },
      { label: 'Delete finding', onClick: () => removeFinding(f.id) },
      { label: 'Copy evidence', onClick: () => void copyText(f.rawEvidence || f.evidence) },
      { label: 'Copy URL', onClick: () => void copyText(f.url) },
      {
        label: 'Send to Manipulate',
        disabled: !f.requestId,
        onClick: () =>
          void withRaw(f, (d) => navigate('/manipulate', { state: { rawReq: d.reqRaw } })),
      },
      {
        label: 'Send to Fuzz',
        disabled: !f.requestId,
        onClick: () => void withRaw(f, (d) => navigate('/fuzz', { state: { rawReq: d.reqRaw } })),
      },
      {
        // The swagger-openapi-exposed rule fires on a captured document, whose
        // response body is the document itself. No withRaw here: SJ takes the
        // request id and fetches the bytes, rather than carrying megabytes
        // through navigation state.
        label: 'Send to SJ',
        disabled: !f.requestId,
        onClick: () =>
          navigate('/sj', {
            state: { source: 'detect', requestId: f.requestId, url: f.url, name: f.ruleName },
          }),
      },
      {
        label: 'Copy as curl',
        disabled: !f.requestId,
        onClick: () =>
          void withRaw(f, (d) => void copyText(rawToCurl(b64Decode(d.reqRaw), f.url))),
      },
      {
        label: 'Stage for Dead Drop',
        disabled: !f.requestId,
        onClick: () =>
          void withRaw(f, (d) =>
            stageDeadDrop({
              id: d.id,
              host: d.host,
              method: d.method,
              url: d.url,
              status: d.statusCode,
              reqRaw: d.reqRaw,
              respRaw: d.respRaw,
              truncated: false,
              // Seed the per-item note with the finding.
              note: `${f.ruleName}: ${f.evidence}`,
            })
          ),
      },
      {
        label: `Disable rule "${f.ruleName}"`,
        onClick: () => {
          useDetectStore.getState().setRuleEnabled(f.ruleId, false)
          addToast(`Rule disabled - existing findings are kept`, 'info')
        },
      },
    ]
  }

  // The filter holds the visible set; empty means no severity filter. The chips
  // and the dropdown read this one field (see matchesFindingFilter).
  const severityVisible = (sev: Severity) =>
    filter.severities.length === 0 || filter.severities.includes(sev)

  const severityCounts = SEVERITY_ORDER.map((sev) => ({
    sev,
    count: summary.bySeverity[sev] ?? 0,
    visible: severityVisible(sev),
  })).filter((s) => s.count > 0)

  // Canonical form for the visible set: severity order rather than click order,
  // and empty once every band is selected, so "all bands" has one
  // representation. Both controls write through this.
  const canonicalSeverities = (next: Severity[]): Severity[] => {
    const ordered = SEVERITY_ORDER.filter((s) => next.includes(s))
    return ordered.length === SEVERITY_ORDER.length ? [] : ordered
  }

  // A chip reverses one band's visibility and leaves the rest alone. Hiding a
  // band while the filter is empty materializes the full set first.
  function toggleSeverityChip(sev: Severity) {
    const current = filter.severities.length > 0 ? filter.severities : SEVERITY_ORDER
    setFilter({
      severities: canonicalSeverities(
        current.includes(sev) ? current.filter((s) => s !== sev) : [...current, sev]
      ),
    })
  }

  // Only offer the toggle where redaction actually hid something.
  const canReveal = Boolean(selected?.rawEvidence && selected.rawEvidence !== selected.evidence)
  const shownEvidence = revealed && selected?.rawEvidence ? selected.rawEvidence : selected?.evidence

  const rawForPane = (() => {
    if (!detailRaw) return ''
    if (detailTab === 'request') return b64Decode(detailRaw.reqRaw)
    return b64Decode(detailRaw.respRaw)
  })()

  // Only apply the offset highlight when the pane matches the part the offset
  // indexes into. The offset is an absolute byte offset into the raw document
  // (the backend translates body-relative positions before storing them), and -1
  // means no faithful mapping exists: a decompressed body, or a URL match.
  const highlightExtensions = useMemo(() => {
    if (!selected) return []
    const partMatches =
      (detailTab === 'response' && (selected.evidencePart ?? 'response') === 'response') ||
      (detailTab === 'request' && selected.evidencePart === 'request')
    const offset = partMatches ? selected.evidenceOffset : -1
    // The stored length, not evidence.length: a redaction mask is a different
    // size from the value it hides.
    const length = selected.evidenceLength
    // The text-search fallback needs the real value; the mask would never match.
    const needle = selected.rawEvidence || selected.evidence
    // An analyzer's evidence is a description, not a slice of the document, so
    // the offset cannot be checked against it.
    const verify = selected.target !== 'message'
    return [evidenceHighlightPlugin(rawForPane, needle, offset, length, verify)]
  }, [selected, detailTab, rawForPane])

  return (
    <div className="flex flex-col flex-1 min-h-0" ref={vSplit.containerRef}>
      {/* Top pane: filters, counts, table */}
      <div
        className="flex flex-col min-h-0 overflow-hidden"
        style={{ flex: vSplit.fraction }}
      >
        {/* Filter bar */}
        <div className="border-b border-border bg-surface-card shrink-0">
          <div className="px-2 pt-1.5 text-[10px] uppercase tracking-wide text-content-muted">
            Filters
          </div>
          <div className="flex flex-wrap items-center gap-2 lg:gap-3 px-2 py-1.5">
            <MultiSelectDropdown
              label="Severity"
              options={SEVERITY_OPTIONS}
              selected={filter.severities}
              onChange={(v) => setFilter({ severities: canonicalSeverities(v as Severity[]) })}
              tooltip="Filter by severity - unchecked bands are hidden from the table"
            />
            <MultiSelectDropdown
              label="Category"
              options={CATEGORY_OPTIONS}
              selected={filter.categories}
              onChange={(v) => setFilter({ categories: v })}
              tooltip="Filter by finding category"
            />
            <label className="flex items-center gap-1.5">
              <span className="text-xs text-content-muted">Host</span>
              <Tooltip content="Filter by hostname (substring match)">
                <input
                  value={filter.host}
                  onChange={(e) => setFilter({ host: e.target.value })}
                  className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-24 lg:w-32"
                />
              </Tooltip>
            </label>
            <label className="flex items-center gap-1.5">
              <span className="text-xs text-content-muted">Rule</span>
              <Tooltip content="Filter by rule name or ID (substring match)">
                <input
                  value={filter.rule}
                  onChange={(e) => setFilter({ rule: e.target.value })}
                  className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-24 lg:w-32"
                />
              </Tooltip>
            </label>
            <label className="flex items-center gap-1.5 flex-1 min-w-24">
              <span className="text-xs text-content-muted">Search</span>
              <Tooltip content="Search evidence, URL, rule name, and detail">
                <input
                  value={filter.search}
                  onChange={(e) => setFilter({ search: e.target.value })}
                  className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-full"
                />
              </Tooltip>
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-2 lg:gap-3 px-2 py-1.5 border-t border-border-subtle">
            <Tooltip content="Scan only in-scope traffic (configured on the Rules tab)">
              <button
                onClick={() => void toggleEnabled()}
                className={`flex items-center gap-1 text-xs px-2 py-1 rounded-sm font-semibold ${
                  enabled
                    ? 'bg-accent text-content-primary'
                    : 'bg-surface-input text-content-secondary hover:bg-surface-hover'
                }`}
              >
                <Radio size={12} />
                {enabled ? 'Detection on' : 'Detection off'}
              </button>
            </Tooltip>
            <div className="w-px h-5 bg-border mx-1 shrink-0" />
            <label className="flex items-center gap-1.5 text-xs text-content-muted">
              <input
                type="checkbox"
                className="accent-accent"
                checked={filter.showFalsePositives}
                onChange={(e) => setFilter({ showFalsePositives: e.target.checked })}
              />
              Show false positives
            </label>
            <label className="flex items-center gap-1.5 text-xs text-content-muted">
              <Tooltip content="Findings from disabled rules are kept, not deleted">
                <input
                  type="checkbox"
                  className="accent-accent"
                  checked={filter.includeDisabled}
                  onChange={(e) => setFilter({ includeDisabled: e.target.checked })}
                />
              </Tooltip>
              From disabled rules
            </label>
            <div className="w-px h-5 bg-border mx-1 shrink-0" />
            <Tooltip content={livePaused ? 'Resume live updates' : 'Pause live updates'}>
              <button
                onClick={togglePaused}
                className={`text-xs px-2 py-1 rounded-sm font-semibold ${
                  livePaused
                    ? 'bg-surface-input text-content-secondary hover:bg-surface-hover'
                    : 'bg-accent text-content-primary'
                }`}
              >
                {livePaused ? 'Paused' : 'Live'}
              </button>
            </Tooltip>
            <div className="ml-auto flex items-center gap-2">
              {scan.running ? (
                <button
                  onClick={() => void stopScan()}
                  className="text-xs px-4 py-1.5 rounded-sm bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary font-semibold"
                >
                  Stop scan
                </button>
              ) : (
                <Tooltip content="Re-run all enabled rules over captured history">
                  <button
                    onClick={() => void startScan()}
                    className="text-xs px-4 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black font-semibold disabled:opacity-50"
                  >
                    Rescan
                  </button>
                </Tooltip>
              )}
              <button
                onClick={() => setConfirmClear(true)}
                className="text-xs px-3 py-1 rounded-sm bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary font-semibold shrink-0"
              >
                Clear
              </button>
            </div>
          </div>
        </div>

        {/* Scan progress */}
        {scan.running && (
          <div className="shrink-0 px-2 py-1.5 border-b border-border bg-surface-card">
            <div className="flex items-center gap-2 text-[10px] text-content-muted mb-1">
              <span className="animate-pulse w-1.5 h-1.5 rounded-full bg-accent-tertiary" />
              Scanning {scan.scanned} of {scan.total} · {scan.findingsNew} new
            </div>
            <div className="h-1.5 bg-surface-input rounded-full overflow-hidden">
              <div
                className="h-full bg-accent-tertiary transition-all"
                style={{
                  width: `${scan.total > 0 ? Math.min(100, (scan.scanned / scan.total) * 100) : 0}%`,
                }}
              />
            </div>
          </div>
        )}

        {/* Count bar */}
        <div className="flex items-center gap-3 text-content-muted text-xs px-2 py-1 border-b border-border bg-surface-card shrink-0">
          <span>
            Showing {items.length} of {total}
          </span>
          {severityCounts.map(({ sev, count, visible }) => (
            <Tooltip
              key={sev}
              content={
                visible
                  ? `Hide ${sev} findings`
                  : `${count} ${sev} finding${count === 1 ? '' : 's'} hidden - click to show`
              }
            >
              <button
                onClick={() => toggleSeverityChip(sev)}
                className={`flex items-center gap-1 rounded-sm px-0.5 hover:bg-surface-hover ${
                  visible ? '' : 'opacity-50'
                }`}
              >
                {severityBadge(sev)}
                {count}
              </button>
            </Tooltip>
          ))}
          {summary.falsePositives > 0 && <span>{summary.falsePositives} FP</span>}
          {summary.hiddenByDisabledRule > 0 && (
            <Tooltip content="Findings whose rule is currently switched off. They are kept, not deleted - tick 'From disabled rules' to show them.">
              <span>{summary.hiddenByDisabledRule} from disabled rules</span>
            </Tooltip>
          )}
          {(summary.skippedEncoded > 0 || summary.skippedBinary > 0) && (
            <Tooltip content="Bodies that could not be read: compressed with an unsupported codec, or binary. Not a clean result - a blind spot.">
              <span className="text-semantic-warning">
                {summary.skippedEncoded + summary.skippedBinary} unreadable
              </span>
            </Tooltip>
          )}
          {pending.length > 0 && (
            <button
              onClick={flushPending}
              className="text-[10px] text-accent-secondary hover:underline"
            >
              {pending.length} new - load
            </button>
          )}
          {truncated && (
            <span className="text-semantic-warning">display capped - narrow the filters</span>
          )}
          <label className="flex items-center gap-1.5 ml-auto">
            <span className="text-content-muted">Limit</span>
            <select
              value={filter.limit}
              onChange={(e) => setFilter({ limit: Number(e.target.value) })}
              className="bg-surface-input text-xs px-2 py-1 rounded-sm border border-border"
            >
              {[50, 100, 200, 500, 1000, 0].map((n) => (
                <option key={n} value={n}>
                  {n === 0 ? 'All' : n}
                </option>
              ))}
            </select>
          </label>
        </div>

        {/* Table */}
        <div className="flex-1 overflow-auto min-h-0" ref={tableRef}>
          {loading && <div className="text-content-muted text-sm p-4">Loading...</div>}
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-surface-card text-content-muted uppercase">
              <tr>
                {th('severity', 'Sev', 'w-16')}
                {th('rule', 'Rule')}
                {th('category', 'Category', 'w-24')}
                {th('host', 'Host', 'w-40')}
                {th('url', 'URL')}
                <th className="px-2 py-1 text-left">Evidence</th>
                <th className="px-2 py-1 text-left w-14">Conf</th>
                {th('count', '#', 'w-12 text-right')}
                {th('lastSeen', 'Last', 'w-20')}
              </tr>
            </thead>
            <tbody>
              {items.length === 0 && !loading && (
                <tr>
                  <td colSpan={9} className="px-2 py-8 text-center text-content-muted text-xs">
                    {total === 0 && summary.total === 0
                      ? 'No findings yet - browse through the proxy, or run a rescan over captured history.'
                      : 'No findings match the current filters.'}
                  </td>
                </tr>
              )}
              {items.map((f) => (
                <tr
                  key={f.id}
                  data-fid={f.id}
                  className={`border-b border-border-subtle cursor-pointer hover:bg-surface-hover ${
                    selected?.id === f.id ? 'bg-surface-hover' : ''
                  }`}
                  onClick={() => setSelected(f)}
                  onContextMenu={(e) => {
                    e.preventDefault()
                    setDetailMenu(null)
                    setRowMenu({ x: e.clientX, y: e.clientY, finding: f })
                  }}
                >
                  <td className="px-2 py-1">{severityBadge(f.severity)}</td>
                  <td
                    className={`px-2 py-1 truncate max-w-xs ${
                      f.falsePositive
                        ? 'text-content-muted line-through'
                        : 'text-content-secondary'
                    }`}
                  >
                    {f.ruleName}
                    {f.detail ? <span className="text-content-muted"> · {f.detail}</span> : null}
                  </td>
                  <td className="px-2 py-1">{categoryPill(f.category)}</td>
                  <td className="px-2 py-1 truncate text-content-secondary">{f.host}</td>
                  <td className="px-2 py-1 truncate max-w-xs text-content-secondary">
                    {f.method ? <>{methodBadge(f.method)} </> : null}
                    {shortPath(f.url)}
                  </td>
                  <td className="px-2 py-1 truncate max-w-[14rem] font-mono text-content-muted">
                    {f.evidence}
                  </td>
                  <td className="px-2 py-1 text-content-muted">{f.confidence}</td>
                  <td className="px-2 py-1 text-right text-content-muted">{f.count}</td>
                  <td className="px-2 py-1 text-content-muted">{formatTime(f.lastSeen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="drag-handle-v" {...vSplit.handleProps} />

      {/* Bottom pane: detail + evidence in context */}
      <div
        className="flex min-h-0 overflow-hidden"
        ref={hSplit.containerRef}
        style={{ flex: 1 - vSplit.fraction }}
      >
        {!selected ? (
          <div className="flex-1 flex items-center justify-center text-content-muted text-sm">
            Select a finding to view details
          </div>
        ) : (
          <>
            {/* Finding detail */}
            <div
              className="flex flex-col min-h-0 overflow-hidden border-r border-border"
              style={{ flex: hSplit.fraction }}
            >
              <div className="flex items-center gap-2 px-2 py-1.5 border-b border-border bg-surface-card shrink-0">
                {severityBadge(selected.severity)}
                <span className="text-xs font-semibold text-content-primary truncate">
                  {selected.ruleName}
                </span>
                {categoryPill(selected.category)}
              </div>
              <div className="flex-1 overflow-auto min-h-0 p-2 space-y-2">
                <DetailField label="Rule ID" value={selected.ruleId} mono />
                {selectedRule?.description && (
                  <DetailField label="Description" value={selectedRule.description} />
                )}
                {selectedRule?.remediation && (
                  <DetailField label="Remediation" value={selectedRule.remediation} />
                )}
                <DetailField label="Confidence" value={selected.confidence} />
                <DetailField label="Target" value={selected.target} />
                <DetailField label="Host" value={selected.host} />
                <DetailField label="URL" value={selected.url} mono />
                <DetailField
                  label="Occurrences"
                  value={`${selected.count} (showing ${occurrences.length})`}
                />
                <DetailField label="First seen" value={selected.firstSeen} />
                <DetailField label="Last seen" value={selected.lastSeen} />
                {selected.truncated && (
                  <div className="text-[10px] text-semantic-warning">
                    The response body hit the scan size cap, so this scan was not
                    exhaustive for that request.
                  </div>
                )}

                <div className="mt-2">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] text-content-muted uppercase tracking-wide">
                      Evidence
                    </span>
                    {canReveal && (
                      <Tooltip
                        content={
                          revealed
                            ? 'Hide the value again'
                            : 'Show the unredacted value. Redaction here guards against shoulder-surfing, not storage.'
                        }
                      >
                        <button
                          onClick={() => setRevealed((v) => !v)}
                          className="w-6 h-5 flex items-center justify-center rounded-sm bg-surface-input text-content-secondary hover:bg-surface-hover"
                        >
                          {revealed ? <EyeOff size={12} /> : <Eye size={12} />}
                        </button>
                      </Tooltip>
                    )}
                  </div>
                  <pre className="bg-surface-input border border-border rounded-sm p-2 text-[11px] font-mono text-content-secondary whitespace-pre-wrap break-all max-h-40 overflow-auto">
                    {shownEvidence}
                  </pre>
                </div>

                {occurrences.length > 0 && (
                  <div className="mt-2">
                    <div className="text-[10px] text-content-muted uppercase tracking-wide mb-1">
                      Sightings
                    </div>
                    <div className="space-y-0.5">
                      {occurrences.map((o, i) => (
                        <div
                          key={`${o.requestId}-${i}`}
                          className="flex items-center gap-2 text-[10px]"
                        >
                          <span className="text-content-muted">{formatTime(o.timestamp)}</span>
                          <span className="text-content-secondary truncate flex-1">
                            {o.method} {shortPath(o.url)}
                          </span>
                          {!o.requestPresent && (
                            <Tooltip content="This request has been evicted from history; the finding is kept because its evidence is self-contained.">
                              <span className="text-content-muted">evicted</span>
                            </Tooltip>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="mt-2">
                  <div className="text-[10px] text-content-muted uppercase tracking-wide mb-1">
                    Notes
                  </div>
                  <textarea
                    value={noteDraft}
                    onChange={(e) => setNoteDraft(e.target.value)}
                    onBlur={() => {
                      if (noteDraft !== selectedNotes) setNotes(selected.id, noteDraft)
                    }}
                    rows={2}
                    placeholder="Triage notes (saved on blur)"
                    className="w-full bg-surface-input text-xs px-2 py-1 rounded-sm border border-border"
                  />
                </div>

                <div className="flex flex-wrap items-center gap-1.5 pt-1">
                  <button
                    onClick={() => markFalsePositive(selected.id, !selected.falsePositive)}
                    className="text-xs px-2 py-1 rounded-sm bg-surface-input text-content-secondary hover:bg-surface-hover"
                  >
                    {selected.falsePositive ? 'Unmark FP' : 'Mark FP'}
                  </button>
                  <button
                    onClick={() => void copyText(shownEvidence ?? '')}
                    className="text-xs px-2 py-1 rounded-sm bg-surface-input text-content-secondary hover:bg-surface-hover"
                  >
                    {revealed ? 'Copy value' : 'Copy evidence'}
                  </button>
                  <button
                    onClick={() => useDetectStore.getState().setRuleEnabled(selected.ruleId, false)}
                    className="text-xs px-2 py-1 rounded-sm bg-surface-input text-content-secondary hover:bg-surface-hover"
                  >
                    Disable rule
                  </button>
                  <button
                    onClick={() => removeFinding(selected.id)}
                    className="text-xs px-2 py-1 rounded-sm bg-surface-input text-semantic-error hover:bg-surface-hover flex items-center gap-1"
                  >
                    <Trash2 size={11} />
                    Delete
                  </button>
                </div>
              </div>
            </div>

            <div className="drag-handle-h" {...hSplit.handleProps} />

            {/* Evidence in context */}
            <div
              className="flex flex-col min-h-0 overflow-hidden"
              style={{ flex: 1 - hSplit.fraction }}
              onContextMenu={(e) => {
                e.preventDefault()
                setRowMenu(null)
                setDetailMenu({ x: e.clientX, y: e.clientY })
              }}
            >
              <div className="flex items-center gap-1 px-2 py-1.5 border-b border-border bg-surface-card shrink-0">
                <div className="flex items-center gap-0.5">
                  {(['response', 'request', 'rendered'] as const).map((k) => (
                    <TabButton key={k} active={activeDetailTab === k} onClick={() => setDetailTab(k)}>
                      {k.charAt(0).toUpperCase() + k.slice(1)}
                    </TabButton>
                  ))}
                  {detailLenses.map((l) => (
                    <TabButton key={l.id} active={activeDetailTab === l.id} onClick={() => setDetailTab(l.id)}>
                      {l.lens!.label}
                    </TabButton>
                  ))}
                </div>
                <div className="flex items-center gap-1 ml-auto">
                  <Tooltip content="Line wrapping">
                    <button
                      onClick={() => setWrap((w) => !w)}
                      className={`w-6 h-5 flex items-center justify-center rounded-sm leading-none ${
                        wrap
                          ? 'bg-accent text-content-primary'
                          : 'bg-surface-input text-content-secondary hover:bg-surface-hover'
                      }`}
                    >
                      <WrapText size={12} />
                    </button>
                  </Tooltip>
                </div>
              </div>
              {!detailRaw ? (
                <div className="flex-1 flex items-center justify-center text-content-muted text-sm px-4 text-center">
                  <span className="flex items-center gap-2">
                    <ShieldAlert size={14} className={severityTextClass(selected.severity)} />
                    Request no longer in history - the finding and its evidence are kept.
                  </span>
                </div>
              ) : activeDetailTab === 'rendered' ? (
                <div className="flex-1 relative min-h-0">
                  <div className="absolute inset-0 overflow-auto">
                    <ResponseRender raw={b64Decode(detailRaw.respRaw)} prettyJson={prettyJson} />
                  </div>
                </div>
              ) : activeLens ? (
                <div className="flex-1 relative min-h-0">
                  <LensOutput
                    scriptId={activeLens.id}
                    part={activeLens.lens!.part === 'request' ? 'request' : 'response'}
                    raw={b64Decode(
                      activeLens.lens!.part === 'request' ? detailRaw.reqRaw : detailRaw.respRaw
                    )}
                    meta={{ host: selected.host, url: selected.url, method: selected.method }}
                  />
                </div>
              ) : (
                <div className="flex-1 relative min-h-0">
                  <div className="absolute inset-0 overflow-hidden">
                    <CodeMirror
                      value={rawForPane}
                      theme={oneDark}
                      readOnly={true}
                      height="100%"
                      extensions={
                        wrap
                          ? [EditorView.lineWrapping, ...highlightExtensions]
                          : highlightExtensions
                      }
                      basicSetup={{ lineNumbers: true, foldGutter: false }}
                    />
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </div>

      {rowMenu && (
        <ContextMenu
          x={rowMenu.x}
          y={rowMenu.y}
          items={rowMenuItems(rowMenu.finding)}
          onClose={() => setRowMenu(null)}
        />
      )}
      {detailMenu && selected && (
        <ContextMenu
          x={detailMenu.x}
          y={detailMenu.y}
          items={[...getSelectionMenuItems(navigate), ...rowMenuItems(selected)]}
          onClose={() => setDetailMenu(null)}
        />
      )}
      {confirmClear && (
        <ConfirmModal
          title="Clear all findings?"
          message="Every finding is deleted, including false-positive marks and notes. Rules and configuration are unchanged, and a rescan will re-report anything still present in captured history."
          confirmLabel="Clear findings"
          onConfirm={() => void doClear()}
          onClose={() => setConfirmClear(false)}
        />
      )}
    </div>
  )
}

// DetailField renders one label/value row in the detail pane.
function DetailField({
  label,
  value,
  mono,
}: {
  label: string
  value: string
  mono?: boolean
}) {
  if (!value) return null
  return (
    <div>
      <div className="text-[10px] text-content-muted uppercase tracking-wide">{label}</div>
      <div
        className={`text-xs text-content-secondary break-all ${mono ? 'font-mono' : ''}`}
      >
        {value}
      </div>
    </div>
  )
}
// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

// RulesView renders either the passive detection rules or the active-scan
// techniques, depending on mode — the two models get separate Detect sub-tabs but
// share this grouped-table view.
function RulesView({ mode }: { mode: 'passive' | 'active' }) {
  const addToast = useToastStore((s) => s.addToast)
  const { rules, rulesLoaded, config, setRules, setRuleEnabled, setConfig, setFilter } =
    useDetectStore()

  const [search, setSearch] = useState('')
  const [origin, setOrigin] = useState<'all' | 'builtin' | 'custom'>('all')
  const [state, setState] = useState<'all' | 'enabled' | 'disabled'>('all')
  const [cats, setCats] = useState<string[]>([])
  const [sevs, setSevs] = useState<string[]>([])
  const [expanded, setExpanded] = useState<Set<string>>(loadExpanded)
  const [modalRuleId, setModalRuleId] = useState<string | null>(null)
  const [creating, setCreating] = useState(false)
  const [showSettings, setShowSettings] = useState(false)

  // Active-scan rules come from a separate registry endpoint and are few and
  // static apart from their enabled toggle, so they live in local state rather
  // than the detect store. null means not-yet-loaded (or unavailable in this mode).
  const [activeRules, setActiveRules] = useState<ActiveScanRule[] | null>(null)
  // Signatures per engine that has a catalog, keyed by rule id.
  const [activeSigs, setActiveSigs] = useState<Record<string, SignatureCatalogItem[]>>({})
  // The signature (or single-engine check) whose read-only detail is open.
  const [activeDetail, setActiveDetail] = useState<SignatureCatalogItem | null>(null)

  const loadActive = useCallback(async () => {
    try {
      const d = await api.activeScanRules()
      setActiveRules(d.rules)
      const sigs: Record<string, SignatureCatalogItem[]> = {}
      await Promise.all(
        d.rules
          .filter((r) => r.hasSignatures)
          .map(async (r) => {
            sigs[r.id] = (await api.activeScanSignatures(r.id)).signatures
          }),
      )
      setActiveSigs(sigs)
    } catch {
      setActiveRules(null)
    }
  }, [])
  useEffect(() => {
    if (mode === 'active') void loadActive()
  }, [mode, loadActive])

  const toggleActiveRule = (id: string, enabled: boolean) => {
    setActiveRules((prev) => prev?.map((r) => (r.id === id ? { ...r, enabled } : r)) ?? prev)
    api.setActiveScanRuleEnabled(id, enabled).catch((err) => {
      addToast((err as Error).message, 'error')
      setActiveRules((prev) => prev?.map((r) => (r.id === id ? { ...r, enabled: !enabled } : r)) ?? prev)
    })
  }
  const toggleSignature = (ruleId: string, sigId: string, enabled: boolean) => {
    setActiveSigs((prev) => ({
      ...prev,
      [ruleId]: (prev[ruleId] ?? []).map((s) => (s.id === sigId ? { ...s, enabled } : s)),
    }))
    api.setActiveScanSignatureEnabled(ruleId, sigId, enabled).catch((err) => {
      addToast((err as Error).message, 'error')
      setActiveSigs((prev) => ({
        ...prev,
        [ruleId]: (prev[ruleId] ?? []).map((s) => (s.id === sigId ? { ...s, enabled: !enabled } : s)),
      }))
    })
  }
  const bulkSignatures = (ruleId: string, enabled: boolean) => {
    setActiveSigs((prev) => ({
      ...prev,
      [ruleId]: (prev[ruleId] ?? []).map((s) => ({ ...s, enabled })),
    }))
    api.setActiveScanSignaturesBulk(ruleId, enabled).catch((err) => {
      addToast((err as Error).message, 'error')
      void loadActive()
    })
  }

  const loadRules = useCallback(async () => {
    try {
      const d = await api.listDetectRules()
      setRules(d.rules ?? [])
    } catch (err) {
      addToast((err as Error).message, 'error')
    }
  }, [setRules, addToast])

  useEffect(() => {
    if (mode === 'passive' && !rulesLoaded) void loadRules()
  }, [mode, rulesLoaded, loadRules])

  useEffect(() => {
    if (mode !== 'passive' || config) return
    api
      .getDetectConfig()
      .then(setConfig)
      .catch(() => {})
  }, [mode, config, setConfig])

  // Resolved from the live list rather than captured on open, so a toggle made
  // inside the modal shows immediately after loadRules().
  const modalRule = rules.find((r) => r.id === modalRuleId) ?? null

  const visible = useMemo(() => {
    const needle = search.toLowerCase()
    return rules.filter((r) => {
      if (origin === 'builtin' && !r.builtin) return false
      if (origin === 'custom' && r.builtin) return false
      if (state === 'enabled' && !r.enabled) return false
      if (state === 'disabled' && r.enabled) return false
      if (cats.length > 0 && !cats.includes(r.category)) return false
      if (sevs.length > 0 && !sevs.includes(r.severity)) return false
      if (
        needle &&
        !r.name.toLowerCase().includes(needle) &&
        !r.id.toLowerCase().includes(needle) &&
        !(r.description ?? '').toLowerCase().includes(needle)
      ) {
        return false
      }
      return true
    })
  }, [rules, search, origin, state, cats, sevs])

  // Grouped by category so the table can offer a bulk toggle per group.
  const grouped = useMemo(() => {
    const map = new Map<string, DetectRule[]>()
    for (const r of visible) {
      const arr = map.get(r.category) ?? []
      arr.push(r)
      map.set(r.category, arr)
    }
    return [...map.entries()]
  }, [visible])

  // Collapse is bypassed while any filter is active, so a search matching rules
  // inside a collapsed group is visible.
  const filtering =
    search !== '' || cats.length > 0 || sevs.length > 0 || origin !== 'all' || state !== 'all'

  function toggleGroup(key: string) {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      persistExpanded(next)
      return next
    })
  }

  function setCategoryEnabled(category: string, enabled: boolean) {
    for (const r of rules) {
      if (r.category === category && r.enabled !== enabled) setRuleEnabled(r.id, enabled)
    }
  }

  // Passive rules mapped into the shared section view-model (rows click → edit modal).
  const passiveGroups = useMemo<RuleGroupVM[]>(
    () =>
      grouped.map(([category, catRules]) => ({
        key: category,
        label: category,
        rows: catRules.map((r) => ({
          id: r.id,
          name: r.name,
          description: r.description,
          severity: r.severity,
          confidence: r.confidence,
          target: r.target,
          originBuiltin: r.builtin,
          originLabel: r.builtin ? 'Built-in' : 'Custom',
          enabled: r.enabled,
          hits: r.findingCount,
          onToggle: (en: boolean) => setRuleEnabled(r.id, en),
          onClick: () => {
            setCreating(false)
            setModalRuleId(r.id)
          },
          onHits: () => setFilter({ rule: r.id, severities: [] }),
        })),
        onEnableAll: () => setCategoryEnabled(category, true),
        onDisableAll: () => setCategoryEnabled(category, false),
      })),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [grouped],
  )

  // Active rules mapped the same way: engines with a catalog expand to their
  // signatures (per-signature toggle, read-only detail on click) with a master
  // engine toggle; a single-row engine (DOM XSS) is one row.
  // Active techniques are grouped by family (section) → technique (group) → rows.
  const activeFamilies = useMemo<{ family: string; groups: RuleGroupVM[] }[]>(() => {
    if (!activeRules) return []
    const needle = search.toLowerCase()
    const stateOK = (enabled: boolean) =>
      state === 'all' || (state === 'enabled' && enabled) || (state === 'disabled' && !enabled)
    const rowOK = (name: string, id: string, desc: string | undefined, severity: string) => {
      if (origin === 'custom') return false // active signatures are all built-in
      if (sevs.length > 0 && !sevs.includes(severity)) return false
      if (
        needle &&
        !name.toLowerCase().includes(needle) &&
        !id.toLowerCase().includes(needle) &&
        !(desc ?? '').toLowerCase().includes(needle)
      ) {
        return false
      }
      return true
    }
    const byFamily = new Map<string, RuleGroupVM[]>()
    const push = (fam: string, g: RuleGroupVM) => {
      const a = byFamily.get(fam) ?? []
      a.push(g)
      byFamily.set(fam, a)
    }
    for (const eng of activeRules) {
      if (cats.length > 0 && !cats.includes(eng.category)) continue
      const fam = ACTIVE_FAMILY[eng.category] ?? 'Other'
      if (eng.hasSignatures) {
        const rows = (activeSigs[eng.id] ?? [])
          .filter((s) => rowOK(s.name, s.id, s.description, s.severity) && stateOK(s.enabled))
          .map((s) => ({
            id: `${eng.id}:${s.id}`,
            name: s.name,
            description: s.description,
            severity: s.severity,
            confidence: s.confidence,
            target: s.target,
            originBuiltin: true,
            originLabel: 'Built-in',
            enabled: s.enabled,
            onToggle: (en: boolean) => toggleSignature(eng.id, s.id, en),
            onClick: () => setActiveDetail(s),
          }))
        if (filtering && rows.length === 0) continue
        push(fam, {
          key: eng.id,
          label: eng.name,
          description: eng.description,
          rows,
          onEnableAll: () => bulkSignatures(eng.id, true),
          onDisableAll: () => bulkSignatures(eng.id, false),
        })
      } else {
        const sev = eng.severity ?? 'info'
        if (!(rowOK(eng.name, eng.id, eng.description, sev) && stateOK(eng.enabled))) continue
        const synthetic: SignatureCatalogItem = {
          id: eng.id,
          name: eng.name,
          severity: sev,
          confidence: eng.confidence,
          target: eng.target,
          description: eng.description,
          enabled: eng.enabled,
        }
        push(fam, {
          key: eng.id,
          label: eng.name,
          rows: [
            {
              id: eng.id,
              name: eng.name,
              description: eng.description,
              severity: sev,
              confidence: eng.confidence,
              target: eng.target,
              originBuiltin: true,
              originLabel: 'Built-in',
              enabled: eng.enabled,
              onToggle: (en: boolean) => toggleActiveRule(eng.id, en),
              onClick: () => setActiveDetail(synthetic),
            },
          ],
          onEnableAll: () => toggleActiveRule(eng.id, true),
          onDisableAll: () => toggleActiveRule(eng.id, false),
        })
      }
    }
    return ACTIVE_FAMILY_ORDER.filter((f) => byFamily.has(f)).map((f) => ({
      family: f,
      groups: byFamily.get(f)!,
    }))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeRules, activeSigs, search, sevs, cats, origin, state, filtering])

  const anyExpanded = expanded.size > 0
  function setAllExpanded(expand: boolean) {
    const keys =
      mode === 'active'
        ? activeFamilies.flatMap((f) => f.groups.map((g) => g.key))
        : passiveGroups.map((g) => g.key)
    const next = expand ? new Set(keys) : new Set<string>()
    persistExpanded(next)
    setExpanded(next)
  }

  async function patchConfig(patch: Record<string, unknown>) {
    try {
      setConfig(await api.updateDetectConfig(patch))
    } catch (err) {
      addToast((err as Error).message, 'error')
    }
  }

  const chip = (active: boolean) =>
    `px-1.5 h-5 flex items-center justify-center text-[10px] rounded-sm font-semibold leading-none ${
      active
        ? 'bg-accent text-content-primary'
        : 'bg-surface-input text-content-secondary hover:bg-surface-hover'
    }`


  const enabledCount = rules.filter((r) => r.enabled).length

  return (
    <div className="flex flex-col flex-1 min-h-0">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2 px-2 py-1.5 border-b border-border bg-surface-card shrink-0">
        {mode === 'passive' && (
          <MultiSelectDropdown
            label="Category"
            options={CATEGORY_OPTIONS}
            selected={cats}
            onChange={setCats}
          />
        )}
        <MultiSelectDropdown
          label="Severity"
          options={SEVERITY_OPTIONS}
          selected={sevs}
          onChange={setSevs}
          tooltip="Filter the rule list by severity"
        />
        <label className="flex items-center gap-1.5 flex-1 min-w-24">
          <span className="text-xs text-content-muted">Search</span>
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border w-full"
          />
        </label>
        {mode === 'passive' && (
          <div className="flex items-center gap-0.5">
            {(['all', 'builtin', 'custom'] as const).map((k) => (
              <button key={k} onClick={() => setOrigin(k)} className={chip(origin === k)}>
                {k === 'all' ? 'All' : k === 'builtin' ? 'Built-in' : 'Custom'}
              </button>
            ))}
          </div>
        )}
        <div className="flex items-center gap-0.5">
          {(['all', 'enabled', 'disabled'] as const).map((k) => (
            <Tooltip
              key={k}
              content={k === 'all' ? 'Any state' : k === 'enabled' ? 'Enabled only' : 'Disabled only'}
            >
              <button onClick={() => setState(k)} className={chip(state === k)}>
                {k === 'all' ? 'Any' : k === 'enabled' ? 'On' : 'Off'}
              </button>
            </Tooltip>
          ))}
        </div>
        <Tooltip content={anyExpanded ? 'Collapse every group' : 'Expand every group'}>
          <button
            onClick={() => setAllExpanded(!anyExpanded)}
            disabled={filtering}
            className="text-xs px-2 py-1 rounded-sm bg-surface-input text-content-secondary hover:bg-surface-hover disabled:opacity-50"
          >
            {anyExpanded ? 'Collapse all' : 'Expand all'}
          </button>
        </Tooltip>
        {mode === 'passive' && (
          <>
            <button
              onClick={() => setShowSettings((v) => !v)}
              className="text-xs px-2 py-1 rounded-sm bg-surface-input text-content-secondary hover:bg-surface-hover"
            >
              {showSettings ? 'Hide settings' : 'Settings'}
            </button>
            <button
              onClick={() => {
                setModalRuleId(null)
                setCreating(true)
              }}
              className="text-xs px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black font-semibold"
            >
              + New rule
            </button>
          </>
        )}
      </div>

      {/* Detection settings: engine config rather than per-rule, so it stays
          inline on the page instead of moving into the per-rule modal. */}
      {showSettings && config && (
        <div className="shrink-0 border-b border-border bg-surface-card px-2 py-2 space-y-1.5">
          <div className="text-[10px] uppercase tracking-wide text-content-muted">
            Detection settings
          </div>
          {(
            [
              ['scopeOnly', 'Scan in-scope traffic only'],
              ['scanRequests', 'Scan requests as well as responses'],
              ['persistFindings', 'Save findings in the project file'],
              ['clearFindingsWithHistory', 'Clear findings when history is cleared'],
              ['anomalyEnabled', 'Flag endpoints unlike others on the same host (anomalies)'],
            ] as const
          ).map(([key, label]) => (
            <label key={key} className="flex items-center gap-1.5 text-xs text-content-muted">
              <input
                type="checkbox"
                className="accent-accent"
                checked={Boolean(config[key])}
                onChange={(e) => void patchConfig({ [key]: e.target.checked })}
              />
              {label}
            </label>
          ))}
          {config.anomalyEnabled && (
            <label className="flex items-center gap-1.5 text-xs text-content-muted">
              <span className="w-32">Anomaly sensitivity</span>
              <select
                value={config.anomalySensitivity || 'medium'}
                onChange={(e) => void patchConfig({ anomalySensitivity: e.target.value })}
                className="bg-surface-input text-xs px-2 py-1 rounded-sm border border-border"
              >
                <option value="low">Low - only stark outliers</option>
                <option value="medium">Medium</option>
                <option value="high">High - more, noisier</option>
              </select>
            </label>
          )}
          <label className="flex items-center gap-1.5 text-xs text-content-muted">
            <span className="w-32">Max body bytes</span>
            <input
              type="number"
              value={config.maxBodyScanBytes}
              onChange={(e) => void patchConfig({ maxBodyScanBytes: Number(e.target.value) })}
              className="bg-surface-input text-xs px-2 py-1 rounded-sm border border-border w-28"
            />
          </label>
          <label className="flex items-start gap-1.5 text-xs text-content-muted">
            <span className="w-32 pt-1">Exclude hosts</span>
            <input
              defaultValue={config.excludeHosts.join(', ')}
              onBlur={(e) =>
                void patchConfig({
                  excludeHosts: e.target.value
                    .split(',')
                    .map((v) => v.trim())
                    .filter(Boolean),
                })
              }
              placeholder="analytics.example.com, cdn.example.net"
              className="bg-surface-input text-xs px-2 py-1 rounded-sm border border-border flex-1"
            />
          </label>
        </div>
      )}

      {/* Count bar */}
      <div className="flex items-center gap-3 text-content-muted text-xs px-2 py-1 border-b border-border bg-surface-card shrink-0">
        {mode === 'passive' ? (
          <>
            <span>
              Showing {visible.length} of {rules.length} rules
            </span>
            <span>
              {enabledCount} enabled, {rules.length - enabledCount} disabled
            </span>
            <span className="ml-auto text-[10px]">
              Click a rule to configure it; use the checkbox to toggle it directly.
            </span>
          </>
        ) : (
          <span className="ml-auto text-[10px]">
            Operator-initiated via "Initiate scan". Click a check for detail; use the checkbox to
            toggle it.
          </span>
        )}
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto min-h-0">
        {mode === 'active' ? (
          activeFamilies.length === 0 ? (
            <div className="px-3 py-8 text-center text-content-muted text-xs">
              No active rules match the current filters.
            </div>
          ) : (
            activeFamilies.map((f) => (
              <RuleTableSection
                key={f.family}
                title={f.family}
                groups={f.groups}
                expanded={expanded}
                onToggleExpand={toggleGroup}
                filtering={filtering}
                emptyText="No techniques match the current filters."
              />
            ))
          )
        ) : (
          <RuleTableSection
            groups={passiveGroups}
            expanded={expanded}
            onToggleExpand={toggleGroup}
            filtering={filtering}
            emptyText="No rules match the current filters."
          />
        )}
      </div>

      {(modalRule || creating) && (
        <DetectRuleModal
          rule={modalRule}
          creating={creating}
          onClose={() => {
            setModalRuleId(null)
            setCreating(false)
          }}
          onChanged={loadRules}
        />
      )}
      {activeDetail && (
        <div
          className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50"
          onClick={() => setActiveDetail(null)}
        >
          <div
            className="bg-surface-card border border-border rounded w-[40rem] max-w-[95vw] max-h-[80vh] overflow-y-auto p-4"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center mb-2">
              <h3 className="text-sm font-semibold text-content-primary">Rule detail</h3>
              <button
                onClick={() => setActiveDetail(null)}
                className="ml-auto px-2 py-1 rounded-sm text-xs text-content-secondary hover:text-content-primary hover:bg-surface-input"
              >
                Close
              </button>
            </div>
            <SignatureDetail sig={activeDetail} />
          </div>
        </div>
      )}
    </div>
  )
}

// ScansView lists active-scan runs with live progress. Runs are session state in
// useActiveScanStore, fed by the activescan.* WS events; this view seeds the list
// from the server on mount and on reconnect, then renders live.
function ScansView() {
  const addToast = useToastStore((s) => s.addToast)
  const runs = useActiveScanStore((s) => s.runs)
  const { setRuns, removeRun } = useActiveScanStore()

  const reload = useCallback(() => {
    api
      .listActiveScanRuns()
      .then((d) => setRuns(d.runs))
      .catch(() => {})
  }, [setRuns])

  useEffect(() => {
    reload()
    window.addEventListener('joro:ws-reconnected', reload)
    return () => window.removeEventListener('joro:ws-reconnected', reload)
  }, [reload])

  const stop = (id: string) => {
    api.stopActiveScan(id).catch((err) => addToast((err as Error).message, 'error'))
  }
  const remove = (id: string) => {
    api
      .deleteActiveScan(id)
      .then(() => removeRun(id))
      .catch((err) => addToast((err as Error).message, 'error'))
  }

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <div className="flex items-center gap-2 px-2 py-1.5 border-b border-border bg-surface-card shrink-0">
        <Scan size={13} strokeWidth={1.8} className="text-accent-tertiary" />
        <span className="text-xs font-semibold text-content-secondary">Active scans</span>
        <span className="text-[10px] text-content-muted">
          {runs.length} run{runs.length === 1 ? '' : 's'}
        </span>
      </div>
      {runs.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-center text-xs text-content-muted px-6">
          No scans yet. Right-click a host in the Site Map or a request in History and choose
          &ldquo;Initiate scan&rdquo;.
        </div>
      ) : (
        <div className="flex-1 overflow-auto min-h-0 divide-y divide-border-subtle">
          {runs.map((run) => (
            <ScanRow key={run.id} run={run} onStop={stop} onDelete={remove} />
          ))}
        </div>
      )}
    </div>
  )
}

function ScanRow({
  run,
  onStop,
  onDelete,
}: {
  run: ActiveScanRun
  onStop: (id: string) => void
  onDelete: (id: string) => void
}) {
  const pct = run.total > 0 ? Math.min(100, Math.round((run.completed / run.total) * 100)) : 0
  const statusClass =
    run.status === 'running'
      ? 'text-accent-tertiary'
      : run.status === 'stopped'
        ? 'text-semantic-warning'
        : 'text-content-muted'
  return (
    <div className="px-3 py-2">
      <div className="flex items-center gap-2">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-content-primary truncate">{run.origin || run.host}</span>
            <span className={`text-[10px] uppercase font-semibold ${statusClass}`}>{run.status}</span>
          </div>
          <div className="text-[10px] text-content-muted truncate">
            {run.scope} · {run.rules.join(', ') || 'all rules'}
          </div>
        </div>
        <div className="flex items-center gap-3 text-[10px] text-content-muted shrink-0">
          <span>
            {run.completed}/{run.total}
          </span>
          <span className="text-content-secondary">
            {run.findings} finding{run.findings === 1 ? '' : 's'}
          </span>
          {run.errors > 0 && <span className="text-semantic-error">{run.errors} err</span>}
          {run.status === 'running' ? (
            <button onClick={() => onStop(run.id)} className="text-semantic-error hover:underline">
              Stop
            </button>
          ) : (
            <button onClick={() => onDelete(run.id)} className="text-content-muted hover:text-content-primary">
              <Trash2 size={13} />
            </button>
          )}
        </div>
      </div>
      <div className="mt-1.5 h-1.5 bg-surface-input rounded-full overflow-hidden">
        <div className="h-full bg-accent-tertiary transition-all" style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}
