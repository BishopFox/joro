import { useAutomationStore } from '../stores/automationStore'
import { useCallbackStore, type CallbackInteraction } from '../stores/callbackStore'
import { useDetectStore, type Finding, type DetectSummary } from '../stores/detectStore'
import { useEchoStore } from '../stores/echoStore'
import type { EchoSummary } from './echoTypes'
import { useSJStore } from '../stores/sjStore'
import type { SJResult, SJFoundSpec } from './sjTypes'
import { useChainStore } from '../stores/chainStore'
import type { ChainResult, ChainVerdict } from './chainTypes'
import { useFuzzStore, type FuzzResult } from '../stores/fuzzStore'
import { useToastStore } from '../stores/toastStore'
import { useInterceptStore, type InterceptKind, type PendingItem } from '../stores/interceptStore'
import { useManipulateWSStore, type WSFrameEntry } from '../stores/manipulateWSStore'
import { useRequestStore, type RequestSummary } from '../stores/requestStore'
import { useTeamStore, type ChatMessage, type ActiveUser } from '../stores/teamStore'
import { useTeamConnectionStore, type RelayState } from '../stores/teamConnectionStore'
import { useTeamFlaggedStore, type FlaggedSummary } from '../stores/teamFlaggedStore'
import { useTeamSharedConfigStore, type SharedConfigSummary } from '../stores/teamSharedConfigStore'
import { useUpdateStore } from '../stores/updateStore'
import { useWebhookStore } from '../stores/webhookStore'
import { useWSStore } from '../stores/wsStore'
import { useXSSHunterStore, type XSSFire } from '../stores/xssHunterStore'
import type { CapturedWSMessage } from './api'
import { redactNow } from '../stores/streamerStore'

type WSMessage = {
  type: string
  data: unknown
}

let ws: WebSocket | null = null
let reconnectTimer: ReturnType<typeof setTimeout> | null = null
let hasConnected = false

let requestBuffer: RequestSummary[] = []
let rafScheduled = false

function flushRequestBuffer() {
  rafScheduled = false
  if (requestBuffer.length === 0) return
  const batch = requestBuffer
  requestBuffer = []
  useRequestStore.getState().addItems(batch)
}

let fuzzResultBuffer: { campaignId: string; result: FuzzResult }[] = []
let fuzzRafScheduled = false

function flushFuzzResultBuffer() {
  fuzzRafScheduled = false
  if (fuzzResultBuffer.length === 0) return
  const batch = fuzzResultBuffer
  fuzzResultBuffer = []
  // Group by campaignId and dispatch to the correct tab
  const byCampaign = new Map<string, FuzzResult[]>()
  for (const item of batch) {
    let arr = byCampaign.get(item.campaignId)
    if (!arr) { arr = []; byCampaign.set(item.campaignId, arr) }
    arr.push(item.result)
  }
  const store = useFuzzStore.getState()
  for (const [campaignId, results] of byCampaign) {
    store.addResultsToCampaign(campaignId, results)
  }
}

// SJ run results share one buffer across scan, matrix and discovery: all three
// arrive in bursts at the worker pool's rate, and each store write rebuilds a
// result list, which is the same cost profile fuzzer.result has.
let sjResultBuffer: { runId: string; result: SJResult }[] = []
let sjRafScheduled = false

function flushSJResultBuffer() {
  sjRafScheduled = false
  if (sjResultBuffer.length === 0) return
  const batch = sjResultBuffer
  sjResultBuffer = []
  const byRun = new Map<string, SJResult[]>()
  for (const item of batch) {
    let arr = byRun.get(item.runId)
    if (!arr) { arr = []; byRun.set(item.runId, arr) }
    arr.push(item.result)
  }
  const store = useSJStore.getState()
  for (const [runId, results] of byRun) {
    store.addRunResults(runId, results)
  }
}

// Chain sweep results are RAF-batched for the same reason SJ's are: each store
// write rebuilds a result array and derives every counter from it, and a sweep
// emits one per step across every variant.
let chainResultBuffer: { runId: string; result: ChainResult }[] = []
let chainRafScheduled = false

function flushChainResultBuffer() {
  chainRafScheduled = false
  if (chainResultBuffer.length === 0) return
  const batch = chainResultBuffer
  chainResultBuffer = []
  const byRun = new Map<string, ChainResult[]>()
  for (const item of batch) {
    let arr = byRun.get(item.runId)
    if (!arr) { arr = []; byRun.set(item.runId, arr) }
    arr.push(item.result)
  }
  const store = useChainStore.getState()
  for (const [runId, results] of byRun) {
    store.addRunResults(runId, results)
  }
}

// Findings are RAF-batched, as request captures are: each upsert re-sorts the
// list and rebuilds an id map, and a rescan emits them in a tight burst.
let findingBuffer: Finding[] = []
let findingRafScheduled = false

function flushFindingBuffer() {
  findingRafScheduled = false
  if (findingBuffer.length === 0) return
  const batch = findingBuffer
  findingBuffer = []
  useDetectStore.getState().upsertFindings(batch)
}

// Scan progress is coalesced to the newest value per frame; a rescan reports
// faster than the UI can paint.
let pendingScanProgress: { scanned: number; total: number; findingsNew: number } | null = null
let scanProgressRafScheduled = false

function flushScanProgress() {
  scanProgressRafScheduled = false
  if (!pendingScanProgress) return
  useDetectStore.getState().setScan(pendingScanProgress)
  pendingScanProgress = null
}

export function connectWS() {
  if (ws && ws.readyState < WebSocket.CLOSING) return

  const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
  ws = new WebSocket(`${protocol}://${window.location.host}/ws`)

  ws.onopen = () => {
    // If we were updating and the WebSocket reconnected, the server restarted.
    if (useUpdateStore.getState().updating) {
      window.location.reload()
    }
    // Events emitted while the socket was down are gone for good (the hub
    // broadcast is non-blocking and has no replay), so views holding
    // server-owned state re-sync on reconnect.
    if (hasConnected) {
      window.dispatchEvent(new Event('joro:ws-reconnected'))
    }
    hasConnected = true
  }

  ws.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data as string) as WSMessage
      handleMessage(msg)
    } catch {
      // ignore malformed messages
    }
  }

  ws.onclose = () => {
    if (reconnectTimer) clearTimeout(reconnectTimer)
    reconnectTimer = setTimeout(connectWS, 2000)
  }

  ws.onerror = () => ws?.close()
}

// Echo rows are server-side aggregates, so a live reflection can only ask for a
// reload. One per frame keeps a rescan from issuing a request per response.
let echoReloadScheduled = false
function scheduleEchoReload() {
  if (echoReloadScheduled) return
  echoReloadScheduled = true
  requestAnimationFrame(() => {
    echoReloadScheduled = false
    useEchoStore.getState().invalidate()
  })
}

function handleMessage(msg: WSMessage) {
  switch (msg.type) {
    case 'request.captured': {
      requestBuffer.push(msg.data as RequestSummary)
      if (!rafScheduled) {
        rafScheduled = true
        requestAnimationFrame(flushRequestBuffer)
      }
      break
    }
    case 'intercept.queued': {
      // Covers both phases; `kind` defaults to request so a payload from an
      // older proxy still renders.
      const item = msg.data as PendingItem & { kind?: InterceptKind }
      useInterceptStore.getState().addItem({
        id: item.id,
        kind: item.kind ?? 'request',
        method: item.method,
        url: item.url,
        host: item.host,
        protocol: item.protocol,
        status: item.status,
        pausedAt: item.pausedAt,
        reqRaw: item.reqRaw,
        respRaw: item.respRaw,
      })
      break
    }
    case 'intercept.resolved': {
      const d = msg.data as { id: string }
      useInterceptStore.getState().removeItem(d.id)
      break
    }
    case 'callback.interaction': {
      const item = msg.data as CallbackInteraction
      useCallbackStore.getState().addInteraction(item)
      break
    }
    case 'ws.message': {
      const item = msg.data as CapturedWSMessage
      useWSStore.getState().addItem(item)
      break
    }
    case 'manipulate.ws.frame': {
      const d = msg.data as {
        sessionId: string
        direction: 'sent' | 'received'
        opcode: WSFrameEntry['opcode']
        payload: string
        isText: boolean
        size: number
        ts: string
      }
      useManipulateWSStore.getState().appendFrameBySession(d.sessionId, {
        id: `${d.ts}-${Math.random().toString(36).slice(2, 8)}`,
        direction: d.direction,
        opcode: d.opcode,
        payload: d.payload,
        isText: d.isText,
        size: d.size,
        ts: d.ts,
      })
      break
    }
    case 'manipulate.ws.closed': {
      const d = msg.data as { sessionId: string; reason: string }
      useManipulateWSStore.getState().markSessionClosed(d.sessionId, d.reason)
      break
    }
    case 'xss.fire': {
      const fire = msg.data as XSSFire
      useXSSHunterStore.getState().addFire(fire)
      break
    }
    case 'team.chat': {
      const chatMsg = msg.data as ChatMessage
      useTeamStore.getState().addMessage(chatMsg)
      break
    }
    case 'team.flagged': {
      const f = msg.data as FlaggedSummary
      useTeamFlaggedStore.getState().addItem(f)
      break
    }
    case 'team.flagged.deleted': {
      const d = msg.data as { id: string }
      useTeamFlaggedStore.getState().removeItem(d.id)
      break
    }
    case 'team.config': {
      const c = msg.data as SharedConfigSummary
      useTeamSharedConfigStore.getState().addItem(c)
      break
    }
    case 'team.config.deleted': {
      const d = msg.data as { id: string }
      useTeamSharedConfigStore.getState().removeItem(d.id)
      break
    }
    case 'team.presence': {
      const presence = msg.data as { users: ActiveUser[] }
      useTeamStore.getState().setActiveUsers(presence.users || [])
      break
    }
    case 'team.nickname_changed': {
      const d = msg.data as { oldNickname: string; newNickname: string }
      useTeamStore.getState().handleNicknameChange(d.oldNickname, d.newNickname)
      break
    }
    case 'team.relay': {
      const d = msg.data as { state: RelayState; error?: string; httpStatus?: number }
      const prev = useTeamConnectionStore.getState().state
      useTeamConnectionStore.getState().setState(d.state, d.error, d.httpStatus)
      // Toast only on the connected→disconnected transition, so backoff retries
      // and reconnect churn don't spam.
      if (prev === 'connected' && d.state === 'disconnected') {
        const detail = d.error ? `: ${redactNow(d.error, 'url')}` : ''
        useToastStore.getState().addToast(`Team server disconnected${detail}`)
      }
      break
    }
    case 'sliver.event': {
      const ev = msg.data as SliverEvent
      sliverEventListeners.forEach((fn) => fn(ev))
      break
    }
    case 'mythic.event': {
      const ev = msg.data as MythicEvent
      mythicEventListeners.forEach((fn) => fn(ev))
      break
    }
    case 'system.update.available': {
      const info = msg.data as { version: string; commit: string; updateAvailable: boolean; latestVersion: string }
      useUpdateStore.getState().setInfo(info)
      break
    }
    case 'system.update.progress': {
      const d = msg.data as { stage: string }
      useUpdateStore.getState().setStatus(d.stage)
      break
    }
    case 'system.update.restarting': {
      useUpdateStore.getState().setStatus('Restarting...')
      break
    }
    case 'system.update.failed': {
      const d = msg.data as { error: string }
      useUpdateStore.getState().setUpdating(false)
      useToastStore.getState().addToast(`Update failed: ${d.error}`)
      break
    }
    case 'fuzzer.result': {
      const d = msg.data as { campaignId: string; result: FuzzResult }
      fuzzResultBuffer.push({ campaignId: d.campaignId, result: d.result })
      if (!fuzzRafScheduled) {
        fuzzRafScheduled = true
        requestAnimationFrame(flushFuzzResultBuffer)
      }
      break
    }
    case 'fuzzer.started': {
      const d = msg.data as { campaignId: string; total: number }
      useFuzzStore.getState().setCampaignStarted(d.campaignId, d.total)
      break
    }
    case 'spec.run.result': {
      const d = msg.data as { runId: string; result: SJResult }
      sjResultBuffer.push({ runId: d.runId, result: d.result })
      if (!sjRafScheduled) {
        sjRafScheduled = true
        requestAnimationFrame(flushSJResultBuffer)
      }
      break
    }
    case 'spec.run.started': {
      const d = msg.data as { runId: string; total: number }
      useSJStore.getState().setRunStarted(d.runId, d.total)
      break
    }
    case 'spec.run.complete': {
      const d = msg.data as { runId: string; status: string }
      useSJStore.getState().setRunStatus(d.runId, d.status === 'stopped' ? 'stopped' : 'complete')
      break
    }
    case 'spec.run.found': {
      const d = msg.data as { runId: string } & SJFoundSpec
      useSJStore.getState().addRunFound(d.runId, {
        specId: d.specId, title: d.title, format: d.format,
        operations: d.operations, sourceUrl: d.sourceUrl,
      })
      break
    }
    case 'spec.run.warning': {
      const d = msg.data as { runId: string; detail: string }
      useSJStore.getState().addRunWarning(d.runId, d.detail)
      break
    }
    case 'chain.run.result': {
      const d = msg.data as { runId: string; result: ChainResult }
      chainResultBuffer.push({ runId: d.runId, result: d.result })
      if (!chainRafScheduled) {
        chainRafScheduled = true
        requestAnimationFrame(flushChainResultBuffer)
      }
      break
    }
    case 'chain.run.started': {
      const d = msg.data as { runId: string; total: number }
      useChainStore.getState().updateRun(d.runId, { total: d.total, status: 'running' })
      break
    }
    case 'chain.run.variant': {
      const d = msg.data as { runId: string; verdict: ChainVerdict }
      // Flush first: a verdict is computed from cells the server has already
      // sent, so applying it before its own row lands would render a verdict
      // beside empty cells.
      flushChainResultBuffer()
      useChainStore.getState().setRunVerdict(d.runId, d.verdict)
      break
    }
    case 'chain.run.complete': {
      const d = msg.data as { runId: string; status: string }
      flushChainResultBuffer()
      useChainStore.getState().setRunStatus(d.runId, d.status === 'stopped' ? 'stopped' : 'complete')
      break
    }
    case 'fuzzer.complete': {
      const d = msg.data as { campaignId: string; status: string }
      useFuzzStore.getState().setCampaignStatus(d.campaignId, d.status === 'stopped' ? 'stopped' : 'completed')
      break
    }
    case 'detect.finding': {
      const d = msg.data as { finding: Finding; isNew: boolean }
      findingBuffer.push(d.finding)
      if (!findingRafScheduled) {
        findingRafScheduled = true
        requestAnimationFrame(flushFindingBuffer)
      }
      break
    }
    case 'detect.summary': {
      useDetectStore.getState().setSummary(msg.data as DetectSummary)
      break
    }
    case 'detect.scan.started': {
      const d = msg.data as { jobId: string; kind: string; total: number }
      useDetectStore.getState().setScan({
        running: true,
        jobId: d.jobId,
        kind: d.kind,
        scanned: 0,
        total: d.total,
        findingsNew: 0,
        status: 'running',
      })
      break
    }
    case 'detect.scan.progress': {
      const d = msg.data as { scanned: number; total: number; findingsNew: number }
      pendingScanProgress = { scanned: d.scanned, total: d.total, findingsNew: d.findingsNew }
      if (!scanProgressRafScheduled) {
        scanProgressRafScheduled = true
        requestAnimationFrame(flushScanProgress)
      }
      break
    }
    case 'detect.scan.complete': {
      const d = msg.data as {
        status: string
        scanned: number
        findingsNew: number
      }
      useDetectStore.getState().setScan({
        running: false,
        scanned: d.scanned,
        findingsNew: d.findingsNew,
        status: d.status,
      })
      // Completion is toasted; the start is not, since the operator clicked it.
      useToastStore
        .getState()
        .addToast(
          `Detection scan ${d.status} - ${d.findingsNew} new finding${d.findingsNew === 1 ? '' : 's'}`,
          'info'
        )
      // Per-finding events are suppressed during a rescan, so reload the table.
      useDetectStore.getState().invalidate()
      break
    }
    case 'detect.findings.cleared': {
      useDetectStore.getState().clearAll()
      break
    }
    case 'detect.rules.changed': {
      // Force the rules view to refetch on next mount.
      useDetectStore.setState({ rulesLoaded: false })
      break
    }
    case 'echo.summary': {
      useEchoStore.getState().setSummary(msg.data as EchoSummary)
      break
    }
    case 'echo.reflection': {
      // The payload carries counts, not a row: a map row is an aggregate over
      // every message that carried the parameter, so it cannot be merged
      // client-side. Coalesce into one reload per frame instead.
      scheduleEchoReload()
      break
    }
    case 'echo.scan.started': {
      const d = msg.data as { jobId: string; total: number }
      useEchoStore.getState().setScan({
        running: true,
        jobId: d.jobId,
        scanned: 0,
        total: d.total,
        status: 'running',
      })
      break
    }
    case 'echo.scan.progress': {
      const d = msg.data as { jobId: string; scanned: number; total: number }
      useEchoStore.getState().setScan({
        running: true,
        jobId: d.jobId,
        scanned: d.scanned,
        total: d.total,
        status: 'running',
      })
      break
    }
    case 'echo.scan.complete': {
      const d = msg.data as { status: string; scanned: number }
      useEchoStore.getState().setScan({
        running: false,
        scanned: d.scanned,
        total: d.scanned,
        status: d.status,
      })
      useEchoStore.getState().invalidate()
      break
    }
    case 'automation.script.state': {
      // The only automation event that is not polled, and the only one an agent does not
      // cause: the runaway breaker pausing an automation the operator armed. Waiting for
      // the next poll to learn that something stopped itself is the wrong default.
      const d = msg.data as { id?: string; paused?: boolean; pausedReason?: string }
      // The toast says it happened; the refresh is what makes the row agree.
      useAutomationStore.getState().refreshScripts()
      if (d?.paused) {
        useToastStore
          .getState()
          .addToast(`Automation ${d.id ?? ''} was paused: ${d.pausedReason ?? 'runaway'}`, 'error')
      }
      break
    }
    case 'webhook.state': {
      // The only webhook event on the bus, and the only state change an operator did not
      // make: the runaway breaker pausing one they armed. Per-delivery events would be a
      // firehose, and the editor polls its delivery log instead.
      const d = msg.data as { id?: string; paused?: boolean; pausedReason?: string }
      useWebhookStore.getState().invalidate()
      useWebhookStore.getState().refresh()
      if (d?.paused) {
        useToastStore
          .getState()
          .addToast(`Webhook ${d.id ?? ''} was paused: ${d.pausedReason ?? 'runaway'}`, 'error')
      }
      break
    }
    case 'automation.script.stored': {
      // The second state change the operator did not make: a token stored or replaced an
      // automation. The Automations panel loads on mount and after its own actions and
      // nothing else, so without this a package stored while they are looking at that
      // panel stays invisible until they leave it and come back.
      const d = msg.data as { id?: string; author?: string; created?: boolean }
      useAutomationStore.getState().refreshScripts()
      // Toasted on a new automation only. A replacement is already visible in the row's
      // hash and revision count, and an agent iterating on a draft must not be able to
      // fill the screen with notifications.
      if (d?.created) {
        useToastStore
          .getState()
          .addToast(
            `${d.author ?? 'An automation token'} stored automation ${d.id ?? ''} - review it in Settings → Automation`,
            'info'
          )
      }
      break
    }
    default:
      if (msg.type.startsWith('plugin.')) {
        pluginEventListeners.forEach((fn) => fn(msg))
      }
      break
  }
}

// ---------------------------------------------------------------------------
// Sliver event listener API
// ---------------------------------------------------------------------------

export type SliverEvent = {
  eventType: string
  session?: { id: string; name: string; hostname: string; os: string; arch: string; remoteAddress: string; transport: string; username: string }
  beacon?: { id: string; name: string; hostname: string; os: string; arch: string; remoteAddress: string; transport: string; username: string }
  jobId?: number
  jobName?: string
  err?: string
}

type SliverEventListener = (ev: SliverEvent) => void
const sliverEventListeners = new Set<SliverEventListener>()

export function onSliverEvent(fn: SliverEventListener): () => void {
  sliverEventListeners.add(fn)
  return () => { sliverEventListeners.delete(fn) }
}

// ---------------------------------------------------------------------------
// Mythic event listener API
// ---------------------------------------------------------------------------

export type MythicEvent = {
  eventType: string
  callback?: { id: number; display_id: number; user: string; host: string; os: string; architecture: string; ip: string; payload_type: string }
}

type MythicEventListener = (ev: MythicEvent) => void
const mythicEventListeners = new Set<MythicEventListener>()

export function onMythicEvent(fn: MythicEventListener): () => void {
  mythicEventListeners.add(fn)
  return () => { mythicEventListeners.delete(fn) }
}

// ---------------------------------------------------------------------------
// Plugin event listener API
// ---------------------------------------------------------------------------

type PluginEventListener = (ev: WSMessage) => void
const pluginEventListeners = new Set<PluginEventListener>()

export function onPluginEvent(fn: PluginEventListener): () => void {
  pluginEventListeners.add(fn)
  return () => { pluginEventListeners.delete(fn) }
}
