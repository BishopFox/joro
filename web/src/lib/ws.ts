import { useCallbackStore, type CallbackInteraction } from '../stores/callbackStore'
import { useFuzzStore, type FuzzResult } from '../stores/fuzzStore'
import { useToastStore } from '../stores/toastStore'
import { useInterceptStore } from '../stores/interceptStore'
import { useManipulateWSStore, type WSFrameEntry } from '../stores/manipulateWSStore'
import { useRequestStore, type RequestSummary } from '../stores/requestStore'
import { useTeamStore, type ChatMessage } from '../stores/teamStore'
import { useTeamFlaggedStore, type FlaggedSummary } from '../stores/teamFlaggedStore'
import { useTeamSharedConfigStore, type SharedConfigSummary } from '../stores/teamSharedConfigStore'
import { useUpdateStore } from '../stores/updateStore'
import { useWSStore } from '../stores/wsStore'
import { useXSSHunterStore, type XSSFire } from '../stores/xssHunterStore'
import type { CapturedWSMessage } from './api'

type WSMessage = {
  type: string
  data: unknown
}

let ws: WebSocket | null = null
let reconnectTimer: ReturnType<typeof setTimeout> | null = null

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

export function connectWS() {
  if (ws && ws.readyState < WebSocket.CLOSING) return

  const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
  ws = new WebSocket(`${protocol}://${window.location.host}/ws`)

  ws.onopen = () => {
    // If we were updating and the WebSocket reconnected, the server restarted.
    if (useUpdateStore.getState().updating) {
      window.location.reload()
    }
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
      const item = msg.data as { id: string; method: string; url: string; host: string; reqRaw: string }
      useInterceptStore.getState().addItem({
        id: item.id,
        method: item.method,
        url: item.url,
        host: item.host,
        reqRaw: item.reqRaw,
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
      const presence = msg.data as { users: string[] }
      useTeamStore.getState().setActiveUsers(presence.users || [])
      break
    }
    case 'team.nickname_changed': {
      const d = msg.data as { oldNickname: string; newNickname: string }
      useTeamStore.getState().handleNicknameChange(d.oldNickname, d.newNickname)
      break
    }
    case 'team.relay.error': {
      const d = msg.data as { message: string }
      useToastStore.getState().addToast(d.message)
      break
    }
    case 'sliver.event': {
      const ev = msg.data as SliverEvent
      sliverEventListeners.forEach((fn) => fn(ev))
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
    case 'fuzzer.complete': {
      const d = msg.data as { campaignId: string; status: string }
      useFuzzStore.getState().setCampaignStatus(d.campaignId, d.status === 'stopped' ? 'stopped' : 'completed')
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
// Plugin event listener API
// ---------------------------------------------------------------------------

type PluginEventListener = (ev: WSMessage) => void
const pluginEventListeners = new Set<PluginEventListener>()

export function onPluginEvent(fn: PluginEventListener): () => void {
  pluginEventListeners.add(fn)
  return () => { pluginEventListeners.delete(fn) }
}
