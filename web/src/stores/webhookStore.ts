import { create } from 'zustand'
import {
  api,
  type Webhook,
  type WebhookAuthKind,
  type WebhookDelivery,
  type WebhookFormat,
  type WebhookToken,
} from '../lib/api'

/**
 * The operator's outbound endpoints, plus the vocabulary for authoring one.
 *
 * Thin on purpose, following triggerStore: the list plus a refetch, with create, update and
 * delete called on `api` directly and followed by a reload. The server normalizes a webhook and
 * computes `problem` on the way out, so an optimistic local copy would buy nothing and could
 * disagree with what the dispatcher actually armed.
 *
 * Not part of settingsStore. That blob is machine-level scalars; this is a set of named objects
 * with their own endpoints, their own secrets, and a file of their own.
 */
interface WebhookState {
  webhooks: Webhook[]

  /** The authoring vocabulary, served rather than hardcoded so the editor cannot offer a
   *  format or a placeholder the server would refuse. */
  formats: WebhookFormat[]
  deliveries: WebhookDelivery[]
  authKinds: WebhookAuthKind[]
  methods: string[]
  tokens: WebhookToken[]
  /** Which event fields a body template may name, per event. */
  fields: Record<string, string[]>
  limits: {
    webhooks: number
    triggers: number
    headers: number
    templateBytes: number
    timeoutMs: number
    retries: number
    minIntervalMs: number
  }

  loaded: boolean
  /** Why the list is empty: null when it loaded, otherwise the server's explanation, which
   *  names the switch that would change the answer. */
  unavailable: string | null

  refresh: () => Promise<void>
  invalidate: () => void
}

const DEFAULT_LIMITS = {
  webhooks: 50,
  triggers: 8,
  headers: 20,
  templateBytes: 16384,
  timeoutMs: 60000,
  retries: 5,
  minIntervalMs: 3600000,
}

export const useWebhookStore = create<WebhookState>((set) => ({
  webhooks: [],
  formats: [],
  deliveries: [],
  authKinds: [],
  methods: [],
  tokens: [],
  fields: {},
  limits: DEFAULT_LIMITS,
  loaded: false,
  unavailable: null,

  refresh: async () => {
    try {
      const d = await api.listWebhooks()
      set({
        webhooks: d.webhooks ?? [],
        formats: d.formats ?? [],
        deliveries: d.deliveries ?? [],
        authKinds: d.authKinds ?? [],
        methods: d.methods ?? [],
        tokens: d.tokens ?? [],
        fields: d.fields ?? {},
        limits: d.limits ?? DEFAULT_LIMITS,
        loaded: true,
        unavailable: null,
      })
    } catch (e) {
      set({
        webhooks: [],
        loaded: true,
        unavailable: String(e instanceof Error ? e.message : e),
      })
    }
  },

  invalidate: () => set({ loaded: false }),
}))
