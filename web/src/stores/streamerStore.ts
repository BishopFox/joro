import { useCallback } from 'react'
import { create } from 'zustand'
import { redactValue, type Sensitivity } from '../lib/redact'

// Streamer mode is a property of this operator's screen, not of the engagement,
// so it stays in localStorage. A project config is published to teammates, and a
// User Config snapshot would silently switch the mode off mid-stream when loaded.

const STORAGE_KEY = 'joro-streamer'
export const STREAMER_VERSION = 1

export interface StreamerPrefs {
  version: number
  enabled: boolean
}

function defaults(): StreamerPrefs {
  return { version: STREAMER_VERSION, enabled: false }
}

/** sanitize is the single gate for stored prefs. A bumped version with no
 *  migration step here silently resets the operator's choice — add the step. */
export function sanitize(raw: unknown): StreamerPrefs {
  if (!raw || typeof raw !== 'object') return defaults()
  const obj = raw as Partial<StreamerPrefs>
  if (obj.version !== STREAMER_VERSION) return defaults()
  return { version: STREAMER_VERSION, enabled: obj.enabled === true }
}

function load(): StreamerPrefs {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return defaults()
    return sanitize(JSON.parse(raw))
  } catch {
    return defaults()
  }
}

function persist(prefs: StreamerPrefs) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs))
  } catch {
    /* ignore quota / privacy-mode failures */
  }
}

/**
 * applyAttr mirrors the pref onto <html> so the CSS-painted inputs follow the
 * same switch as the transformed text. main.tsx sets the same attribute from
 * the same key before React mounts, which is what keeps a reload from painting
 * one frame of real values — the two must stay in step.
 */
function applyAttr(enabled: boolean) {
  if (enabled) document.documentElement.setAttribute('data-streamer', 'on')
  else document.documentElement.removeAttribute('data-streamer')
}

interface StreamerState {
  enabled: boolean
  setEnabled: (v: boolean) => void
  toggle: () => void
}

export const useStreamerStore = create<StreamerState>((set, get) => ({
  enabled: load().enabled,
  setEnabled: (v) => {
    persist({ version: STREAMER_VERSION, enabled: v })
    applyAttr(v)
    set({ enabled: v })
  },
  toggle: () => get().setEnabled(!get().enabled),
}))

/**
 * useRedact returns a redactor bound to the live toggle, so flipping the switch
 * re-renders every consumer. Use it for SVG labels and title= attributes; plain
 * text spans have the <Redacted> component.
 */
export function useRedact(): (v: string, kind?: Sensitivity) => string {
  const on = useStreamerStore((s) => s.enabled)
  return useCallback((v: string, kind?: Sensitivity) => (on ? redactValue(v, kind) : v), [on])
}

/**
 * redactNow is the redactor for a string composed before it is rendered — a
 * toast, a confirmation sentence, anything where the sensitive value is baked
 * into a larger message and <Redacted> cannot wrap just that part.
 *
 * It reads the toggle at call time rather than through a hook, so it also works
 * outside React (the WebSocket dispatcher raises toasts of its own). The value
 * is frozen at composition, so a message raised before the mode is switched on
 * keeps whatever it captured — bar at the moment of composing, not later.
 */
export function redactNow(v: string, kind?: Sensitivity): string {
  return useStreamerStore.getState().enabled ? redactValue(v, kind) : v
}
