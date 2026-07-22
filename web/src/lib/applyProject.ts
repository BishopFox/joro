import { api } from './api'
import { useRequestStore } from '../stores/requestStore'
import { useSettingsStore, type Settings } from '../stores/settingsStore'

// applyProjectResp propagates a project load/switch response to global live
// state: it invalidates cached request history, refreshes settings into the
// store, and dispatches `joro:project-changed` so the app can re-evaluate team
// mode. Page-local rule state (scope / match&replace / custom data) is refreshed
// by those pages when they next mount, so it isn't touched here.
export function applyProjectResp(_resp: unknown): void {
  useRequestStore.getState().invalidate()
  api
    .getSettings()
    .then((s) => useSettingsStore.getState().setSettings(s as Settings))
    .catch(() => {})
  window.dispatchEvent(new CustomEvent('joro:project-changed'))
}
