import { api } from './api'
import { useDetectStore } from '../stores/detectStore'
import { useRequestStore } from '../stores/requestStore'
import { useSettingsStore, type Settings } from '../stores/settingsStore'
import { useSJStore } from '../stores/sjStore'
import { useEchoStore } from '../stores/echoStore'
import { useChainStore } from '../stores/chainStore'
import { useActiveScanStore } from '../stores/activeScanStore'

// applyProjectResp propagates a project load/switch response to global live
// state: it invalidates cached request history, refreshes settings into the
// store, and dispatches `joro:project-changed` so the app can re-evaluate team
// mode. Page-local rule state (scope / match&replace / custom data) is refreshed
// by those pages when they next mount, so it isn't touched here.
export function applyProjectResp(_resp: unknown): void {
  useRequestStore.getState().invalidate()
  // Findings live in the project file, so a switch or import drops the previous
  // project's findings.
  useDetectStore.getState().clearAll()
  useDetectStore.getState().invalidate()
  // SJ holds the previous engagement's documents, targets and — crucially —
  // auth profiles, whose credentials are session state that must not follow the
  // operator into the next project.
  useSJStore.getState().clearAll()
  // The reflection map is derived from the history being replaced; the server
  // clears its copy on the same switch, and the page refetches on mount.
  useEchoStore.getState().clearAll()
  // Chains themselves travel in the project file and are refetched when the Chain
  // page mounts. Their runs do not: a run's rows reference History from the
  // previous engagement, and its verdicts were computed against a baseline
  // measured there.
  useChainStore.getState().clearAll()
  useActiveScanStore.getState().clear()
  api
    .getSettings()
    .then((s) => useSettingsStore.getState().setSettings(s as Settings))
    .catch(() => {})
  window.dispatchEvent(new CustomEvent('joro:project-changed'))
}
