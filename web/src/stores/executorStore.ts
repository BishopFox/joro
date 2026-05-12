import { create } from 'zustand'
import type { ExecProviderInfo, PluginProviderStatus } from '../lib/api'

export interface OutputLine {
  type: 'cmd' | 'out' | 'err'
  text: string
}

const MAX_HISTORY = 100

interface ExecutorState {
  execMode: string
  providers: ExecProviderInfo[]
  target: string
  webshell: string
  authKey: string
  configText: string
  sliverConnected: boolean
  activeSessionName: string
  pluginStatus: Record<string, PluginProviderStatus>
  pluginConfigValues: Record<string, Record<string, string>>
  outputByMode: Record<string, OutputLine[]>
  historyByMode: Record<string, string[]>
  commandByMode: Record<string, string>

  setExecMode: (mode: string) => void
  setProviders: (providers: ExecProviderInfo[]) => void
  setTarget: (v: string) => void
  setWebshell: (v: string) => void
  setAuthKey: (v: string) => void
  setConfigText: (v: string) => void
  setSliverConnected: (v: boolean) => void
  setActiveSessionName: (v: string) => void
  setPluginStatus: (name: string, status: PluginProviderStatus) => void
  setPluginConfigValue: (plugin: string, field: string, value: string) => void
  setCommand: (v: string) => void
  appendOutput: (line: OutputLine) => void
  popOutput: () => void
  clearOutput: () => void
  pushHistory: (cmd: string) => void
}

export const useExecutorStore = create<ExecutorState>((set) => ({
  execMode: 'webshell',
  providers: [],
  target: '',
  webshell: '',
  authKey: '',
  configText: '',
  sliverConnected: false,
  activeSessionName: '',
  pluginStatus: {},
  pluginConfigValues: {},
  outputByMode: {},
  historyByMode: {},
  commandByMode: {},

  setExecMode: (execMode) => set({ execMode }),
  setProviders: (providers) => set({ providers }),
  setTarget: (target) => set({ target }),
  setWebshell: (webshell) => set({ webshell }),
  setAuthKey: (authKey) => set({ authKey }),
  setConfigText: (configText) => set({ configText }),
  setSliverConnected: (sliverConnected) => set({ sliverConnected }),
  setActiveSessionName: (activeSessionName) => set({ activeSessionName }),
  setPluginStatus: (name, status) =>
    set((s) => ({ pluginStatus: { ...s.pluginStatus, [name]: status } })),
  setPluginConfigValue: (plugin, field, value) =>
    set((s) => ({
      pluginConfigValues: {
        ...s.pluginConfigValues,
        [plugin]: { ...(s.pluginConfigValues[plugin] ?? {}), [field]: value },
      },
    })),
  setCommand: (command) =>
    set((s) => ({ commandByMode: { ...s.commandByMode, [s.execMode]: command } })),
  appendOutput: (line) =>
    set((s) => ({
      outputByMode: {
        ...s.outputByMode,
        [s.execMode]: [...(s.outputByMode[s.execMode] ?? []), line],
      },
    })),
  popOutput: () =>
    set((s) => ({
      outputByMode: {
        ...s.outputByMode,
        [s.execMode]: (s.outputByMode[s.execMode] ?? []).slice(0, -1),
      },
    })),
  clearOutput: () =>
    set((s) => ({ outputByMode: { ...s.outputByMode, [s.execMode]: [] } })),
  pushHistory: (cmd) =>
    set((s) => {
      const next = [...(s.historyByMode[s.execMode] ?? []), cmd]
      if (next.length > MAX_HISTORY) next.shift()
      return { historyByMode: { ...s.historyByMode, [s.execMode]: next } }
    }),
}))
