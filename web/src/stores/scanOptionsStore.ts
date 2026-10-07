import { create } from 'zustand'

// The target a scan-options dialog was opened for. Mirrors the fields
// initiateScan takes, minus the options the dialog itself collects.
export interface ScanTarget {
  scope: 'host' | 'request'
  origin?: string
  url?: string
  requestId?: string
  // label is a human description of the target for the dialog header.
  label: string
}

interface ScanOptionsState {
  open: boolean
  target: ScanTarget | null
  openScan: (target: ScanTarget) => void
  close: () => void
}

// A global modal, mounted once in App, so the "Scan with options…" context-menu
// item on any page can open it without each page hosting the dialog.
export const useScanOptionsStore = create<ScanOptionsState>((set) => ({
  open: false,
  target: null,
  openScan: (target) => set({ open: true, target }),
  close: () => set({ open: false, target: null }),
}))
