import { useEffect, useState } from 'react'
import { useLocation } from 'react-router-dom'
import ManipulateHTTP from './ManipulateHTTP'
import ManipulateWS from './ManipulateWS'

type SubTab = 'http' | 'ws'

export default function Manipulate() {
  const location = useLocation()
  const [subTab, setSubTab] = useState<SubTab>('http')

  // If we were navigated here from "Send to Manipulate" with an explicit sub-tab,
  // honor it on mount.
  useEffect(() => {
    const state = location.state as { subTab?: SubTab } | null
    if (state?.subTab === 'ws' || state?.subTab === 'http') {
      setSubTab(state.subTab)
    }
  }, [location.state])

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <div className="flex items-center gap-0.5 px-2 py-1 bg-surface-card border-b border-border shrink-0">
        <SubTabButton active={subTab === 'http'} onClick={() => setSubTab('http')}>HTTP</SubTabButton>
        <SubTabButton active={subTab === 'ws'} onClick={() => setSubTab('ws')}>WebSocket</SubTabButton>
      </div>
      {subTab === 'http' ? <ManipulateHTTP /> : <ManipulateWS />}
    </div>
  )
}

function SubTabButton({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className={`px-3 py-1 rounded-sm text-xs font-semibold transition-colors ${
        active
          ? 'bg-accent text-content-primary'
          : 'text-content-secondary hover:text-content-primary hover:bg-surface-input'
      }`}
    >
      {children}
    </button>
  )
}
