import { useRef } from 'react'
import type { ConfigField, PluginProviderStatus } from '../lib/api'

interface DynamicConfigFormProps {
  schema: ConfigField[]
  values: Record<string, string>
  onValueChange: (name: string, value: string) => void
  status: PluginProviderStatus | null
  connecting: boolean
  onConnect: () => void
  onDisconnect: () => void
}

export default function DynamicConfigForm({
  schema,
  values,
  onValueChange,
  status,
  connecting,
  onConnect,
  onDisconnect,
}: DynamicConfigFormProps) {
  const fileInputRefs = useRef<Record<string, HTMLInputElement | null>>({})

  const connected = status?.connected ?? false

  function handleFileChange(name: string, e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => onValueChange(name, reader.result as string)
    reader.readAsText(file)
  }

  if (connected) {
    return (
      <div className="flex items-center gap-3">
        <span className="text-xs text-semantic-success font-semibold">Connected</span>
        {status?.displayInfo && Object.entries(status.displayInfo).map(([k, v]) => (
          <span key={k} className="text-xs text-content-secondary">
            {k}: <span className="text-accent-secondary font-semibold">{v}</span>
          </span>
        ))}
        <div className="flex-1" />
        <button
          onClick={onDisconnect}
          className="px-3 py-1.5 rounded-sm bg-semantic-error-bg hover:bg-semantic-error-hover text-content-primary text-xs font-semibold"
        >
          Disconnect
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {schema.map((field) => (
          <div key={field.name}>
            <label className="text-xs text-content-muted block mb-1">
              {field.label}
              {field.required && <span className="text-semantic-error ml-0.5">*</span>}
            </label>
            {field.type === 'textarea' ? (
              <textarea
                value={values[field.name] || ''}
                onChange={(e) => onValueChange(field.name, e.target.value)}
                placeholder={field.placeholder}
                rows={3}
                className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border font-mono resize-none"
              />
            ) : field.type === 'checkbox' ? (
              <label className="flex items-center gap-2 text-xs text-content-secondary cursor-pointer h-[30px]">
                <input
                  type="checkbox"
                  checked={values[field.name] === 'true'}
                  onChange={(e) => onValueChange(field.name, e.target.checked ? 'true' : 'false')}
                />
                <span>{field.placeholder || field.label}</span>
              </label>
            ) : field.type === 'file' ? (
              <div className="flex gap-2">
                <input
                  value={values[field.name] ? '(file loaded)' : ''}
                  readOnly
                  placeholder={field.placeholder || 'Upload file...'}
                  className="flex-1 bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
                />
                <label className="px-3 py-1.5 rounded-sm bg-surface-input border border-border text-xs text-content-secondary hover:bg-surface-hover cursor-pointer">
                  Upload
                  <input
                    type="file"
                    ref={(el) => { fileInputRefs.current[field.name] = el }}
                    onChange={(e) => handleFileChange(field.name, e)}
                    className="hidden"
                  />
                </label>
              </div>
            ) : (
              <input
                type={field.type === 'password' ? 'password' : 'text'}
                value={values[field.name] || ''}
                onChange={(e) => onValueChange(field.name, e.target.value)}
                placeholder={field.placeholder}
                className="w-full bg-surface-input text-xs px-2 py-1.5 rounded-sm border border-border"
              />
            )}
            {field.helpText && (
              <p className="text-[10px] text-content-muted mt-0.5">{field.helpText}</p>
            )}
          </div>
        ))}
      </div>
      <button
        onClick={onConnect}
        disabled={connecting}
        className="px-3 py-1.5 rounded-sm bg-accent-tertiary hover:bg-accent-tertiary-hover text-black text-xs font-semibold disabled:opacity-50"
      >
        {connecting ? 'Connecting...' : 'Connect'}
      </button>
    </div>
  )
}
