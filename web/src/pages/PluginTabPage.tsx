import { useParams } from 'react-router-dom'
import { currentTheme } from '../lib/theme'

export default function PluginTabPage() {
  const { extName } = useParams()

  if (!extName) {
    return (
      <div className="flex items-center justify-center h-full">
        <span className="text-content-muted text-sm">Plugin not found</span>
      </div>
    )
  }

  return (
    <iframe
      src={`/plugin/${extName}/?theme=${currentTheme()}`}
      className="w-full h-full border-0"
      sandbox="allow-scripts allow-forms allow-same-origin"
      title={extName}
    />
  )
}
