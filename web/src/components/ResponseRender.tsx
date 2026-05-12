import { useEffect, useMemo, useState } from 'react'
import { createResponseBlobUrl } from '../lib/responseRenderer'

const STORAGE_KEY = 'joro-render-pretty-json'

export function usePrettyJson(): [boolean, (next: boolean) => void] {
  const [prettyJson, setPrettyJson] = useState(() => localStorage.getItem(STORAGE_KEY) !== 'false')
  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, String(prettyJson))
  }, [prettyJson])
  return [prettyJson, setPrettyJson]
}

type Props = { raw: string; prettyJson: boolean }

export function ResponseRender({ raw, prettyJson }: Props) {
  const url = useMemo(() => createResponseBlobUrl(raw, { prettyJson }), [raw, prettyJson])
  useEffect(() => () => URL.revokeObjectURL(url), [url])

  return (
    <iframe
      src={url}
      sandbox="allow-same-origin"
      className="absolute inset-0 w-full h-full"
      style={{ colorScheme: 'light dark' }}
      title="Rendered response"
    />
  )
}
