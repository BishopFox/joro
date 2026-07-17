// Testing-browser launch preferences, persisted in localStorage and shared by
// the Settings section and the first-run health check.

const URL_KEY = 'joro-testbrowser-url'

export interface BrowserPrefs {
  url: string
}

export function getBrowserPrefs(): BrowserPrefs {
  return { url: localStorage.getItem(URL_KEY) || '' }
}

export function setBrowserPrefs(p: Partial<BrowserPrefs>): void {
  if (p.url !== undefined) localStorage.setItem(URL_KEY, p.url)
}
