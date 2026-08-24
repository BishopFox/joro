import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router'
import App from './App'
import './index.css'

const THEME_RENAMES: Record<string, string> = {
  'bf-dark': 'bishop-fox',
  'bf-light': 'bishop-fox',
  'miami-dark': 'miami',
  'miami-light': 'miami',
  'purple-dark': 'purple',
  'purple-light': 'purple',
}
const savedTheme = localStorage.getItem('joro-theme')
if (savedTheme) {
  const theme = THEME_RENAMES[savedTheme] ?? savedTheme
  if (theme !== savedTheme) localStorage.setItem('joro-theme', theme)
  document.documentElement.setAttribute('data-theme', theme)
}

// Streamer mode, applied before the first paint for the same reason as the theme:
// the CSS-painted fields must already be black when the page renders. Kept in step
// with applyAttr in stores/streamerStore.ts, which owns the attribute thereafter.
try {
  const rawStreamer = localStorage.getItem('joro-streamer')
  if (rawStreamer && JSON.parse(rawStreamer)?.enabled === true) {
    document.documentElement.setAttribute('data-streamer', 'on')
  }
} catch {
  /* ignore parse / privacy-mode failures */
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
)
