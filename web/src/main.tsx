import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
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

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
)
