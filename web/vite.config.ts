import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://localhost:9090',
      '/ws': {
        target: 'ws://localhost:9090',
        ws: true,
      },
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          codemirror: [
            '@uiw/react-codemirror',
            '@codemirror/lang-javascript',
            '@codemirror/lang-html',
            '@codemirror/lang-json',
            '@codemirror/lang-css',
            '@codemirror/theme-one-dark',
          ],
        },
      },
    },
  },
})
