import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Relative base: the bundle is served by FastAPI from whatever path the
// deployment mounts it at, and an air-gapped install has no CDN to fall back
// on. Everything the page needs ships inside dist/.
export default defineConfig({
  plugins: [react()],
  base: './',
  build: { outDir: 'dist', emptyOutDir: true },
  server: {
    port: 5173,
    proxy: { '/api': 'http://127.0.0.1:8000' },
  },
})
