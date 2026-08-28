import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        // Vendorii pe chunk-uri proprii, cu alt ritm de schimbare decât aplicația:
        // la fiecare release, un browser care revine re-descarcă DOAR codul nostru
        // (~x00KB), nu și React/xterm (neschimbate luni întregi → cache hit). Tot
        // asta duce chunk-ul principal sub pragul de 500KB la care vite avertiza
        // în fiecare build (și avertismentele repetate ajung ignorate, exact ca
        // alertele false). NUMELE contează: un chunk pe pachet, stabil.
        manualChunks: {
          'vendor-react': ['react', 'react-dom'],
          'vendor-xterm': ['@xterm/xterm', '@xterm/addon-fit', '@xterm/addon-search',
                           '@xterm/addon-web-links'],
        },
      },
    },
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8000',
      '/install': 'http://localhost:8000',
      '/agent': { target: 'http://localhost:8000', ws: true },
      '/ws': { target: 'http://localhost:8000', ws: true },
    },
  },
})
