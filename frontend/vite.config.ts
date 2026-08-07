import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://localhost:8000',
      '/install': 'http://localhost:8000',
      '/agent': { target: 'http://localhost:8000', ws: true },
      '/ws': { target: 'http://localhost:8000', ws: true },
    },
  },
})
