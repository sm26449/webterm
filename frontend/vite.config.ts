import react from '@vitejs/plugin-react'
import { dirname } from 'node:path'
import type { Plugin as EsbuildPlugin } from 'esbuild'
import { defineConfig, type Plugin } from 'vite'

// monaco-editor 0.57 NU foloseşte pachetul npm `dompurify`: are propria copie, DOMPurify 3.4.15
// (esm/vs/base/browser/dompurify/dompurify.js), cu 5 avertismente XSS (GHSA-p98j-92pf-mc4p şi
// înrudite, reparate în 3.4.17). `overrides` din package.json schimbă doar ce citesc scanerele
// (npm audit / Trivy erau verzi, editorul rula tot 3.4.15) — de aici redirecţionarea importului
// spre pachetul `dompurify` pinuit în overrides. Fail closed: dacă monaco mută fişierul şi
// redirecţionarea nu se mai aplică, build-ul PICĂ, nu livrează tăcut copia veche. Când o versiune
// monaco aduce DOMPurify >= 3.4.17, scoateţi plugin-ul şi intrarea din overrides împreună.
// Aceleaşi două teste în ambele plugin-uri (rollup pentru build, esbuild pentru dev).
const MONACO_IMPORTER = /[\\/]monaco-editor[\\/]/
const VENDORED_DOMPURIFY = /(^|\/)dompurify\/dompurify\.js$/

function monacoPatchedDompurify(): Plugin {
  let hits = 0
  let building = false
  return {
    name: 'webterm-monaco-dompurify',
    enforce: 'pre',
    configResolved(cfg) { building = cfg.command === 'build' },
    async resolveId(source, importer, options) {
      if (!importer || !MONACO_IMPORTER.test(importer)) return null
      if (!VENDORED_DOMPURIFY.test(source)) return null
      const r = await this.resolve('dompurify', importer, { ...options, skipSelf: true })
      if (!r) this.error('pachetul dompurify lipseşte: monaco ar rula copia sa vulnerabilă')
      hits++
      return r
    },
    buildEnd(err) {
      if (building && !err && hits === 0) {
        this.error('monaco nu mai importă dompurify/dompurify.js: verificaţi ce DOMPurify livrează ' +
                   'acum şi actualizaţi monacoPatchedDompurify din vite.config.ts')
      }
    },
  }
}

// `vite dev` pre-împachetează monaco cu esbuild (optimizeDeps), pas în care plugin-urile rollup
// de mai sus NU rulează: fără asta, serverul de dezvoltare servea tot copia 3.4.15. Aici nu
// oprim nimic dacă redirecţionarea nu se aplică (ar bloca dev-ul); garda e cea din build.
function monacoPatchedDompurifyDev(): EsbuildPlugin {
  return {
    name: 'webterm-monaco-dompurify-dev',
    setup(build) {
      build.onResolve({ filter: VENDORED_DOMPURIFY }, async (args) => {
        if (!MONACO_IMPORTER.test(args.importer)) return undefined
        const r = await build.resolve('dompurify', { resolveDir: dirname(args.importer), kind: args.kind })
        if (r.errors.length) return { errors: r.errors }
        return { path: r.path }
      })
    },
  }
}

export default defineConfig({
  plugins: [monacoPatchedDompurify(), react()],
  optimizeDeps: {
    esbuildOptions: { plugins: [monacoPatchedDompurifyDev()] },
  },
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
