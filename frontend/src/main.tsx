import React from 'react'
import ReactDOM from 'react-dom/client'
// self-hosted terminal font (woff2 bundled by Vite, served from 'self' per CSP) —
// no more silent fallback to Menlo on machines without JetBrains Mono installed
import '@fontsource/jetbrains-mono/400.css'
import '@fontsource/jetbrains-mono/700.css'
import App from './App'
import TooltipLayer from './components/TooltipLayer'
import './index.css'
import { applyTheme, currentTheme } from './lib/theme'
import { showFailsafe } from './lib/failsafe'
import { I18nProvider } from './lib/i18n'

applyTheme(currentTheme())

// iOS Safari nu redimensionează layout-ul când apare tastatura virtuală (doar
// visual viewport-ul) → terminalul și keybar-ul rămâneau sub tastatură. Când
// diferența față de fereastră e mare (= tastatură deschisă), limităm înălțimea
// aplicației la visual viewport; pragul de 80px lasă pinch-zoom-ul în pace.
// Android e rezolvat declarativ (interactive-widget=resizes-content în meta).
const vv = window.visualViewport
if (vv) {
  const applyViewport = () => {
    if (window.innerHeight - vv.height > 80) {
      document.documentElement.style.setProperty('--app-height', `${Math.round(vv.height)}px`)
    } else {
      document.documentElement.style.removeProperty('--app-height')
    }
  }
  vv.addEventListener('resize', applyViewport)
  applyViewport()
}

// Ultimul gard din interiorul React-ului: un crash de randare de după boot ar
// demonta altfel tot arborele (ecran alb). Predăm eroarea paginii statice de
// failsafe (public/failsafe.js) — cea cu diagnostic + reload + instrucțiuni de
// rollback. Fallback-ul text de mai jos rămâne doar pentru cazul (teoretic) în
// care failsafe.js nu s-a încărcat.
class ErrorBoundary extends React.Component<{ children: React.ReactNode }, { failed: boolean }> {
  state = { failed: false }
  static getDerivedStateFromError() {
    return { failed: true }
  }
  componentDidCatch(err: unknown) {
    showFailsafe(err instanceof Error ? `${err.name}: ${err.message}` : String(err))
  }
  render() {
    if (this.state.failed) {
      return (
        <div style={{ padding: 24, fontFamily: 'monospace', color: '#cbd5e1' }}>
          WebTerm hit a fatal error — reload the page.
        </div>
      )
    }
    return this.props.children
  }
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <I18nProvider>
        <App />
        <TooltipLayer />
      </I18nProvider>
    </ErrorBoundary>
  </React.StrictMode>,
)
