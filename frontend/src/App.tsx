import { startAuthentication } from '@simplewebauthn/browser'
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import CommandPalette from './components/CommandPalette'
import CredentialModal, { CredField } from './components/CredentialModal'
import SerialModal, { SerialParams } from './components/SerialModal'
import DiagnosticModal from './components/DiagnosticModal'
import Watermark from './components/Watermark'
import Dashboard from './components/Dashboard'
import HostOverview from './components/HostOverview'
import LoginPage from './components/LoginPage'
import KeyboardHelp from './components/KeyboardHelp'
import SnippetParams, { snippetParams } from './components/SnippetParams'
import PaneErrorBoundary from './components/PaneErrorBoundary'
import PopoutView from './components/PopoutView'
import SharedView from './components/SharedView'
import Sidebar from './components/Sidebar'
import SessionView from './components/SessionView'
import TabBar from './components/TabBar'
import Toasts, { ToastItem } from './components/Toasts'
import { errText, api, AppState, Host, Session, Snippet, setStepupHandler } from './lib/api'
import { hostAt } from './lib/host'
import { useI18n } from './lib/i18n'
import { ensureNotificationPermission, notify, registerToast } from './lib/notify'
import { markBooted } from './lib/failsafe'
import { useMetricsTick } from './lib/metrics'
import { matchShortcut, ShortcutId } from './lib/shortcuts'
import { getTimezone } from './lib/tz'

interface Route {
  primary: string | null      // sesiune deschisă (terminal)
  host: number | null         // pagina unui host
  popout: string | null
  shared: string | null
}

function parseHash(): Route {
  const h = window.location.hash
  const base = { primary: null, host: null, popout: null, shared: null }
  const shared = h.match(/^#\/shared\/([A-Za-z0-9_-]+)$/)
  if (shared) return { ...base, shared: shared[1] }
  const pop = h.match(/^#\/popout\/([0-9a-f]{32})$/)
  if (pop) return { ...base, popout: pop[1] }
  const host = h.match(/^#\/h\/(\d+)$/)
  if (host) return { ...base, host: Number(host[1]) }
  const m = h.match(/^#\/s\/([0-9a-f]{32})$/)
  return { ...base, primary: m ? m[1] : null }
}

function useRoute(): [Route, (sid: string | null) => void, (id: number) => void] {
  const [route, setRoute] = useState<Route>(parseHash)
  useEffect(() => {
    const onHash = () => setRoute(parseHash())
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])
  const navigate = (next: string | null) => {
    window.location.hash = next ? `/s/${next}` : ''
  }
  const navigateHost = (id: number) => {
    window.location.hash = `/h/${id}`
  }
  return [route, navigate, navigateHost]
}

const FileBrowser = lazy(() => import('./components/FileBrowser'))
const HistoryModal = lazy(() => import('./components/HistoryModal'))

export function popoutUrl(sid: string): string {
  return `${window.location.origin}${window.location.pathname}#/popout/${sid}`
}

// Anunță watchdog-ul din public/failsafe.js că UI-ul a ajuns la un ecran
// funcțional — fără semnalul ăsta, failsafe-ul afișează pagina de recuperare.
// Montat în fiecare „destinație" de boot (login, app, popout, share), NU în
// ecranul de „Se încarcă…": un boot blocat acolo e exact ce vrem să prindem.
function BootReady() {
  useEffect(() => {
    markBooted()
  }, [])
  return null
}

/* Câte terminale ţinem montate simultan. Fiecare terminal cu scrollback plin ≈ 10-15 MB,
   plus un context WebGL — pe telefon contează.

   `deviceMemory` lipseşte pe Safari şi Firefox, iar `undefined <= 4` e `false`, deci premisa
   „lipseşte ⇒ e desktop, duce 6" era falsă exact pe Safari MOBIL, singurul motor de pe iPhone:
   un telefon primea 6 terminale montate. Când nu ştim memoria, ne uităm dacă e touch — nu e o
   măsurătoare, dar e semnalul corect pentru întrebarea „e un telefon?".

   Constantă de modul, nu valoare din corpul componentei: nu se schimbă în timpul unei sesiuni,
   iar calculată la fiecare randare lipsea din dependenţele memo-ului care o foloseşte. */
const KEEP_ALIVE = (() => {
  const mem = (navigator as { deviceMemory?: number }).deviceMemory
  if (mem !== undefined) return mem <= 4 ? 2 : 6
  // `maxTouchPoints` e 0 în WebKit-ul din harness-ul de CI (deşi e 5 pe iOS real), deci
  // condiţia asta ar fi făcut ca auditul mobil să nu vadă niciodată o regresie aici.
  // `pointer: coarse` singur e adevărat pe toate cele 5 profiluri mobile măsurate.
  const coarse = typeof window.matchMedia === 'function'
    && window.matchMedia('(pointer: coarse)').matches
  return coarse ? 2 : 6
})()

export default function App() {
  const [route] = useRoute()
  // Public read-only share link — no login required.
  if (route.shared)
    return (
      <>
        <BootReady />
        <SharedView token={route.shared} />
      </>
    )
  // Popout window: render only the terminal, no app chrome.
  if (route.popout)
    return (
      <>
        <BootReady />
        <PopoutView sid={route.popout} />
      </>
    )
  return <MainApp />
}

function MainApp() {
  const { t } = useI18n()
  const [appState, setAppState] = useState<AppState | null>(null)
  const [hosts, setHosts] = useState<Host[]>([])
  const [sessions, setSessions] = useState<Session[]>([])
  const [route, navigate, navigateHost] = useRoute()
  const selectedSid = route.primary
  const [filesHost, setFilesHost] = useState<Host | null>(null)
  const [serialHost, setSerialHost] = useState<Host | null>(null)
  const [diagHost, setDiagHost] = useState<Host | null>(null)
  // layout-ul de split se restaurează la reload (înainte murea la orice F5);
  // sesiunea secundară dispărută între timp e curățată de reconcilierea din refresh()
  const [secondSid, setSecondSid] = useState<string | null>(() => {
    try { return JSON.parse(localStorage.getItem('wt_layout') || '{}').second ?? null } catch { return null }
  })
  const [splitRatio, setSplitRatio] = useState<number>(() => {
    try {
      const r = JSON.parse(localStorage.getItem('wt_layout') || '{}').ratio
      return typeof r === 'number' ? Math.min(0.85, Math.max(0.15, r)) : 0.5
    } catch { return 0.5 }
  })
  useEffect(() => {
    localStorage.setItem('wt_layout', JSON.stringify({ second: secondSid, ratio: splitRatio }))
  }, [secondSid, splitRatio])
  // invariant: aceeași sesiune nu poate fi și primară și secundară. Fără gardul
  // ăsta, navigarea directă (TabBar/hash) pe sesiunea din split lăsa panoul
  // principal GOL — stack-ul keep-alive exclude secundarul de la montare
  // (incidentul v1.0.15: „nu mai văd nimic în terminal")
  useEffect(() => {
    if (selectedSid && selectedSid === secondSid) setSecondSid(null)
  }, [selectedSid, secondSid])
  const [activePane, setActivePane] = useState<'primary' | 'second'>('primary')
  const [sidebarOpen, setSidebarOpen] = useState(false)
  // Plierea sidebarului e o preferinţă de spaţiu, nu o stare de sesiune: cine lucrează pe
  // un laptop mic o vrea din prima, la fiecare deschidere. Citită sincron la montare, ca
  // layout-ul să nu sară după primul render.
  const [sidebarCollapsed, setSidebarCollapsed] = useState(
    () => localStorage.getItem('wt-sidebar-collapsed') === '1')
  const toggleSidebar = () => setSidebarCollapsed((v) => {
    localStorage.setItem('wt-sidebar-collapsed', v ? '0' : '1')
    return !v
  })
  const [openTabs, setOpenTabs] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem('wt_tabs') || '[]') } catch { return [] }
  })
  // Ordonarea taburilor DESCHISE: 'manual' (ordinea de deschidere, stabilă) sau 'activity'
  // (după ultima folosire — daily-driver-ele sus). Opt-in; NU atinge arborele de hosturi.
  const [tabSort, setTabSort] = useState<'manual' | 'activity'>(() =>
    localStorage.getItem('wt_tabsort') === 'activity' ? 'activity' : 'manual')
  const [tabUsed, setTabUsed] = useState<Record<string, number>>(() => {
    try { return JSON.parse(localStorage.getItem('wt_tabused') || '{}') } catch { return {} }
  })
  const [addHostSignal, setAddHostSignal] = useState(0)
  const [settingsSignal, setSettingsSignal] = useState(0)
  const [statusSignal, setStatusSignal] = useState(0)
  // activitate pe tab-uri din fundal: ultimul out_offset „văzut" per sesiune.
  // Tab-ul activ e mereu la zi; un tab abia deschis pornește de la offset-ul
  // curent (fără punct instant). Comparația se face pe poll-ul de 5s.
  const seenOffsets = useRef(new Map<string, number>())
  useEffect(() => {
    const bySid = new Map(sessions.map((s) => [s.id, s.out_offset ?? 0]))
    for (const sid of openTabs) {
      const off = bySid.get(sid)
      if (off == null) continue
      if (sid === selectedSid || sid === secondSid || !seenOffsets.current.has(sid)) {
        seenOffsets.current.set(sid, off)
      }
    }
    for (const k of [...seenOffsets.current.keys()]) {
      if (!openTabs.includes(k)) seenOffsets.current.delete(k)
    }
  }, [sessions, selectedSid, secondSid, openTabs])
  const tabActivity = useMemo(() => {
    const set = new Set<string>()
    for (const s of sessions) {
      if (!openTabs.includes(s.id) || s.id === selectedSid || s.id === secondSid) continue
      const seen = seenOffsets.current.get(s.id)
      if (seen != null && (s.out_offset ?? 0) > seen) set.add(s.id)
    }
    return set
  }, [sessions, selectedSid, secondSid, openTabs])
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [showHistory, setShowHistory] = useState(false)
  const [helpOpen, setHelpOpen] = useState(false)
  // snippets în paletă: încărcate o dată la deschiderea ei (nu la fiecare poll)
  const [snippets, setSnippets] = useState<Snippet[]>([])
  const [snipParams, setSnipParams] = useState<Snippet | null>(null)
  useEffect(() => {
    if (paletteOpen) api<Snippet[]>('/api/snippets').then(setSnippets).catch(() => {})
  }, [paletteOpen])
  // inserarea merge la panoul ACTIV, prin același canal ca scurtăturile
  const insertInSession = (body: string) =>
    window.dispatchEvent(new CustomEvent('wt-session-insert', { detail: body }))
  // stiva de tab-uri închise, pentru „redeschide ultimul" (închiderea e doar
  // detach — sesiunea trăiește mai departe, deci redeschiderea e gratuită)
  const closedTabsRef = useRef<string[]>([])
  // pasul între tab-uri (Alt+←/→), circular
  const stepTab = (dir: 1 | -1) => {
    if (openTabs.length < 2 || !selectedSid) return
    const i = openTabs.indexOf(selectedSid)
    if (i === -1) return
    const next = openTabs[(i + dir + openTabs.length) % openTabs.length]
    window.location.hash = `/s/${next}`
  }
  const [credReq, setCredReq] = useState<
    { title: string; subtitle?: string; fields: CredField[]; submitLabel?: string;
      resolve: (v: Record<string, string> | null) => void } | null>(null)
  const askCreds = (spec: { title: string; subtitle?: string; fields: CredField[]; submitLabel?: string }) =>
    new Promise<Record<string, string> | null>((resolve) => setCredReq({ ...spec, resolve }))
  const [pendingSearch, setPendingSearch] = useState<{ term: string; n: number } | null>(null)
  const [toasts, setToasts] = useState<ToastItem[]>([])
  // deploy nou detectat din headerul X-Webterm-Version (vezi lib/api.ts)
  const [newVersion, setNewVersion] = useState<string | null>(null)
  useEffect(() => {
    const onNew = (e: Event) => setNewVersion((e as CustomEvent<string>).detail || '?')
    window.addEventListener('wt-new-version', onNew)
    return () => window.removeEventListener('wt-new-version', onNew)
  }, [])
  // poll-uri eșuate consecutiv: la ≥2, banner „gateway inaccesibil" — altfel
  // căderea serverului e complet silențioasă (datele îngheață fără semnal)
  const [gwFails, setGwFails] = useState(0)
  const onlineRef = useRef<Map<number, boolean> | null>(null)
  // last serialized poll payloads — skip setState (and the re-render) when the
  // 5s poll returns identical data, so the whole fleet doesn't re-render idle.
  const lastHostsRef = useRef('')
  const lastSessionsRef = useRef('')

  useEffect(() => {
    registerToast((message, kind) => {
      const id = `${Date.now()}-${Math.random()}`
      setToasts((t) => [...t, { id, message, kind }])
      setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 6000)
    })
  }, [])

  const refresh = useCallback(async () => {
    try {
      const [h, s] = await Promise.all([
        api<Host[]>('/api/hosts'),
        api<Session[]>('/api/sessions'),
      ])
      const prev = onlineRef.current
      const next = new Map(h.map((host) => [host.id, host.online]))
      if (prev) {
        for (const host of h) {
          if (prev.get(host.id) === true && host.online === false) {
            notify(t('app.hostOffline'), t('app.hostOfflineBody', { name: host.name }), 'warn', `host-offline-${host.id}`)
          }
        }
      }
      onlineRef.current = next
      // skip setState (and the re-render) when the 5s poll returns identical data
      const hj = JSON.stringify(h)
      if (hj !== lastHostsRef.current) { lastHostsRef.current = hj; setHosts(h) }
      const sj = JSON.stringify(s)
      if (sj !== lastSessionsRef.current) { lastSessionsRef.current = sj; setSessions(s) }
      // drop tabs whose session was deleted (reconcile against fresh data)
      setOpenTabs((prev) => {
        const valid = prev.filter((sid) => s.some((x) => x.id === sid))
        return valid.length === prev.length ? prev : valid
      })
      // split-ul restaurat poate referi o sesiune dispărută între timp
      setSecondSid((prev) => (prev && !s.some((x) => x.id === prev) ? null : prev))
      setGwFails(0)
    } catch {
      setGwFails((n) => n + 1)
      const st = await api<AppState>('/api/state').catch(() => null)
      if (st && !st.authenticated) setAppState(st)
    }
  }, [t])

  useEffect(() => {
    api<AppState>('/api/state').then(setAppState).catch(() => setAppState(null))
  }, [])

  useEffect(() => {
    localStorage.setItem('wt_tabs', JSON.stringify(openTabs))
  }, [openTabs])

  useEffect(() => { localStorage.setItem('wt_tabsort', tabSort) }, [tabSort])

  // „ultima folosire" per tab: marcat când tab-ul devine activ (nu la output de fundal —
  // un host care scuipă loguri n-are voie să sară în față). Alimentează sortarea 'activity'.
  useEffect(() => {
    if (!selectedSid) return
    setTabUsed((m) => {
      const next = { ...m, [selectedSid]: Date.now() }
      try { localStorage.setItem('wt_tabused', JSON.stringify(next)) } catch { /* quota */ }
      return next
    })
  }, [selectedSid])

  // deep-link (#/s/<sid> deschis dintr-un URL / PWA proaspăt): sesiunea primară
  // primește tab — altfel ar fi „orfană": fără reprezentare în TabBar, fără
  // indicator de activitate și inaccesibilă cu Alt+N
  useEffect(() => {
    if (selectedSid && sessions.some((s) => s.id === selectedSid)) {
      setOpenTabs((prev) => (prev.includes(selectedSid) ? prev : [...prev, selectedSid]))
    }
  }, [selectedSid, sessions])

  // „You are here" în titlul ferestrei/tab-ului OS: titlu sesiune · user@host.
  // Același loc anunță schimbarea și pentru cititoarele de ecran (regiunea
  // aria-live de mai jos) — altfel comutarea de tab e complet tăcută.
  // istoricul de metrice (ring buffer client-side) se alimentează din poll
  useMetricsTick(hosts)
  const [srAnnounce, setSrAnnounce] = useState('')
  useEffect(() => {
    const s = sessions.find((x) => x.id === selectedSid)
    if (s) {
      const h = hosts.find((x) => x.id === s.host_id)
      document.title = `${s.title || t('app.sessionFallback')}${h ? ' · ' + hostAt(h) : ''} · WebTerm`
      // Efectul se re-execută când sesiunea trece pe `lost`, iar anunţul spunea tot
      // „is active" — un utilizator de screen reader primea exact informaţia inversă,
      // în timp ce panoul vizibil arăta „Session lost". Anunţăm starea reală.
      setSrAnnounce(t(s.state === 'live' ? 'app.srSessionActive' : 'app.srSessionEnded', {
        title: s.title || t('app.untitledSession'),
        on: h ? t('app.srOnHost', { host: h.name }) : '',
      }))
    } else {
      document.title = 'WebTerm'
      setSrAnnounce(t('app.srMainPanel'))
    }
  }, [selectedSid, sessions, hosts, t])

  useEffect(() => {
    if (!appState?.authenticated) return
    // permisiunea de notificări se cere la primul gest al utilizatorului, nu la
    // load: Safari refuză cererile fără gest, iar Chrome le degradează („quieter UI")
    const askOnce = () => ensureNotificationPermission()
    window.addEventListener('pointerdown', askOnce, { once: true })
    refresh()
    // fereastra ascunsă nu mai face poll (PWA-ul din fundal făcea ~1.400
    // cereri/oră degeaba); la revenire, refresh imediat
    const timer = setInterval(() => { if (!document.hidden) refresh() }, 5000)
    const onVis = () => { if (!document.hidden) refresh() }
    document.addEventListener('visibilitychange', onVis)
    return () => {
      window.removeEventListener('pointerdown', askOnce)
      document.removeEventListener('visibilitychange', onVis)
      clearInterval(timer)
    }
  }, [appState?.authenticated, refresh])

  // acțiunile scurtăturilor, într-un singur loc (registrul le mapează pe taste).
  // Cele „de sesiune" trimit un eveniment pe care panoul ACTIV îl ascultă —
  // aplicația nu trebuie să știe cum caută sau ce font are un terminal.
  const shortcutActions: Partial<Record<ShortcutId, () => void>> = {
    palette: () => setPaletteOpen((v) => !v),
    help: () => setHelpOpen((v) => !v),
    home: () => navigate(null),
    focusSidebar: () => {
      setSidebarOpen(true)
      setTimeout(() => window.dispatchEvent(new Event('wt-focus-search')), 50)
    },
    closeTab: () => { if (selectedSid) closeTab(selectedSid) },
    reopenTab: () => {
      const sid = closedTabsRef.current.pop()
      if (sid && sessions.some((s) => s.id === sid)) selectSession(sid)
    },
    nextTab: () => stepTab(1),
    prevTab: () => stepTab(-1),
    split: () => { if (selectedSid) splitSession(selectedSid) },
    popout: () => { if (selectedSid) popout(selectedSid) },
    search: () => window.dispatchEvent(new Event('wt-session-search')),
    snippets: () => window.dispatchEvent(new Event('wt-session-snippets')),
    fontUp: () => window.dispatchEvent(new CustomEvent('wt-session-font', { detail: 1 })),
    fontDown: () => window.dispatchEvent(new CustomEvent('wt-session-font', { detail: -1 })),
  }

  // scurtături globale (capture: înaintea xterm). Toate vin din registrul unic
  // lib/shortcuts.ts — o scurtătură nouă se adaugă ACOLO, ca să apară automat
  // și în cheatsheet-ul „?" (altfel ecranul de ajutor minte).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const inField = !!(e.target as HTMLElement)?.closest?.('input,textarea,[contenteditable="true"]')
      const inTerminal = !!(document.activeElement as HTMLElement)?.closest?.('.xterm')
      const id = matchShortcut(e)

      // ⌘/Ctrl+Shift+K: portiță universală spre paletă, funcționează și din terminal
      if (e.code === 'KeyK' && (e.metaKey || e.ctrlKey) && e.shiftKey) {
        e.preventDefault()
        setPaletteOpen((v) => !v)
        return
      }
      if (!id) return
      // scurtăturile „simple" (?, /) nu se declanșează cât scrii într-un câmp
      // sau în terminal — acolo caracterul aparține conținutului
      if ((id === 'help' || id === 'focusSidebar') && (inField || inTerminal)) return
      // Ctrl+K în terminal rămâne kill-line al shell-ului (pe mac ⌘K e liber)
      if (id === 'palette' && inTerminal && e.ctrlKey && !e.metaKey) return

      const act = shortcutActions[id]
      if (!act) return
      e.preventDefault()
      // `preventDefault()` opreşte acţiunea implicită a BROWSERULUI, nu propagarea. Handlerul
      // ăsta e pe `window` în fază de CAPTURE, iar xterm ascultă pe textarea (bubble), deci
      // primea evenimentul oricum şi scria secvenţa în PTY. Concret: `Alt+D` ajungea la
      // readline ca `M-d` = kill-word — am tastat `sudo rm -rf /var/log/old`, Ctrl+A, Alt+D,
      // şi linia a devenit `rm -rf /var/log/old`. Fără split, fără niciun mesaj.
      // Aceeaşi familie: Alt+P = history-search-backward (înlocuieşte linia), Alt+1..9 =
      // digit-argument (următorul caracter se multiplică), Alt+= = possible-completions.
      // În capture, `stopPropagation` opreşte evenimentul înainte să ajungă la ţintă.
      e.stopPropagation()
      act()
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [openTabs, selectedSid, secondSid, sessions])

  // Escape închide overlay-urile globale indiferent unde e focusul. Focus trap-ul
  // din dialog acoperă cazul normal, dar dacă focusul a rămas în terminal (sau
  // într-un pane keep-alive), Escape ar ajunge în shell și overlay-ul ar rămâne
  // deschis, blocând clickurile cu scrim-ul lui `fixed inset-0`.
  useEffect(() => {
    if (!helpOpen) return
    const onEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        e.stopPropagation()
        setHelpOpen(false)
      }
    }
    window.addEventListener('keydown', onEsc, true)
    return () => window.removeEventListener('keydown', onEsc, true)
  }, [helpOpen])

  // Alt+1..9 → tab-ul N (rămâne în afara registrului: e o familie, nu o tastă)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!e.altKey || e.metaKey || e.ctrlKey || !/^Digit[1-9]$/.test(e.code)) return
      const idx = Number(e.code.slice(5)) - 1
      if (openTabs[idx]) {
        e.preventDefault()
        e.stopPropagation()          // vezi nota de la handlerul de scurtături: altfel
        window.location.hash = `/s/${openTabs[idx]}`   // readline primeşte digit-argument
      }
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [openTabs])

  // cache de sesiuni (keep-alive): tab-urile folosite recent rămân MONTATE
  // (terminal + websocket + buffer) și doar li se comută vizibilitatea —
  // schimbarea de tab e instantanee, fără replay și fără dansul de resize.
  // Limită MRU ca memoria să rămână mărginită (xterm ține scrollback per tab);
  // tab-urile dincolo de limită se remontează clasic (cu cortina de replay).
  // ATENȚIE: hook-urile stau ÎNAINTEA return-urilor timpurii de mai jos
  // (Rules of Hooks) — mutate după ele, prima randare post-login crapă cu #310.
  const [mru, setMru] = useState<string[]>([])
  useEffect(() => {
    if (!selectedSid) return
    setMru((prev) => [selectedSid, ...prev.filter((x) => x !== selectedSid)].slice(0, 12))
  }, [selectedSid])
  const keepAlive = useMemo(() => {
    const alive: string[] = []
    for (const sid of [selectedSid, ...mru]) {
      if (!sid || alive.includes(sid) || sid === secondSid) continue
      if (sid !== selectedSid && !openTabs.includes(sid)) continue
      alive.push(sid)
      if (alive.length >= KEEP_ALIVE) break
    }
    return alive
  }, [selectedSid, mru, openTabs, secondSid])

  // Ceremonia de step-up pentru un host cu 2FA (passkey sau, fără WebAuthn, re-autentificare cu
  // parola). Întoarce credențialul de trimis (grant sau parolă) ori null la anulare/eșec.
  // NB: HOOK — trebuie definit ÎNAINTE de orice `return` timpuriu (Rules of Hooks).
  const stepupCredential = useCallback(async (
    hostId: number,
  ): Promise<{ stepup_grant?: string; stepup_password?: string } | null> => {
    if (appState?.webauthn_available) {
      try {
        const options = await api<Record<string, unknown>>('/api/webauthn/stepup/options', {
          method: 'POST', body: JSON.stringify({ host_id: hostId }),
        })
        const credential = await startAuthentication({ optionsJSON: options as never })
        const r = await api<{ grant: string }>('/api/webauthn/stepup/verify', {
          method: 'POST', body: JSON.stringify({ host_id: hostId, credential }),
        })
        return { stepup_grant: r.grant }
      } catch {
        notify('2FA', t('app.twofaFailed'), 'warn')
        return null
      }
    }
    // fără passkey disponibil (deploy IP-only) — asta e RE-AUTENTIFICARE cu parola
    // contului, nu un al doilea factor real; etichetăm cinstit
    const v = await askCreds({
      title: t('app.reauth'),
      subtitle: t('app.reauthSubtitle'),
      fields: [{ key: 'password', label: t('app.accountPassword'), type: 'password' }],
      submitLabel: t('app.confirmSubmit'),
    })
    if (!v) return null
    return { stepup_password: v.password }
  }, [appState?.webauthn_available, t])

  // H1: înregistrează ceremonia ca handler global de step-up — `api()` o cheamă automat la un
  // 403 pe orice acțiune de host (run/fs/update/provision/uninstall), deschide fereastra pe
  // server prin /stepup și reîncearcă cererea. Fără asta, doar crearea sesiunii cerea 2FA.
  // NB: HOOK — tot înainte de orice `return` timpuriu.
  useEffect(() => {
    setStepupHandler(async (hostId) => {
      const cred = await stepupCredential(hostId)
      if (!cred) return false
      try {
        await api(`/api/hosts/${hostId}/stepup`, { method: 'POST', body: JSON.stringify(cred) })
        return true
      } catch {
        return false
      }
    })
    return () => setStepupHandler(null)
  }, [stepupCredential])

  // Întoarcerea de la un forward pe host cu 2FA. `forward_auth` nu poate rula ceremonia passkey
  // (e un redirect de pagină, în afara SPA-ului), deci ne trimite aici cu `?stepup=forward`.
  // Deschidem fereastra şi ne întoarcem de unde am venit — altfel omul ar rămâne pe pagina
  // hostului fără să înţeleagă de ce, iar tunelul ar părea pur şi simplu stricat.
  // NB: HOOK — înainte de orice `return` timpuriu (vezi app-tsx-hooks-before-early-returns).
  useEffect(() => {
    if (!appState?.authenticated) return
    const q = new URLSearchParams(window.location.search)
    if (q.get('stepup') !== 'forward') return
    const slug = q.get('slug') ?? ''
    const next = q.get('next') || '/'
    const hostId = Number(window.location.hash.match(/^#\/h\/(\d+)$/)?.[1] ?? 0)
    if (!slug || !hostId) return
    let cancelled = false
    ;(async () => {
      const cred = await stepupCredential(hostId)
      if (cancelled || !cred) return
      try {
        await api(`/api/hosts/${hostId}/stepup`, { method: 'POST', body: JSON.stringify(cred) })
      } catch {
        return                                  // step-up refuzat → rămâi pe pagina hostului
      }
      if (cancelled) return
      window.location.href =
        `/__wtfwd/auth?slug=${encodeURIComponent(slug)}&next=${encodeURIComponent(next)}`
    })()
    return () => { cancelled = true }
  }, [appState?.authenticated, stepupCredential])

  if (!appState) {
    return <div className="flex h-full items-center justify-center text-slate-500">{t('app.loading')}</div>
  }
  if (!appState.authenticated) {
    return (
      <>
        <BootReady />
        <LoginPage
          setupRequired={appState.setup_required}
          webauthnAvailable={appState.webauthn_available}
          onLogin={() => api<AppState>('/api/state').then(setAppState)}
        />
      </>
    )
  }

  const primary = sessions.find((s) => s.id === selectedSid) ?? null
  const second = secondSid ? (sessions.find((s) => s.id === secondSid) ?? null) : null
  // AICI era o gardă care făcea `setSecondSid(null)` când sesiunea secundară nu se găsea
  // în `sessions`. Rula în corpul randării, iar la prima randare după un reload `sessions`
  // e încă `[]` — deci ştergea splitul restaurat din localStorage ÎNAINTE ca datele să
  // sosească. Adică exact funcţia reparată nu supravieţuia unui F5.
  // Curăţarea corectă există în `refresh()`, pe date reale (vezi `setSecondSid` acolo).

  function popout(sid: string) {
    window.open(popoutUrl(sid), `wt_${sid}`, 'width=960,height=640')
  }

  const renderPane = (s: Session, isSecond: boolean, isActive: boolean) => (
    <SessionView
      key={s.id}
      session={s}
      stepupCredential={stepupCredential}
      host={hosts.find((h) => h.id === s.host_id)}
      commandGuard={appState.command_guard}
      // căutarea din rezultate globale merge DOAR la panoul activ — panourile
      // ținute în cache nu trebuie să (re)pornească o căutare veche când redevin
      // vizibile (prop-ul lor rămâne 0 cât sunt inactive)
      initialSearch={isSecond || !isActive ? null : (pendingSearch?.term ?? null)}
      searchNonce={isSecond || !isActive ? 0 : (pendingSearch?.n ?? 0)}
      paneActive={isActive}
      streamActive={isSecond || isActive}
      activeInSplit={!!second && ((isSecond && activePane === 'second') || (!isSecond && activePane === 'primary'))}
      // ținta acțiunilor de sesiune (snippet/insert/font/search): în split e panoul
      // FOCUSAT (activePane), nu ambele — altfel un snippet se executa pe ambele hosturi.
      // Fără split, panoul vizibil/selectat.
      actionTarget={second ? ((isSecond && activePane === 'second') || (!isSecond && activePane === 'primary')) : isActive}
      onMenu={() => { setSidebarCollapsed(false); localStorage.setItem('wt-sidebar-collapsed', '0'); setSidebarOpen(true) }}
      sidebarCollapsed={sidebarCollapsed}
      onPopout={() => {
        popout(s.id)
        if (isSecond) setSecondSid(null)
      }}
      onSplitClosed={isSecond ? () => setSecondSid(null) : undefined}
      onChanged={refresh}
      onOpenSession={async (sid) => { await refresh(); selectSession(sid) }}
      onDeleted={() => {
        if (isSecond) setSecondSid(null)
        else closeTab(s.id)
        refresh()
      }}
    />
  )

  const openTab = (sid: string) =>
    setOpenTabs((prev) => (prev.includes(sid) ? prev : [...prev, sid]))

  // închide tab-ul (detach — sesiunea rămâne activă); activează un vecin
  const closeTab = (sid: string) => {
    closedTabsRef.current.push(sid)
    if (closedTabsRef.current.length > 20) closedTabsRef.current.shift()
    setOpenTabs((prev) => {
      const idx = prev.indexOf(sid)
      const next = prev.filter((s) => s !== sid)
      if (sid === selectedSid) navigate(next[idx] ?? next[idx - 1] ?? null)
      return next
    })
    if (sid === secondSid) setSecondSid(null)
  }

  // click pe o sesiune → deschide-o ca tab și înlocuiește panoul activ
  const selectSession = (sid: string, search?: string) => {
    setPendingSearch(search ? { term: search, n: Date.now() } : null)
    openTab(sid)
    // deja vizibilă într-un panou? doar activează panoul — altfel am ajunge cu
    // aceeași sesiune deschisă simultan în ambele panouri ale split-ului
    if (sid === selectedSid) setActivePane('primary')
    else if (sid === secondSid) setActivePane('second')
    else if (second && activePane === 'second') setSecondSid(sid)
    else navigate(sid)
    setSidebarOpen(false)
  }

  const selectHost = (id: number) => {
    navigateHost(id)
    setSidebarOpen(false)
  }

  // deschide o sesiune alături (split). Dacă avem deja un terminal activ, o
  // punem în al doilea panou; dacă venim din pagina hostului (fără primar),
  // folosim alt tab deschis ca primar; altfel doar o deschidem.
  const splitSession = (sid: string) => {
    openTab(sid)
    if (selectedSid && selectedSid !== sid) {
      // caz normal: suntem în altă sesiune → cea cerută intră în al doilea panou
      setSecondSid(sid)
      setActivePane('second')
      return
    }
    const other = openTabs.find((t) => t !== sid)
    if (!other) {
      navigate(sid)                    // nu avem cu ce face split
      return
    }
    if (selectedSid === sid) {
      // Alt+D din CHIAR sesiunea asta. Aici era bug-ul: se punea `sid` în panoul
      // secundar și se naviga la `other`. Dar `navigate` scrie hash-ul, iar
      // `hashchange` sosește ASINCRON — React comitea `secondSid = sid` cât timp
      // `selectedSid` era tot `sid`, garda „aceeași sesiune nu poate fi și primară
      // și secundară" se declanșa și anula split-ul în același tick. Rezultat:
      // Alt+D era no-op tăcut, plus o excepție din xterm la montarea-demontarea
      // instantanee a celui de-al doilea terminal.
      // Sesiunea curentă rămâne unde e; ALTA vine lângă ea. E și mai firesc.
      setSecondSid(other)
      setActivePane('second')
      return
    }
    // fără primar (venim din pagina hostului): `other` devine primar, `sid` secundar
    setSecondSid(sid)
    setActivePane('second')
    navigate(other)
  }
  const routeHost = route.host != null ? hosts.find((h) => h.id === route.host) ?? null : null

  // host-ul activ pentru ${host} din watermark (sesiunea din tab-ul selectat; altfel ruta)
  const activeSession = sessions.find((s) => s.id === selectedSid)
  const activeHost = activeSession
    ? hosts.find((h) => h.id === activeSession.host_id) ?? null
    : routeHost
  const activeHostLabel = activeHost ? hostAt(activeHost) : ''

  // deschide o sesiune nouă — gestionează 2FA step-up + credențiale „ask”
  async function connectHost(host: Host) {
    const body: Record<string, unknown> = { title: '', tz: getTimezone() }
    if (host.require_2fa) {
      const cred = await stepupCredential(host.id)
      if (!cred) return
      Object.assign(body, cred)
    }
    if (host.connection_type !== 'agent' && host.credential_policy === 'ask') {
      const isKey = host.auth_method === 'key'
      const v = await askCreds({
        title: t('app.connectToHost', { name: host.name }),
        subtitle: `${host.ssh_username || ''}@${host.hostname || ''}`,
        fields: isKey
          ? [
              { key: 'credential', label: t('app.sshPrivateKey'), type: 'textarea', placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----' },
              { key: 'passphrase', label: t('app.keyPassphrase'), type: 'password', optional: true, placeholder: t('app.leaveEmptyIfNone') },
            ]
          : [{ key: 'credential', label: t('app.sshPassword'), type: 'password' }],
        submitLabel: t('app.connectSubmit'),
      })
      if (!v) return
      body.credential = v.credential
      if (isKey) body.passphrase = v.passphrase || ''
    }
    try {
      const r = await api<{ id: string }>(`/api/hosts/${host.id}/sessions`, {
        method: 'POST', body: JSON.stringify(body),
      })
      await refresh()
      openTab(r.id)
      navigate(r.id)
      setSidebarOpen(false)
    } catch (e) {
      notify(t('app.cannotStartSession'), errText(e, t) || t('app.error'), 'warn')
    }
  }

  // deschide o consolă serială pe un host cu agent (gestionează 2FA step-up)
  async function openSerial(host: Host, device: string, params: SerialParams): Promise<boolean> {
    const body: Record<string, unknown> = { device, ...params, tz: getTimezone() }
    if (host.require_2fa) {
      const cred = await stepupCredential(host.id)
      if (!cred) return false
      Object.assign(body, cred)
    }
    try {
      const r = await api<{ id: string }>(`/api/hosts/${host.id}/serial/open`, {
        method: 'POST', body: JSON.stringify(body),
      })
      await refresh()
      openTab(r.id)
      navigate(r.id)
      setSidebarOpen(false)
      return true
    } catch (e) {
      notify(t('app.cannotOpenSerial'), errText(e, t) || t('app.error'), 'warn')
      return false
    }
  }

  async function deleteSession(sid: string) {
    await api(`/api/sessions/${sid}`, { method: 'DELETE' }).catch(() => {})
    closeTab(sid)
    refresh()
  }

  return (
    <div className="flex h-full overflow-hidden">
      <BootReady />
      <Watermark config={appState.watermark} email={appState.email} host={activeHostLabel} />
      <Sidebar
        hosts={hosts}
        sessions={sessions}
        selectedHost={route.host}
        open={sidebarOpen}
        addHostSignal={addHostSignal}
        settingsSignal={settingsSignal}
        statusSignal={statusSignal}
        onClose={() => setSidebarOpen(false)}
        collapsed={sidebarCollapsed}
        onToggleCollapse={toggleSidebar}
        onSelectHost={selectHost}
        onSelect={selectSession}
        onNewSession={connectHost}
        onFiles={setFilesHost}
        onSerial={setSerialHost}
        onDiagnostic={setDiagHost}
        onOpenPalette={() => setPaletteOpen(true)}
        onChanged={refresh}
        onAccountChanged={() => api<AppState>('/api/state').then(setAppState)}
        email={appState.email}
        webauthnAvailable={appState.webauthn_available}
        backupReady={appState.backup_ready}
        signingMissing={appState.signing_missing}
        signingLocked={appState.signing_locked}
        onLogout={async () => {
          await api('/api/logout', { method: 'POST' })
          setAppState({ ...appState, authenticated: false })
        }}
      />
      <div className="wt-workspace flex min-w-0 flex-1 flex-col">
        {openTabs.length > 0 && (
          <TabBar
            tabs={(() => {
              const base = openTabs.map((sid) => sessions.find((s) => s.id === sid)).filter(Boolean) as Session[]
              return tabSort === 'activity'
                ? [...base].sort((a, b) => (tabUsed[b.id] || 0) - (tabUsed[a.id] || 0))   // ultima folosire
                : base
            })()}
            activeSid={selectedSid}
            activity={tabActivity}
            hosts={hosts}
            sort={tabSort}
            onToggleSort={() => setTabSort((s) => (s === 'activity' ? 'manual' : 'activity'))}
            onHome={() => navigate(null)}
            onSelect={(sid) => { setPendingSearch(null); navigate(sid) }}
            onClose={closeTab}
            onReorder={(order) => {
              // drag & drop = control manual: fixăm ordinea DRAG-uită şi comutăm pe „manual"
              // (altfel sortarea pe activitate ar re-muta tab-ul imediat). Păstrăm la coadă
              // eventualele tab-uri deschise a căror sesiune încă nu s-a încărcat (nu-s în
              // ordinea afişată), ca să nu le pierdem.
              setTabSort('manual')
              setOpenTabs((prev) => [...order, ...prev.filter((sid) => !order.includes(sid))])
            }}
          />
        )}
      <main className="wt-main flex min-h-0 min-w-0 flex-1">
        {/* stack-ul keep-alive: toate tab-urile recente stau montate, suprapuse;
            doar cel activ e vizibil. `visibility` (nu display:none) ca hidden-ele
            să-și păstreze dimensiunile corecte prin ResizeObserver. Când nu e
            niciun terminal activ (dashboard / pagina hostului), stack-ul rămâne
            montat dar ascuns — sesiunile supraviețuiesc navigării. */}
        <div
          className={primary ? 'relative min-w-0' : 'hidden'}
          style={primary ? { flex: second ? splitRatio : 1 } : undefined}
          onMouseDownCapture={() => setActivePane('primary')}
        >
          {keepAlive.map((sid) => {
            const s = sessions.find((x) => x.id === sid)
            if (!s) return null
            const active = sid === selectedSid
            return (
              <div key={sid} aria-hidden={!active} className={`absolute inset-0 ${active ? 'visible' : 'invisible'}`}>
                <PaneErrorBoundary>{renderPane(s, false, active)}</PaneErrorBoundary>
              </div>
            )
          })}
        </div>
        {primary && second && (
          <>
            <Divider onRatio={setSplitRatio} />
            <div
              className="min-w-0"
              style={{ flex: 1 - splitRatio }}
              onMouseDownCapture={() => setActivePane('second')}
            >
              <PaneErrorBoundary>{renderPane(second, true, activePane === 'second')}</PaneErrorBoundary>
            </div>
          </>
        )}
        {!primary && (<PaneErrorBoundary>{routeHost ? (
          <HostOverview
            onMenu={() => { setSidebarCollapsed(false); localStorage.setItem('wt-sidebar-collapsed', '0'); setSidebarOpen(true) }}
      sidebarCollapsed={sidebarCollapsed}
            host={routeHost}
            sessions={sessions.filter((s) => s.host_id === routeHost.id)}
            onOpenSession={selectSession}
            onNewSession={connectHost}
            onFiles={setFilesHost}
            onSplit={splitSession}
            onPopout={popout}
            onDeleteSession={deleteSession}
          />
        ) : (
          <Dashboard
            hosts={hosts}
            sessions={sessions}
            onOpenSession={selectSession}
            onSelectHost={selectHost}
            onNewSession={connectHost}
            onAddHost={() => setAddHostSignal((n) => n + 1)}
            onOpenPalette={() => setPaletteOpen(true)}
            onOpenSidebar={() => setSidebarOpen(true)}
          />
        )}</PaneErrorBoundary>)}
      </main>
      </div>
      {filesHost && (
        <Suspense fallback={null}>
          <FileBrowser host={filesHost} onClose={() => setFilesHost(null)} />
        </Suspense>
      )}
      {serialHost && (
        <SerialModal
          host={serialHost}
          onClose={() => setSerialHost(null)}
          onOpen={(device, params) => openSerial(serialHost, device, params)}
        />
      )}
      {diagHost && (
        <DiagnosticModal host={diagHost} onClose={() => setDiagHost(null)} />
      )}
      {paletteOpen && (
        <CommandPalette
          open
          onClose={() => setPaletteOpen(false)}
          hosts={hosts}
          sessions={sessions}
          openTabs={openTabs}
          onOpenSession={selectSession}
          onNewSession={connectHost}
          onSelectHost={selectHost}
          onAddHost={() => setAddHostSignal((n) => n + 1)}
          onFiles={setFilesHost}
          onOpenSettings={() => setSettingsSignal((n) => n + 1)}
          onOpenStatus={() => setStatusSignal((n) => n + 1)}
          onOpenHistory={() => { setPaletteOpen(false); setShowHistory(true) }}
          snippets={snippets}
          hasActiveSession={!!selectedSid}
          onRunSnippet={(s) => {
            setPaletteOpen(false)
            // cu parametri → dialog; fără → direct în terminal
            if (snippetParams(s.body).length) setSnipParams(s)
            else insertInSession(s.body)
          }}
        />
      )}
      {showHistory && (
        <Suspense fallback={null}>
          <HistoryModal hosts={hosts} onClose={() => setShowHistory(false)} />
        </Suspense>
      )}
      {snipParams && (
        <SnippetParams
          snippet={snipParams}
          onRun={(body) => { insertInSession(body); setSnipParams(null) }}
          onCancel={() => setSnipParams(null)}
        />
      )}
      {helpOpen && <KeyboardHelp onClose={() => setHelpOpen(false)} />}
      {credReq && (
        <CredentialModal
          title={credReq.title}
          subtitle={credReq.subtitle}
          fields={credReq.fields}
          submitLabel={credReq.submitLabel}
          onSubmit={(v) => { credReq.resolve(v); setCredReq(null) }}
          onCancel={() => { credReq.resolve(null); setCredReq(null) }}
        />
      )}
      {/* anunțuri pentru cititoarele de ecran (schimbare de tab / context) */}
      <div aria-live="polite" className="sr-only">{srAnnounce}</div>
      <Toasts items={toasts} onDismiss={(id) => setToasts((t) => t.filter((x) => x.id !== id))} />
      {gwFails >= 2 && (
        <div className="fixed left-1/2 top-3 z-50 flex -translate-x-1/2 items-center gap-2 rounded-full border border-rose-500/40 bg-ink-900 px-4 py-1.5 text-sm text-slate-200 shadow-2xl">
          <span className="wt-danger font-medium">
            {navigator.onLine ? t('app.gatewayUnreachable') : t('app.noInternet')}
          </span>
          <span className="text-slate-500">{t('app.staleDataRetrying')}</span>
        </div>
      )}
      {newVersion && (
        /* jos-centrat: sus ar acoperi TabBar-ul (banner persistent ≠ suprapunere
           trecătoare); wt-warn în loc de amber-400 — pe Aurora bannerul e alb */
        <div className="fixed bottom-6 left-1/2 z-50 flex -translate-x-1/2 items-center gap-3 rounded-full border border-ink-600 bg-ink-900 py-1.5 pl-4 pr-1.5 text-sm text-slate-200 shadow-2xl">
          <span>
            {t('app.newVersionInstalled')} (<span className="wt-warn font-medium">{newVersion}</span>)
          </span>
          <button
            onClick={() => window.location.reload()}
            className="rounded-full bg-amber-500 px-3 py-1 text-xs font-semibold text-black hover:bg-amber-400"
          >
            {t('app.reload')}
          </button>
          <button
            onClick={() => setNewVersion(null)}
            aria-label={t('app.close')}
            className="rounded-full px-2 py-1 text-slate-500 hover:bg-ink-800 hover:text-slate-300"
          >
            ✕
          </button>
        </div>
      )}
    </div>
  )
}

function Divider(props: { onRatio: (r: number) => void }) {
  // Pointer Events (nu mouse*): split-ul e oferit și pe tablete, unde mouse
  // events nu vin. Pseudo-elementul lărgește zona activă la ~16px — 4px e o
  // țintă tactilă imposibilă — fără să îngroașe linia vizibilă.
  return (
    <div
      role="separator"
      aria-orientation="vertical"
      className="relative w-1 shrink-0 cursor-col-resize touch-none bg-ink-700 hover:bg-sky-500 after:absolute after:inset-y-0 after:-left-1.5 after:-right-1.5 after:content-['']"
      onPointerDown={(e) => {
        e.preventDefault()
        const el = e.currentTarget
        el.setPointerCapture(e.pointerId)
        const rect = (el.parentElement as HTMLElement).getBoundingClientRect()
        const move = (ev: PointerEvent) => {
          const r = Math.min(0.85, Math.max(0.15, (ev.clientX - rect.left) / rect.width))
          props.onRatio(r)
        }
        const up = () => {
          el.removeEventListener('pointermove', move)
          el.removeEventListener('pointerup', up)
          el.removeEventListener('pointercancel', up)
        }
        el.addEventListener('pointermove', move)
        el.addEventListener('pointerup', up)
        el.addEventListener('pointercancel', up)
      }}
    />
  )
}
