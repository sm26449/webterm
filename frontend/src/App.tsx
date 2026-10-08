import { startAuthentication } from '@simplewebauthn/browser'
import { lazy, ReactNode, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import CommandPalette from './components/CommandPalette'
import CredentialModal, { CredField } from './components/CredentialModal'
import SerialModal, { SerialParams } from './components/SerialModal'
import DiagnosticModal from './components/DiagnosticModal'
import ToolboxPanel from './components/ToolboxPanel'
import ConfirmModal from './components/ConfirmModal'
import Watermark from './components/Watermark'
import Dashboard from './components/Dashboard'
import HostOverview from './components/HostOverview'
import LoginPage from './components/LoginPage'
import KeyboardHelp from './components/KeyboardHelp'
import Walkthrough from './components/Walkthrough'
import SnippetParams, { snippetParams } from './components/SnippetParams'
import PaneErrorBoundary from './components/PaneErrorBoundary'
import PopoutView from './components/PopoutView'
import SharedView from './components/SharedView'
import ReplayView from './components/ReplayView'
import { replayTokenFromHash } from './lib/replay'
import Sidebar from './components/Sidebar'
import SessionView from './components/SessionView'
import TabBar from './components/TabBar'
import TransfersWidget from './components/TransfersWidget'
import Toasts, { ToastItem } from './components/Toasts'
import CopyToast from './components/CopyToast'
import { errText, api, ApiError, AppState, Host, isSessionLive, Session, Snippet, SplitView, setStepupHandler, withStepup } from './lib/api'
import { hostAt, hostColor } from './lib/host'
import type { SettingsTarget } from './lib/settingsIndex'
import { stepupPrompt } from './lib/stepup'
import { useI18n } from './lib/i18n'
import { useConfirm } from './lib/confirm'
import { useFocusTrap } from './lib/useFocusTrap'
import { copyText } from './lib/clipboard'
import { CloseIcon, CopyIcon, ShieldIcon } from './components/Icons'
import { ensureNotificationPermission, notify, notifyError, registerToast } from './lib/notify'
import { restoreOrphans } from './lib/uploads'
import { clearAll as clearClipHistory } from './lib/cliphistory'
import { askSecret, registerSecretPrompt, SecretAsk } from './lib/secretPrompt'
import SecretPromptModal from './components/SecretPromptModal'
import { markBooted } from './lib/failsafe'
import { useMetricsTick } from './lib/metrics'
import { matchShortcut, ShortcutId } from './lib/shortcuts'
import { shouldAutoOpen } from './lib/walkthrough'
import { fmtTs, getTimezone } from './lib/tz'

/* localStorage „sigur": Safari cu „Block all cookies" / iframe sandbox aruncă SecurityError chiar la
   getItem (= cădere înainte de primul render), iar QuotaExceededError într-un useEffect ajungea în
   ErrorBoundary → ecranul de failsafe la FIECARE schimbare de tab (audit frontend B4). Aceeaşi gardă
   ca în lib/font.ts, ţinută local — lib/ nu e în perimetrul acestui sweep. */
const lsGet = (k: string): string | null => { try { return localStorage.getItem(k) } catch { return null } }
const lsSet = (k: string, v: string): void => { try { localStorage.setItem(k, v) } catch { /* quota / privat */ } }

/** Container de dialog cu focus-trap (Tab ciclic, Escape, focus restaurat pe declanşator) + semantica
    ARIA. Hook-urile nu pot sta într-un JSX condiţional, deci dialogurile inline din App (wizard-ul de
    split, alarma de host-key) trec prin componenta asta în loc să-şi care fiecare propriul ref. */
function TrapDialog(props: {
  onClose: () => void
  labelledBy: string
  describedBy?: string
  alert?: boolean          // role=alertdialog (cere o decizie), altfel dialog
  className: string
  children: ReactNode
}) {
  const ref = useRef<HTMLDivElement>(null)
  useFocusTrap(ref, props.onClose)
  return (
    <div ref={ref} role={props.alert ? 'alertdialog' : 'dialog'} aria-modal="true"
      aria-labelledby={props.labelledBy} aria-describedby={props.describedBy}
      className={props.className}>
      {props.children}
    </div>
  )
}

/** Alarma de host-key: ce ştim despre schimbare (vezi `startFailed` + evenimentul `wt-hostkey-changed`). */
type HostKeyAlarm = { hostId: number; name: string; old_fp?: string; new_fp?: string; changed_at?: number | string }

/** Un rând de amprentă (monospace, trunchiat cu title complet) + buton de copiere. */
function FingerprintRow(props: { label: string; value?: string; copyLabel: string }) {
  return (
    <div className="flex items-center gap-2">
      <dt className="w-32 shrink-0 text-slate-500">{props.label}</dt>
      <dd className="min-w-0 flex-1">
        <code className="block truncate rounded-md bg-black/40 px-2 py-1 font-mono text-slate-200" title={props.value}>
          {props.value || '—'}
        </code>
      </dd>
      {props.value && (
        <button type="button" onClick={() => { copyText(props.value!) }} aria-label={props.copyLabel} title={props.copyLabel}
          className="grid h-7 w-7 shrink-0 place-items-center rounded-md text-slate-400 hover:bg-ink-800 hover:text-slate-200">
          <CopyIcon />
        </button>
      )}
    </div>
  )
}

interface Route {
  primary: string | null      // sesiune deschisă (terminal)
  host: number | null         // pagina unui host
  popout: string | null
  shared: string | null
  replay: string | null       // link public de replay (3.5.12): tokenul din fragment
}

function parseHash(): Route {
  const h = window.location.hash
  const base = { primary: null, host: null, popout: null, shared: null, replay: null }
  const replay = replayTokenFromHash(h)
  if (replay) return { ...base, replay }
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
const AddHostModal = lazy(() => import('./components/AddHostModal'))

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
  // Public replay link (closed-session recording) — no login, no app chrome, only the player.
  if (route.replay)
    return (
      <>
        <BootReady />
        <ReplayView token={route.replay} />
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
  // confirm() nativ → dialog propriu (vezi lib/confirm.tsx: de ce); umbreşte deliberat window.confirm
  const { confirm } = useConfirm()
  const [hosts, setHosts] = useState<Host[]>([])
  const [sessions, setSessions] = useState<Session[]>([])
  const [route, navigate, navigateHost] = useRoute()
  const selectedSid = route.primary
  const [filesHost, setFilesHost] = useState<Host | null>(null)
  const [toolboxHost, setToolboxHost] = useState<Host | null>(null)   // panoul Connections, la nivel de host
  const [serialHost, setSerialHost] = useState<Host | null>(null)
  const [diagHost, setDiagHost] = useState<Host | null>(null)
  const [editHostApp, setEditHostApp] = useState<Host | null>(null)   // editare host din pagina hostului
  // ── Split-views: layout-uri denumite de 2-4 sesiuni ──────────────────────────
  // Definiţiile stau server-side (sincronizate între dispozitive, încărcate în refresh);
  // selecţia ACTIVĂ (care view e deschis) e per-browser. Doar view-ul activ e montat, deci
  // aceeaşi sesiune nu ajunge niciodată de două ori în acelaşi document (vezi keep-alive).
  // Colapsează fostele gridSids/secondSid/splitPct/splitRatio. Vezi docs/design/SPLIT-VIEWS.md.
  const [splitViews, setSplitViews] = useState<SplitView[]>([])
  const [activeSplitId, setActiveSplitId] = useState<number | null>(() => {
    try { const v = Number(localStorage.getItem('wt_active_split')); return v > 0 ? v : null } catch { return null }
  })
  useEffect(() => {
    try {
      if (activeSplitId) localStorage.setItem('wt_active_split', String(activeSplitId))
      else localStorage.removeItem('wt_active_split')
    } catch { /* */ }
  }, [activeSplitId])
  const GRID_MAX = 4
  // wizard-ul „+ Split view": creare (fără id) sau editare (cu id) — nume + sesiunile bifate (2–4)
  type SplitWizard = { id?: number; name: string; sel: string[] }
  const [wizard, setWizard] = useState<SplitWizard | null>(null)
  const toggleWizardPick = (sid: string) => setWizard((w) => (w ? {
    ...w,
    sel: w.sel.includes(sid) ? w.sel.filter((s) => s !== sid)
      : w.sel.length >= GRID_MAX ? w.sel : [...w.sel, sid],
  } : w))
  const splitRef = useRef<HTMLDivElement>(null)
  // migrare unică: fostul split (wt_layout) + procentul de grilă (wt_split_pct) nu mai sunt citite
  useEffect(() => {
    try { localStorage.removeItem('wt_layout'); localStorage.removeItem('wt_split_pct') } catch { /* */ }
  }, [])

  // derivate din view-ul activ (folosite de keep-alive, broadcast, randare)
  const activeSplit = activeSplitId ? (splitViews.find((v) => v.id === activeSplitId) ?? null) : null
  const splitPanes = activeSplit
    ? (activeSplit.panes.map((sid) => sessions.find((s) => s.id === sid)).filter(Boolean) as Session[])
    : []
  const splitActive = !!activeSplit && splitPanes.length >= 2
  const broadcast = !!activeSplit?.broadcast
  const splitRatio = activeSplit ? Math.min(0.85, Math.max(0.15, activeSplit.ratio)) : 0.5
  const splitPaneSids = activeSplit ? activeSplit.panes : []
  const splitPaneKey = splitPaneSids.join(',')   // dep stabil (array-ul se recreează la fiecare render)
  // send-ul fiecărui panou montat, indexat pe sid — SessionView îl înregistrează singur
  const sendMap = useRef(new Map<string, (d: string | Uint8Array) => void>())
  const broadcastRef = useRef(false)
  useEffect(() => { broadcastRef.current = broadcast }, [broadcast])
  const registerSend = useCallback((sid: string, fn: ((d: string | Uint8Array) => void) | null) => {
    if (fn) sendMap.current.set(sid, fn)
    else sendMap.current.delete(sid)
  }, [])
  // o tastă dintr-un panou → difuzată către CELELALTE (originea a trimis deja local)
  const handleUserData = useCallback((sid: string, d: string | Uint8Array) => {
    if (!broadcastRef.current) return
    sendMap.current.forEach((fn, osid) => { if (osid !== sid) fn(d) })
  }, [])

  const [sidebarOpen, setSidebarOpen] = useState(false)
  // Plierea sidebarului e o preferinţă de spaţiu, nu o stare de sesiune: cine lucrează pe
  // un laptop mic o vrea din prima, la fiecare deschidere. Citită sincron la montare, ca
  // layout-ul să nu sară după primul render.
  const [sidebarCollapsed, setSidebarCollapsed] = useState(
    () => lsGet('wt-sidebar-collapsed') === '1')
  const toggleSidebar = () => setSidebarCollapsed((v) => {
    lsSet('wt-sidebar-collapsed', v ? '0' : '1')
    return !v
  })
  const [openTabs, setOpenTabs] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem('wt_tabs') || '[]') } catch { return [] }
  })
  // Ordonarea taburilor DESCHISE: 'manual' (ordinea de deschidere, stabilă) sau 'activity'
  // (după ultima folosire — daily-driver-ele sus). Opt-in; NU atinge arborele de hosturi.
  const [tabSort, setTabSort] = useState<'manual' | 'activity'>(() =>
    lsGet('wt_tabsort') === 'activity' ? 'activity' : 'manual')
  const [tabUsed, setTabUsed] = useState<Record<string, number>>(() => {
    try { return JSON.parse(localStorage.getItem('wt_tabused') || '{}') } catch { return {} }
  })
  const [addHostSignal, setAddHostSignal] = useState(0)
  const [settingsSignal, setSettingsSignal] = useState(0)
  // tab-ul cu care se deschid Setările la următorul semnal (cardul Securitate → „Backup"); gol =
  // alegerea obişnuită a Sidebar-ului (punctul de pe rotiţă / Cont)
  const [settingsCat, setSettingsCat] = useState<SettingsTarget | undefined>(undefined)
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
      if (sid === selectedSid || splitPaneSids.includes(sid) || !seenOffsets.current.has(sid)) {
        seenOffsets.current.set(sid, off)
      }
    }
    for (const k of [...seenOffsets.current.keys()]) {
      if (!openTabs.includes(k)) seenOffsets.current.delete(k)
    }
  }, [sessions, selectedSid, splitPaneKey, openTabs])   // eslint-disable-line react-hooks/exhaustive-deps
  const tabActivity = useMemo(() => {
    const set = new Set<string>()
    for (const s of sessions) {
      if (!openTabs.includes(s.id) || s.id === selectedSid || splitPaneSids.includes(s.id)) continue
      const seen = seenOffsets.current.get(s.id)
      if (seen != null && (s.out_offset ?? 0) > seen) set.add(s.id)
    }
    return set
  }, [sessions, selectedSid, splitPaneKey, openTabs])   // eslint-disable-line react-hooks/exhaustive-deps
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [showHistory, setShowHistory] = useState(false)
  const [showLogoutConfirm, setShowLogoutConfirm] = useState(false)
  const [helpOpen, setHelpOpen] = useState(false)
  // walkthrough de primă rulare: `auto` = deschis singur la prima rulare (marchează „gata" la
  // finalizare); `auto:false` = redeschis manual din „?"/Setări (nu atinge starea fără bifă)
  const [walkthrough, setWalkthrough] = useState<{ auto: boolean } | null>(null)
  const walkAutoRef = useRef(false)   // auto-open o SINGURĂ dată per montare, nu la fiecare poll
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
  // autentificarea a expirat ÎN TIMPUL lucrului (401 generic în api(), WS închis cu 4401 în
  // SessionView): până acum pagina de login apărea tăcut la următorul poll. Semnalul vine prin
  // `wt-unauth`; aici doar re-verificăm starea şi explicăm tranziţia deasupra formularului.
  const [authExpired, setAuthExpired] = useState(false)
  const wasAuthedRef = useRef(false)
  useEffect(() => {
    const onUnauth = () => {
      if (!wasAuthedRef.current) return     // 401 pe pagina de login nu e o „expirare"
      setAuthExpired(true)
      api<AppState>('/api/state').then(setAppState).catch(() => {})
    }
    window.addEventListener('wt-unauth', onUnauth)
    return () => window.removeEventListener('wt-unauth', onUnauth)
  }, [])
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
  const lastSplitViewsRef = useRef('')
  // sesiuni de „upgrade OS" urmărite: sid → {host, dacă a apucat să fie live}. Când una se
  // încheie, cerem un refresh de diagnostics (forţează re-check-ul de update-uri pe agent v52)
  // ca badge-ul din sidebar să dispară singur după upgrade.
  const upgradeWatch = useRef<Map<string, { hostId: number; seen: boolean }>>(new Map())

  // Cât mouse-ul sau focusul e pe stiva de toast-uri, nu ştergem nimic (WCAG 2.2.1: conţinutul
  // cronometrat trebuie să poată fi oprit): expirările se adună în `toastPending` şi se aplică
  // când userul pleacă de pe stivă. Fără asta, un mesaj de eroare dispărea exact când dădeai
  // să-l selectezi ca să-l copiezi.
  const toastHeld = useRef(false)
  const toastPending = useRef<Set<string>>(new Set())
  const expireToast = useCallback((id: string) => {
    if (toastHeld.current) { toastPending.current.add(id); return }
    setToasts((t) => t.filter((x) => x.id !== id))
  }, [])
  const onToastHold = useCallback((held: boolean) => {
    toastHeld.current = held
    if (!held && toastPending.current.size) {
      const gone = toastPending.current; toastPending.current = new Set()
      setToasts((t) => t.filter((x) => !gone.has(x.id)))
    }
  }, [])
  useEffect(() => {
    registerToast((message, kind) => {
      const id = `${Date.now()}-${Math.random()}`
      setToasts((t) => [...t, { id, message, kind }])
      // erorile stau mai mult (12s) — ai nevoie de timp să citeşti motivul; info/warn 6s
      setTimeout(() => expireToast(id), kind === 'error' ? 12000 : 6000)
    })
  }, [expireToast])

  // gazda pentru askSecret(): acelaşi tipar imperativ ca credReq (promise + modal).
  // O cerere nouă peste una deschisă o anulează pe cea veche (resolve null) — fluxurile
  // sunt secvenţiale, dar un promise agăţat pentru totdeauna ar bloca apelantul.
  const [secretReq, setSecretReq] = useState<{ ask: SecretAsk; resolve: (v: string | null) => void } | null>(null)
  useEffect(() => {
    registerSecretPrompt((ask) => new Promise((resolve) => {
      setSecretReq((prev) => {
        prev?.resolve(null)
        return { ask, resolve }
      })
    }))
    return () => registerSecretPrompt(null)
  }, [])

  // Revenire din step-up SSO (redirect la IdP → callback → /?stepup=ok): restaurăm tab-ul de
  // unde a plecat userul (salvat în sessionStorage înainte de redirect) şi curăţăm query-ul.
  // Fereastra de step-up e deja deschisă server-side; acţiunea reuşeşte la re-încercare.
  useEffect(() => {
    const p = new URLSearchParams(window.location.search)
    if (p.get('stepup') !== 'ok') return
    let back = ''
    try { back = sessionStorage.getItem('wt_stepup_return') || ''; sessionStorage.removeItem('wt_stepup_return') } catch { /* */ }
    window.history.replaceState(null, '', window.location.pathname + (back || ''))
    if (back) window.location.hash = back
  }, [])

  const refresh = useCallback(async () => {
    try {
      const [h, s, sv] = await Promise.all([
        api<Host[]>('/api/hosts'),
        api<Session[]>('/api/sessions'),
        api<{ split_views: SplitView[] }>('/api/split-views').catch(() => ({ split_views: [] })),
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
      // split-views: server-ul deja curăţă panourile moarte + face prune la <2 la GET.
      // Aici doar sincronizăm starea locală şi dezactivăm view-ul activ dacă a dispărut.
      const svj = JSON.stringify(sv.split_views)
      if (svj !== lastSplitViewsRef.current) { lastSplitViewsRef.current = svj; setSplitViews(sv.split_views) }
      setActiveSplitId((prev) => (prev && !sv.split_views.some((v) => v.id === prev) ? null : prev))
      setGwFails(0)
    } catch {
      setGwFails((n) => n + 1)
      const st = await api<AppState>('/api/state').catch(() => null)
      if (st && !st.authenticated) { setAuthExpired(true); setAppState(st) }   // eram autentificaţi
    }
  }, [t])

  useEffect(() => {
    api<AppState>('/api/state').then(setAppState).catch(() => setAppState(null))
  }, [])

  useEffect(() => {
    lsSet('wt_tabs', JSON.stringify(openTabs))
  }, [openTabs])

  useEffect(() => { lsSet('wt_tabsort', tabSort) }, [tabSort])

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

  // ── Avertizare ÎNAINTE de idle-lock (WCAG 2.2.1 „timing adjustable") ───────────────────
  // Serverul blochează terminalele hosturilor cu 2FA după `idle_lock_seconds` fără INPUT şi nu
  // trimite niciun preaviz: blocarea venea din senin, în mijlocul unei comenzi (audit 6.c1).
  // Ţinem local ceasul activităţii (taste/pointer, throttled) şi cu 60 s înainte arătăm un
  // banner non-modal cu numărătoare inversă + „Sunt încă aici", care împrospătează şi ceasul
  // serverului (SessionView ascultă `wt-idle-ping`). Doar cât există un tab deschis cu o
  // sesiune vie pe un host cu 2FA — altfel n-are de ce să apară.
  const idleSecs = (appState as (AppState & { idle_lock_seconds?: number }) | null)?.idle_lock_seconds ?? 0
  const lastActRef = useRef(Date.now())
  const [idleWarn, setIdleWarn] = useState<number | null>(null)
  const idleWarnRef = useRef<number | null>(null)
  idleWarnRef.current = idleWarn
  const [idleDismissed, setIdleDismissed] = useState(false)   // ✕ pe banner: tăcere până la următorul ciclu
  const stillHere = useCallback(() => {
    lastActRef.current = Date.now()
    setIdleWarn(null)
    window.dispatchEvent(new Event('wt-idle-ping'))
    api('/api/state').catch(() => {})      // ieftin; ţine şi cookie-ul de sesiune „cald"
  }, [])
  useEffect(() => {
    let lastSeen = 0
    const onAct = () => {
      const now = Date.now()
      if (now - lastSeen < 1000) return     // throttle: evenimentele de pointer vin în rafală
      lastSeen = now
      lastActRef.current = now
      // cât bannerul e vizibil, orice activitate contează şi pe server: pointerul singur nu
      // ajunge în PTY, deci fără ping serverul ar bloca oricum
      if (idleWarnRef.current != null) stillHere()
    }
    window.addEventListener('keydown', onAct, true)
    window.addEventListener('pointerdown', onAct, true)
    return () => {
      window.removeEventListener('keydown', onAct, true)
      window.removeEventListener('pointerdown', onAct, true)
    }
  }, [stillHere])
  const idleApplies = idleSecs > 0 && openTabs.some((sid) => {
    const s = sessions.find((x) => x.id === sid)
    const h = s && hosts.find((x) => x.id === s.host_id)
    return !!s && !!h?.require_2fa && isSessionLive(s, hosts)
  })
  useEffect(() => {
    if (!idleApplies) { setIdleWarn(null); return }
    const tick = () => {
      const remaining = Math.ceil(idleSecs - (Date.now() - lastActRef.current) / 1000)
      if (remaining <= 60 && remaining > 0) setIdleWarn(remaining)
      else { setIdleWarn(null); if (remaining > 60) setIdleDismissed(false) }
    }
    tick()
    const iv = setInterval(tick, 1000)
    return () => clearInterval(iv)
  }, [idleApplies, idleSecs])

  // ── Alarma de host-key schimbat (SSH direct / jump) ───────────────────────────────────
  // Card persistent (`alertdialog`) cu amprenta fixată vs. cea primită, explicaţie şi două
  // acţiuni — în locul toast-ului de 12 s cu text brut, fără amprente şi fără cale de re-pin
  // (audit 6.e1/6.e2). Contract: evenimentul `hostkey_changed` {host_id, host_name, old_fp,
  // new_fp, changed_at} (livrat aici ca CustomEvent `wt-hostkey-changed` de cine primeşte
  // fluxul de stare), GET /api/hosts/{id}/hostkey → {fingerprint, previous, changed_at, pinned},
  // POST /api/hosts/{id}/hostkey/accept (gardat de step-up). Fără `new_fp` cădem pe toast-ul vechi.
  const [hostKeyAlarm, setHostKeyAlarm] = useState<HostKeyAlarm | null>(null)
  // Sursa evenimentului: gateway-ul nu are un bus WS către UI, ci pune alarma pe rândul
  // hostului (`hostkey_alarm`, vine cu poll-ul de /api/hosts la 5 s) şi în /api/state. Aici o
  // transformăm în `wt-hostkey-changed` o singură dată per (host, changed_at), ca să nu
  // redeschidem cardul la fiecare poll cât timp userul încă citeşte.
  const seenHostKeyRef = useRef<Set<string>>(new Set())
  useEffect(() => {
    for (const h of hosts) {
      const a = h.hostkey_alarm
      if (!a?.new_fp) continue
      const key = `${h.id}:${a.changed_at ?? ''}:${a.new_fp}`
      if (seenHostKeyRef.current.has(key)) continue
      seenHostKeyRef.current.add(key)
      window.dispatchEvent(new CustomEvent('wt-hostkey-changed', {
        detail: { host_id: h.id, host_name: h.name, old_fp: a.old_fp, new_fp: a.new_fp, changed_at: a.changed_at },
      }))
    }
  }, [hosts])
  const [hostKeyBusy, setHostKeyBusy] = useState(false)
  useEffect(() => {
    const onEv = (e: Event) => {
      const d = (e as CustomEvent<{ host_id: number; host_name?: string; old_fp?: string; new_fp?: string; changed_at?: number | string }>).detail
      if (!d) return
      const name = hosts.find((h) => h.id === d.host_id)?.name ?? d.host_name ?? `#${d.host_id}`
      if (d.new_fp) setHostKeyAlarm({ hostId: d.host_id, name, old_fp: d.old_fp, new_fp: d.new_fp, changed_at: d.changed_at })
      else notifyError(t('app.cannotStartSession'), t('hostkey.title', { name }))
    }
    window.addEventListener('wt-hostkey-changed', onEv)
    return () => window.removeEventListener('wt-hostkey-changed', onEv)
  }, [hosts, t])

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

  // auto-clear al badge-ului de update-uri: când o sesiune de upgrade urmărită se încheie
  // (state 'closed'/'lost'), cerem un refresh de diagnostics — pe agent v52 asta re-verifică
  // update-urile ocolind cache-ul, deci numărul scade la 0 şi badge-ul dispare. `seen` evită
  // cursa la creare (nu declanşăm înainte s-o fi văzut live măcar o dată).
  useEffect(() => {
    if (upgradeWatch.current.size === 0) return
    for (const [sid, w] of [...upgradeWatch.current]) {
      const s = sessions.find((x) => x.id === sid)
      if (s && (s.state === 'live' || s.state === 'creating')) { w.seen = true; continue }
      if (w.seen) {
        upgradeWatch.current.delete(sid)
        // step-up-ul deschis la lansarea upgrade-ului acoperă şi refresh-ul (fereastra de 5 min);
        // dacă a expirat, 403-ul e prins şi tăcut — utilizatorul poate face Refresh manual
        api(`/api/hosts/${w.hostId}/diagnostics/refresh`, { method: 'POST' }).then(refresh).catch(() => {})
      }
    }
  }, [sessions, refresh])

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
      // Alt+Shift+←/→ = reordonarea tabului FOCALIZAT (TabBar). Matcher-ul de next/prevTab nu
      // se uită la Shift, deci aici l-am „fura" înainte să ajungă la tab — îl lăsăm să treacă.
      if ((id === 'nextTab' || id === 'prevTab') && e.shiftKey) return
      // scurtăturile „simple" (?, /) nu se declanșează cât scrii într-un câmp
      // sau în terminal — acolo caracterul aparține conținutului
      if ((id === 'help' || id === 'focusSidebar') && (inField || inTerminal)) return
      // „/" dintr-un dialog modal aparţine dialogului (Setări: căutarea, 3.5.9) — altfel ar muta
      // focusul în sidebar-ul DE SUB modal, adică în afara capcanei de focus
      if (id === 'focusSidebar' && (e.target as HTMLElement)?.closest?.('[role="dialog"][aria-modal="true"]')) return
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
  }, [openTabs, selectedSid, splitPaneKey, sessions])

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
      // sesiunile view-ului activ de split sunt montate ACOLO — exclude-le din stivă ca să nu
      // se monteze de două ori (două WS pe acelaşi PTY = război de detach tmux)
      if (!sid || alive.includes(sid) || splitPaneSids.includes(sid)) continue
      if (sid !== selectedSid && !openTabs.includes(sid)) continue
      alive.push(sid)
      if (alive.length >= KEEP_ALIVE) break
    }
    return alive
  }, [selectedSid, mru, openTabs, splitPaneKey])   // eslint-disable-line react-hooks/exhaustive-deps

  // 3.5.14: contul n-are niciun factor real (fără passkey, fără TOTP, fără SSO) — parola singură
  // nu mai deschide un host 2FA. Explicăm şi oferim drumul direct la Setări → Autentificare & 2FA.
  // NB: HOOK — înainte de orice `return` timpuriu.
  const promptNeedsFactor = useCallback(async () => {
    if (await confirm({
      title: t('stepup.needsFactorTitle'), message: t('err.stepup.needsFactor'),
      confirmLabel: t('stepup.openSignin'),
    })) {
      setSettingsCat({ cat: 'autentificare', section: 'totp' })
      setSettingsSignal((n) => n + 1)
    }
  }, [confirm, t])

  // Ceremonia de step-up pentru un host cu 2FA: passkey, cod TOTP, re-auth SSO — sau, doar pe o
  // ţintă FĂRĂ 2FA (deploy de cheie, `stepup.password`), parola contului. Ce cerem decide
  // `stepupPrompt` (lib/stepup.ts) din codul refuzului sau, proactiv, din `stepup_method`.
  // Întoarce credențialul de trimis ori null la anulare/eșec.
  // NB: HOOK — trebuie definit ÎNAINTE de orice `return` timpuriu (Rules of Hooks).
  const stepupCredential = useCallback(async (
    hostId: number,
    code?: string,
  ): Promise<{ stepup_grant?: string; stepup_password?: string; totp?: string } | null> => {
    const kind = stepupPrompt(code, appState?.stepup_method, !!appState?.webauthn_available)
    if (kind === 'needsFactor') {
      await promptNeedsFactor()
      return null
    }
    // SSO: nicio ceremonie inline — cererea pleacă fără factor, serverul răspunde
    // `host.needs2faSso`, iar api() face redirectul la IdP (re-auth proaspăt)
    if (kind === 'sso') return {}
    if (kind === 'passkey') {
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
    // User cu TOTP activ, fără passkey: backend-ul cere un cod de 6 cifre în câmpul `totp` al
    // cererii /stepup (acolo unde altfel merge `stepup_password`). Cod scurt, viaţă 30s → input
    // NEMASCAT, numeric, `one-time-code` (vezi SecretPromptModal cu `otp`).
    if (kind === 'totp') {
      const otp = await askSecret(t('stepup.totpTitle'), {
        masked: false, otp: true, label: t('stepup.totpLabel'), hint: t('stepup.totpHint'),
      })
      if (otp === null) return null
      return { totp: otp.trim() }
    }
    // `password`: re-AUTENTIFICARE cu parola contului (ţintă fără 2FA), nu un al doilea factor
    const v = await askCreds({
      title: t('app.reauth'),
      subtitle: t('app.reauthSubtitle'),
      fields: [{ key: 'password', label: t('app.accountPassword'), type: 'password' }],
      submitLabel: t('app.confirmSubmit'),
    })
    if (!v) return null
    return { stepup_password: v.password }
  }, [appState?.webauthn_available, appState?.stepup_method, promptNeedsFactor, t])

  // H1: înregistrează ceremonia ca handler global de step-up — `api()` o cheamă automat la un
  // 403 pe orice acțiune de host (run/fs/update/provision/uninstall), deschide fereastra pe
  // server prin /stepup și reîncearcă cererea. Fără asta, doar crearea sesiunii cerea 2FA.
  // NB: HOOK — tot înainte de orice `return` timpuriu.
  // upload-uri rămase neterminate într-o sesiune anterioară (chei `wt_up_*`): le arătăm în bara
  // de transferuri ca „orfane" imediat ce suntem autentificaţi (Discard are nevoie de API)
  useEffect(() => {
    if (appState?.authenticated) restoreOrphans()
  }, [appState?.authenticated])
  // history-ul de clipboard (în memorie, poate ţine parole/tokenuri) moare odată cu sesiunea web:
  // logout explicit SAU expirare (401 / poll) — orice tranziţie spre neautentificat
  useEffect(() => {
    if (appState?.authenticated === false) clearClipHistory()
  }, [appState?.authenticated])

  // Auto-deschiderea walkthrough-ului la PRIMA rulare: doar după autentificare (nu pe login) şi
  // doar dacă `wt_walkthrough_done` lipseşte. `walkAutoRef` ne apără de poll-ul de 5s (authenticated
  // rămâne true, dar nu vrem să-l redeschidem). E2e-urile presetează cheia → shouldAutoOpen=false,
  // deci fluxul de login nu e atins. NB: HOOK — înainte de orice `return` timpuriu.
  useEffect(() => {
    if (!appState?.authenticated || walkAutoRef.current) return
    walkAutoRef.current = true
    if (shouldAutoOpen(true)) setWalkthrough({ auto: true })
  }, [appState?.authenticated])

  // Redeschiderea manuală: Setări → Preferinţe cere turul printr-un eveniment (componenta e
  // adâncă în SettingsModal), iar „?" îl cere prin prop. Ambele îl deschid în mod `auto:false`.
  useEffect(() => {
    const onOpen = () => setWalkthrough({ auto: false })
    window.addEventListener('wt-open-walkthrough', onOpen)
    return () => window.removeEventListener('wt-open-walkthrough', onOpen)
  }, [])
  useEffect(() => {
    setStepupHandler(async (hostId, code) => {
      const cred = await stepupCredential(hostId, code)
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
  wasAuthedRef.current = appState.authenticated
  if (!appState.authenticated) {
    return (
      <>
        <BootReady />
        {authExpired && (
          /* motivul pentru care a apărut login-ul: expirare, nu eroare — terminalele trăiesc */
          <div role="alert"
            className="fixed left-1/2 top-3 z-50 flex max-w-[92vw] -translate-x-1/2 items-center gap-2 rounded-full border border-amber-500/40 bg-ink-900 px-4 py-1.5 text-sm text-slate-200 shadow-2xl">
            <span className="wt-warn font-medium">{t('session.authExpired')}.</span>
            <span className="text-slate-400">{t('session.authExpiredBody')}</span>
          </div>
        )}
        <LoginPage
          setupRequired={appState.setup_required}
          webauthnAvailable={appState.webauthn_available}
          onLogin={() => { setAuthExpired(false); api<AppState>('/api/state').then(setAppState) }}
        />
      </>
    )
  }

  const primary = sessions.find((s) => s.id === selectedSid) ?? null
  // `activeSplit`/`splitPanes`/`splitActive` sunt derivate sus (au nevoie de ele keep-alive +
  // broadcast). Panourile moarte sunt curăţate server-side la GET (vezi refresh + API).

  function popout(sid: string) {
    window.open(popoutUrl(sid), `wt_${sid}`, 'width=960,height=640')
  }

  // Un panou: un tab normal (grid=false) sau un panou dintr-un split-view (grid=true). În split
  // toate panourile stream-uiesc simultan; `isActive` = panoul selectat (ţinta snippet/font/căutare
  // + inelul albastru). Acelaşi renderer pentru 2 (divider) şi 3–4 (grilă 2×2).
  // părintele unei ţinte jump (overlay-ul „host offline" vorbeşte despre agentul lui)
  const viaHostOf = (hostId: number) => {
    const via = hosts.find((h) => h.id === hostId)?.via_host_id
    return via ? hosts.find((h) => h.id === via) : undefined
  }
  const renderPane = (s: Session, isActive: boolean, grid?: boolean) => (
    <SessionView
      key={s.id}
      session={s}
      stepupCredential={stepupCredential}
      host={hosts.find((h) => h.id === s.host_id)}
      viaHost={viaHostOf(s.host_id)}
      onOpenHost={selectHost}
      commandGuard={appState.command_guard}
      registerSend={grid ? registerSend : undefined}
      onUserData={grid ? handleUserData : undefined}
      broadcasting={grid ? broadcast : undefined}
      // căutarea din rezultate globale merge DOAR la panoul activ — panourile ţinute în cache
      // nu trebuie să (re)pornească o căutare veche când redevin vizibile
      initialSearch={!isActive ? null : (pendingSearch?.term ?? null)}
      searchNonce={!isActive ? 0 : (pendingSearch?.n ?? 0)}
      paneActive={isActive}
      streamActive={grid || isActive}
      // delimitare: orice panou de split are border; cel selectat = accent (activeInSplit)
      inSplit={!!grid}
      activeInSplit={grid ? isActive : false}
      actionTarget={isActive}
      // right-click „Add to split view" (alternativă la butonul din bară) → deschide wizard-ul.
      // Doar pe taburi normale (nu din interiorul unui split) şi doar dacă ai ≥2 taburi de combinat.
      onSplitView={!grid && openTabs.length >= 2 ? openWizardCreate : undefined}
      onMenu={() => { setSidebarCollapsed(false); lsSet('wt-sidebar-collapsed', '0'); setSidebarOpen(true) }}
      sidebarCollapsed={sidebarCollapsed}
      onPopout={() => popout(s.id)}
      onChanged={refresh}
      onOpenSession={async (sid) => { await refresh(); selectSession(sid) }}
      onOpenContainerShell={openContainerShell}
      onOpenContainerLogs={openContainerLogs}
      onJournal={openJournal}
      onOpenConnection={openConnection}
      onDeleted={() => { closeTab(s.id); refresh() }}
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
  }

  // click pe o sesiune (sidebar/paletă) → deschide-o ca tab şi ieşi din orice split-view activ
  const selectSession = (sid: string, search?: string) => {
    setPendingSearch(search ? { term: search, n: Date.now() } : null)
    openTab(sid)
    setActiveSplitId(null)
    navigate(sid)
    setSidebarOpen(false)
  }

  const selectHost = (id: number) => {
    // navigarea la pagina unui host IESE din split-view-ul activ (chip-ul rămâne în bară →
    // revii oricând). Altfel `splitActive` are prioritate de render peste pagina hostului, iar
    // click-ul pe host părea mort până dădeai întâi click pe un tab (care dezactiva split-ul).
    setActiveSplitId(null)
    navigateHost(id)
    setSidebarOpen(false)
  }

  // ── operaţii pe split-views (server-side, optimist) ──────────────────────────
  const patchSplit = async (id: number, changes: Partial<SplitView>) => {
    setSplitViews((prev) => prev.map((v) => (v.id === id ? { ...v, ...changes } : v)))   // optimist
    try { await api(`/api/split-views/${id}`, { method: 'PATCH', body: JSON.stringify(changes) }) }
    catch { refresh() }   // dezacord cu serverul → resincronizează
  }
  const createSplit = async (panes: string[], name?: string) => {
    const uniq = [...new Set(panes)].slice(0, GRID_MAX)   // distincte, ordine păstrată
    if (uniq.length < 2) return
    try {
      const sv = await api<SplitView>('/api/split-views', {
        method: 'POST',
        body: JSON.stringify({ name: (name || '').trim() || t('split.defaultName', { n: splitViews.length + 1 }),
                               panes: uniq, ratio: 0.5, broadcast: false }),
      })
      setSplitViews((prev) => [...prev, sv])
      setActiveSplitId(sv.id)
    } catch (e) { notify(t('split.title'), errText(e, t) || t('toolbox.error'), 'warn') }
  }
  // deschide o sesiune alături (Alt+D / pagina hostului): creează un split-view de 2 panouri
  const splitSession = (sid: string) => {
    openTab(sid)
    const other = (selectedSid && selectedSid !== sid) ? selectedSid : openTabs.find((tb) => tb !== sid)
    if (!other) { navigate(sid); return }   // nimic cu care să facem split
    createSplit([other, sid])
  }
  // wizard: creare (nume implicit + primele taburi) sau editare (nume + panouri existente)
  const openWizardCreate = () => setWizard({ name: t('split.defaultName', { n: splitViews.length + 1 }), sel: openTabs.slice(0, GRID_MAX) })
  const openWizardEdit = (v: SplitView) => setWizard({ id: v.id, name: v.name, sel: v.panes })
  const saveWizard = async () => {
    if (!wizard) return
    const panes = openTabs.filter((sid) => wizard.sel.includes(sid))   // păstrează ordinea din taburi
    if (panes.length < 2) return
    const name = wizard.name.trim() || t('split.defaultName', { n: splitViews.length + 1 })
    const id = wizard.id
    setWizard(null)
    if (id) await patchSplit(id, { name, panes })
    else await createSplit(panes, name)
  }
  const deleteSplit = async (id: number) => {
    const v = splitViews.find((x) => x.id === id)
    if (!(await confirm({
      title: t('split.delete'), message: t('split.confirmDelete', { name: v?.name || '' }),
      danger: true, confirmLabel: t('split.delete'),
    }))) return
    setSplitViews((prev) => prev.filter((x) => x.id !== id))
    if (activeSplitId === id) setActiveSplitId(null)
    try { await api(`/api/split-views/${id}`, { method: 'DELETE' }) } catch { refresh() }
  }
  // divider draggable (2 panouri): actualizare optimistă locală în timpul drag-ului, PATCH la release
  const dragSplit = (e: React.PointerEvent) => {
    e.preventDefault()
    const el = splitRef.current
    if (!el || !activeSplit) return
    const id = activeSplit.id
    const rect = el.getBoundingClientRect()
    const clamp = (v: number) => Math.min(0.85, Math.max(0.15, v))
    const at = (x: number) => clamp((x - rect.left) / rect.width)
    const move = (ev: PointerEvent) =>
      setSplitViews((prev) => prev.map((v) => (v.id === id ? { ...v, ratio: at(ev.clientX) } : v)))
    const up = (ev: PointerEvent) => { detach(); patchSplit(id, { ratio: at(ev.clientX) }) }
    const detach = () => { window.removeEventListener('pointermove', move); window.removeEventListener('pointerup', up) }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
  }
  const routeHost = route.host != null ? hosts.find((h) => h.id === route.host) ?? null : null

  // host-ul activ pentru ${host} din watermark (sesiunea din tab-ul selectat; altfel ruta)
  const activeSession = sessions.find((s) => s.id === selectedSid)
  const activeHost = activeSession
    ? hosts.find((h) => h.id === activeSession.host_id) ?? null
    : routeHost
  const activeHostLabel = activeHost ? hostAt(activeHost) : ''

  // Eşec la pornirea unei sesiuni. Cazul special: 409 de host-key schimbat (SSH direct/jump).
  // Codul `ssh.hostKeyChanged` e contractul; regexul rămâne rezervă pentru 409-ul încă necodat
  // (api.py ridică azi HTTPException fără cod). Detaliile vin de la GET /api/hosts/{id}/hostkey;
  // dacă ruta nu există încă (gateway vechi) sau nu are amprenta nouă, rămâne toast-ul vechi.
  async function startFailed(host: Host, e: unknown) {
    const hostKey = e instanceof ApiError && e.status === 409
      && (e.code === 'ssh.hostKeyChanged' || /host key fingerprint changed/i.test(e.message))
    if (hostKey) {
      const info = await api<{ fingerprint?: string; previous?: string; changed_at?: number | string }>(
        `/api/hosts/${host.id}/hostkey`).catch(() => null)
      if (info?.fingerprint) {
        setHostKeyAlarm({ hostId: host.id, name: host.name, old_fp: info.previous, new_fp: info.fingerprint, changed_at: info.changed_at })
        return
      }
    }
    notifyError(t('app.cannotStartSession'), errText(e, t) || t('app.error'))
  }
  // „Am reinstalat hostul": re-pin după verificare out-of-band. Step-up (hostul e, prin definiţie,
  // unul la care tocmai am refuzat conexiunea) — withStepup rulează ceremonia şi reîncearcă o dată.
  async function acceptHostKey() {
    const a = hostKeyAlarm
    if (!a) return
    setHostKeyBusy(true)
    try {
      await withStepup(a.hostId, () => api(`/api/hosts/${a.hostId}/hostkey/accept`, {
        method: 'POST', body: JSON.stringify({ fingerprint: a.new_fp }),
      }))
      setHostKeyAlarm(null)
      notify(t('hostkey.accepted', { name: a.name }), t('hostkey.acceptedBody'), 'info')
      refresh()
    } catch (e) {
      notifyError(t('hostkey.acceptFailed'), errText(e, t) || t('app.error'))
    } finally {
      setHostKeyBusy(false)
    }
  }

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
      startFailed(host, e)
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
      notifyError(t('app.cannotOpenSerial'), errText(e, t) || t('app.error'))
      return false
    }
  }

  // deschide un shell ÎNTR-un container Docker de pe host (sesiune cu docker_container →
  // gateway-ul o transformă în `docker exec`). Acelaşi 2FA step-up ca o sesiune normală.
  async function openContainerShell(host: Host, container: string) {
    const body: Record<string, unknown> = { title: '', tz: getTimezone(), docker_container: container }
    if (host.require_2fa) {
      const cred = await stepupCredential(host.id)
      if (!cred) return
      Object.assign(body, cred)
    }
    try {
      const r = await api<{ id: string }>(`/api/hosts/${host.id}/sessions`, {
        method: 'POST', body: JSON.stringify(body),
      })
      await refresh()
      openTab(r.id)
      navigate(r.id)
    } catch (e) {
      startFailed(host, e)
    }
  }

  // Lansator de conexiune DB: sesiune care rulează CLI-ul salvat (psql/mysql/…) pe host.
  // Acelaşi flux/2FA ca shell-ul de container. Politica `ask` → clientul cere parola singur.
  async function openConnection(host: Host, connId: number) {
    const body: Record<string, unknown> = { title: '', tz: getTimezone(), connection_id: connId }
    if (host.require_2fa) {
      const cred = await stepupCredential(host.id)
      if (!cred) return
      Object.assign(body, cred)
    }
    try {
      const r = await api<{ id: string }>(`/api/hosts/${host.id}/sessions`, {
        method: 'POST', body: JSON.stringify(body),
      })
      await refresh()
      openTab(r.id)
      navigate(r.id)
    } catch (e) {
      startFailed(host, e)
    }
  }

  // „Logs" dintr-un container Docker: sesiune care urmăreşte `docker logs --tail 500 -f` (gateway-ul
  // validează id-ul şi construieşte comanda). Acelaşi flux/2FA ca „Logs" din Services, mai jos.
  async function openContainerLogs(host: Host, container: string, name?: string) {
    const body: Record<string, unknown> = {
      title: `logs: ${(name || container.slice(0, 12)).slice(0, 40)}`, tz: getTimezone(), docker_logs: container,
    }
    if (host.require_2fa) {
      const cred = await stepupCredential(host.id)
      if (!cred) return
      Object.assign(body, cred)
    }
    try {
      const r = await api<{ id: string }>(`/api/hosts/${host.id}/sessions`, {
        method: 'POST', body: JSON.stringify(body),
      })
      await refresh()
      openTab(r.id)
      navigate(r.id)
    } catch (e) {
      startFailed(host, e)
    }
  }

  // „Logs": sesiune care urmăreşte `journalctl -u <unit> -f` pe host. Acelaşi flux/2FA.
  async function openJournal(host: Host, unit: string) {
    const body: Record<string, unknown> = { title: '', tz: getTimezone(), journal_unit: unit }
    if (host.require_2fa) {
      const cred = await stepupCredential(host.id)
      if (!cred) return
      Object.assign(body, cred)
    }
    try {
      const r = await api<{ id: string }>(`/api/hosts/${host.id}/sessions`, {
        method: 'POST', body: JSON.stringify(body),
      })
      await refresh()
      openTab(r.id)
      navigate(r.id)
    } catch (e) {
      startFailed(host, e)
    }
  }

  // „Upgrade într-un terminal": sesiune care rulează comanda interactivă de upgrade OS
  // (gateway-ul o alege după managerul detectat). Acelaşi flux/2FA ca shell-ul de container.
  async function openUpgradeSession(host: Host) {
    const body: Record<string, unknown> = { title: '', tz: getTimezone(), os_upgrade: true }
    if (host.require_2fa) {
      const cred = await stepupCredential(host.id)
      if (!cred) return
      Object.assign(body, cred)
    }
    try {
      const r = await api<{ id: string }>(`/api/hosts/${host.id}/sessions`, {
        method: 'POST', body: JSON.stringify(body),
      })
      // urmărim sesiunea: când se încheie (upgrade-ul s-a terminat), cerem un refresh de
      // diagnostics — care forţează re-verificarea update-urilor (agent v52) → badge-ul dispare
      // singur, fără să aştepţi cache-ul de 6h. `seen` = a apucat să fie live (evită cursa la creare).
      upgradeWatch.current.set(r.id, { hostId: host.id, seen: false })
      await refresh()
      openTab(r.id)
      navigate(r.id)
    } catch (e) {
      startFailed(host, e)
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
        settingsCat={settingsCat}
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
        onUpgrade={openUpgradeSession}
        onOpenPalette={() => setPaletteOpen(true)}
        onChanged={refresh}
        onAccountChanged={() => api<AppState>('/api/state').then(setAppState)}
        email={appState.email}
        webauthnAvailable={appState.webauthn_available}
        backupReady={appState.backup_ready}
        signingMissing={appState.signing_missing}
        signingLocked={appState.signing_locked}
        onLogout={() => setShowLogoutConfirm(true)}
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
            // click pe Home sau pe un tab de sesiune IESE din split-view-ul activ (chip-ul rămâne
            // în bară → revii oricând). Altfel takeover-ul split-ului ignora navigarea pe taburi.
            onHome={() => { setActiveSplitId(null); navigate(null) }}
            onSelect={(sid) => { setPendingSearch(null); setActiveSplitId(null); navigate(sid) }}
            onClose={closeTab}
            onReorder={(order) => {
              // drag & drop = control manual: fixăm ordinea DRAG-uită şi comutăm pe „manual"
              // (altfel sortarea pe activitate ar re-muta tab-ul imediat). Păstrăm la coadă
              // eventualele tab-uri deschise a căror sesiune încă nu s-a încărcat (nu-s în
              // ordinea afişată), ca să nu le pierdem.
              setTabSort('manual')
              setOpenTabs((prev) => [...order, ...prev.filter((sid) => !order.includes(sid))])
            }}
            /* split view: intrarea + controalele stau în bara de taburi (fosta bandă dedicată
               mânca o linie de ecran ori de câte ori aveai ≥2 taburi, chiar nefolosită) */
            split={{
              views: splitViews.map((v) => ({ id: v.id, name: v.name })),
              activeId: activeSplitId,
              broadcast,
              onSelect: (id) => setActiveSplitId(id),
              onCreate: openWizardCreate,
              onEdit: (id) => { const v = splitViews.find((x) => x.id === id); if (v) openWizardEdit(v) },
              onDelete: deleteSplit,
              onBroadcast: () => { if (activeSplit) patchSplit(activeSplit.id, { broadcast: !broadcast }) },
              // „exit" doar DEZACTIVEAZĂ view-ul (rămâne salvat în DB); nu-l şterge
              onExit: () => setActiveSplitId(null),
            }}
          />
        )}
      <main className="wt-main flex min-h-0 min-w-0 flex-1">
        {/* GRILĂ multi-terminal: ia locul stack-ului keep-alive şi al split-ului (altfel o
            sesiune s-ar monta de două ori → două WS pe acelaşi PTY, războiul de detach tmux).
            2 panouri = o linie; 3–4 = 2×2. Fiecare panou e o sesiune completă, vie. */}
        {splitActive && splitPanes.length === 2 ? (
          /* SPLIT de 2: două panouri vii cu divider draggable între ele. Click pe un panou îl
             face „activ" (ţinta acţiunilor de sesiune); broadcast-ul merge oricum per-panou. */
          <div ref={splitRef} className="flex min-h-0 min-w-0 flex-1 bg-ink-800">
            <div className="relative min-h-0 min-w-0 overflow-hidden bg-ink-900"
              style={{ width: `${splitRatio * 100}%` }}
              onMouseDownCapture={() => { if (splitPanes[0].id !== selectedSid) navigate(splitPanes[0].id) }}>
              <PaneErrorBoundary>{renderPane(splitPanes[0], splitPanes[0].id === selectedSid, true)}</PaneErrorBoundary>
            </div>
            <div
              role="separator" aria-orientation="vertical" tabIndex={0}
              aria-label={t('split.dividerAria')}
              aria-valuenow={Math.round(splitRatio * 100)} aria-valuemin={15} aria-valuemax={85}
              onPointerDown={dragSplit}
              onDoubleClick={() => { if (activeSplit) patchSplit(activeSplit.id, { ratio: 0.5 }) }}
              onKeyDown={(e) => {
                const d = e.key === 'ArrowLeft' ? -0.02 : e.key === 'ArrowRight' ? 0.02 : 0
                if (!d || !activeSplit) return
                e.preventDefault()
                patchSplit(activeSplit.id, { ratio: Math.min(0.85, Math.max(0.15, splitRatio + d)) })
              }}
              className="group/divider relative w-1.5 shrink-0 cursor-col-resize bg-ink-600 outline-none transition-colors hover:bg-sky-500 focus-visible:bg-sky-500"
            >
              {/* grip: 3 puncte centrate — semnalează că e trăgabil (înainte era o linie de 1px abia vizibilă) */}
              <span className="pointer-events-none absolute left-1/2 top-1/2 flex -translate-x-1/2 -translate-y-1/2 flex-col gap-[3px] opacity-50 transition-opacity group-hover/divider:opacity-90">
                <span className="h-[3px] w-[3px] rounded-full bg-slate-300" />
                <span className="h-[3px] w-[3px] rounded-full bg-slate-300" />
                <span className="h-[3px] w-[3px] rounded-full bg-slate-300" />
              </span>
            </div>
            <div className="relative min-h-0 min-w-0 flex-1 overflow-hidden bg-ink-900"
              onMouseDownCapture={() => { if (splitPanes[1].id !== selectedSid) navigate(splitPanes[1].id) }}>
              <PaneErrorBoundary>{renderPane(splitPanes[1], splitPanes[1].id === selectedSid, true)}</PaneErrorBoundary>
            </div>
          </div>
        ) : splitActive ? (
          <div className="grid min-h-0 min-w-0 flex-1 grid-cols-2 grid-rows-2 gap-px bg-ink-800">
            {splitPanes.map((s) => (
              // click pe un panou îl face „activ" (ţinta acţiunilor de sesiune: snippet/font/
              // căutare); tastarea/broadcast-ul merg oricum per-panou, asta doar retarghetează
              <div key={s.id} className="relative min-h-0 min-w-0 overflow-hidden bg-ink-900"
                onMouseDownCapture={() => { if (s.id !== selectedSid) navigate(s.id) }}>
                <PaneErrorBoundary>{renderPane(s, s.id === selectedSid, true)}</PaneErrorBoundary>
              </div>
            ))}
          </div>
        ) : (
        /* stack-ul keep-alive: toate tab-urile recente stau montate, suprapuse; doar cel activ e
           vizibil. `visibility` (nu display:none) ca hidden-ele să-și păstreze dimensiunile prin
           ResizeObserver. Fără terminal activ (dashboard/pagina hostului) stack-ul rămâne montat
           dar ascuns — sesiunile supraviețuiesc navigării. */
        <div className={primary ? 'relative min-w-0 flex-1' : 'hidden'}>
          {keepAlive.map((sid) => {
            const s = sessions.find((x) => x.id === sid)
            if (!s) return null
            const active = sid === selectedSid
            return (
              <div key={sid} aria-hidden={!active} className={`absolute inset-0 ${active ? 'visible' : 'invisible'}`}>
                <PaneErrorBoundary>{renderPane(s, active)}</PaneErrorBoundary>
              </div>
            )
          })}
        </div>
        )}
        {!splitActive && !primary && (<PaneErrorBoundary>{routeHost ? (
          <HostOverview
            onMenu={() => { setSidebarCollapsed(false); lsSet('wt-sidebar-collapsed', '0'); setSidebarOpen(true) }}
            sidebarCollapsed={sidebarCollapsed}
            host={routeHost}
            sessions={sessions.filter((s) => s.host_id === routeHost.id)}
            onOpenSession={selectSession}
            onNewSession={connectHost}
            onSplit={splitSession}
            onPopout={popout}
            onDeleteSession={deleteSession}
            onConnectionOpen={openConnection}
            onJournal={openJournal}
            onContainerShell={openContainerShell}
            onContainerLogs={openContainerLogs}
            onSerial={setSerialHost}
            onDiagnostic={setDiagHost}
            onEdit={setEditHostApp}
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
            onOpenSettings={(cat) => { setSettingsCat(cat); setSettingsSignal((n) => n + 1) }}
            onOpenStatus={() => setStatusSignal((n) => n + 1)}
          />
        )}</PaneErrorBoundary>)}
      </main>
      </div>
      {filesHost && (
        <Suspense fallback={null}>
          <FileBrowser host={filesHost} onClose={() => setFilesHost(null)} />
        </Suspense>
      )}
      {toolboxHost && (
        <ToolboxPanel key={toolboxHost.id} host={toolboxHost} overlay onClose={() => setToolboxHost(null)}
          onOpen={(h, cid) => { setToolboxHost(null); openConnection(h, cid) }} />
      )}
      {serialHost && (
        <SerialModal
          host={serialHost}
          onClose={() => setSerialHost(null)}
          onOpen={(device, params) => openSerial(serialHost, device, params)}
        />
      )}
      {diagHost && (
        <DiagnosticModal key={diagHost.id} host={diagHost} onClose={() => setDiagHost(null)} />
      )}
      {editHostApp && (
        <Suspense fallback={null}>
          <AddHostModal host={editHostApp} tagSuggestions={[...new Set(hosts.flatMap((h) => h.tags || []))].sort()}
            onSaved={refresh} onClose={() => setEditHostApp(null)} />
        </Suspense>
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
          onOpenSettings={() => { setSettingsCat(undefined); setSettingsSignal((n) => n + 1) }}
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
      {showLogoutConfirm && (
        <ConfirmModal
          title={t('logout.confirmTitle')}
          message={t('logout.confirmBody')}
          confirmLabel={t('logout.confirm')}
          onCancel={() => setShowLogoutConfirm(false)}
          onConfirm={async () => {
            setShowLogoutConfirm(false)
            clearClipHistory()
            await api('/api/logout', { method: 'POST' })
            setAppState({ ...appState, authenticated: false })
          }}
        />
      )}
      {snipParams && (
        <SnippetParams
          snippet={snipParams}
          onRun={(body) => { insertInSession(body); setSnipParams(null) }}
          onCancel={() => setSnipParams(null)}
        />
      )}
      {helpOpen && (
        <KeyboardHelp
          onClose={() => setHelpOpen(false)}
          onReplayWalkthrough={() => { setHelpOpen(false); setWalkthrough({ auto: false }) }}
        />
      )}
      {walkthrough && (
        <Walkthrough auto={walkthrough.auto} onClose={() => setWalkthrough(null)} />
      )}
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
      {secretReq && (
        <SecretPromptModal
          ask={secretReq.ask}
          onSubmit={(v) => { secretReq.resolve(v); setSecretReq(null) }}
          onCancel={() => { secretReq.resolve(null); setSecretReq(null) }}
        />
      )}
      {/* wizard „+ Split view": nume + bifezi ce sesiuni deschise intră (2–4) */}
      {wizard && (
        // scrim-ul închide doar la click PE el (nu pe dialog): fără stopPropagation pe dialog, deci
        // fără handler de click pe un element cu rol non-interactiv (jsx-a11y)
        <div role="presentation" className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
          onClick={(e) => { if (e.target === e.currentTarget) setWizard(null) }}>
          <TrapDialog onClose={() => setWizard(null)} labelledBy="wt-split-wizard-title"
            className="glass flex max-h-[80vh] w-full max-w-md flex-col rounded-2xl">
            <header className="border-b border-ink-800 px-4 py-3">
              <h2 id="wt-split-wizard-title" className="text-base font-semibold">{wizard.id ? t('split.editTitle') : t('split.wizardTitle')}</h2>
              <p className="mt-0.5 text-xs text-slate-400">{t('grid.pickHint', { max: GRID_MAX })}</p>
            </header>
            <div className="border-b border-ink-800 px-4 py-3">
              <label className="block">
                <span className="mb-0.5 block text-xs text-slate-400">{t('split.nameLabel')}</span>
                <input autoFocus value={wizard.name} onChange={(e) => setWizard((w) => (w ? { ...w, name: e.target.value.slice(0, 80) } : w))}
                  onKeyDown={(e) => { if (e.key === 'Enter' && wizard.sel.length >= 2) saveWizard() }}
                  placeholder={t('split.namePlaceholder')}
                  className="w-full rounded-md bg-ink-800 px-2 py-1 text-sm text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" />
              </label>
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto px-2 py-2">
              {openTabs.map((sid) => {
                const s = sessions.find((x) => x.id === sid)
                if (!s) return null
                const h = hosts.find((x) => x.id === s.host_id)
                const checked = wizard.sel.includes(sid)
                const atCap = !checked && wizard.sel.length >= GRID_MAX
                return (
                  <label key={sid}
                    className={`flex items-center gap-2.5 rounded-md px-2.5 py-2 ${atCap ? 'opacity-40' : 'cursor-pointer hover:bg-ink-800/60'}`}>
                    <input type="checkbox" checked={checked} disabled={atCap} onChange={() => toggleWizardPick(sid)}
                      className="h-4 w-4 shrink-0 accent-sky-500" />
                    <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: h ? hostColor(h) : '#64748b' }} />
                    <span className="min-w-0 flex-1 truncate text-sm text-slate-200">{s.title}</span>
                    <span className="shrink-0 truncate font-mono text-2xs text-slate-500">{h?.name}</span>
                  </label>
                )
              })}
            </div>
            <footer className="flex items-center gap-2 border-t border-ink-800 px-4 py-3">
              <span className="text-xs text-slate-500">{t('grid.pickCount', { n: wizard.sel.length, max: GRID_MAX })}</span>
              <button onClick={() => setWizard(null)}
                className="ml-auto rounded-md px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800">
                {t('common.cancel')}
              </button>
              <button disabled={wizard.sel.length < 2} onClick={saveWizard}
                className="rounded-md bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-40">
                {wizard.id ? t('common.save') : t('grid.pickConfirm')}
              </button>
            </footer>
          </TrapDialog>
        </div>
      )}
      {/* alarma de host-key schimbat: persistentă până la o decizie; „Keep blocking" e primul
          focusabil (= implicitul), acceptarea e butonul de pericol */}
      {hostKeyAlarm && (
        <div role="presentation" className="fixed inset-0 z-[70] flex items-center justify-center bg-black/60 p-4"
          onClick={(e) => { if (e.target === e.currentTarget) setHostKeyAlarm(null) }}>
          <TrapDialog alert onClose={() => setHostKeyAlarm(null)} labelledBy="wt-hostkey-title" describedBy="wt-hostkey-desc"
            className="glass w-full max-w-lg rounded-2xl p-6">
            <h2 id="wt-hostkey-title" className="wt-danger flex items-center gap-2 text-lg font-semibold leading-tight">
              <ShieldIcon /> {t('hostkey.title', { name: hostKeyAlarm.name })}
            </h2>
            <p id="wt-hostkey-desc" className="mt-2 text-sm leading-relaxed text-slate-300">{t('hostkey.intro')}</p>
            <dl className="mt-3 space-y-2 text-xs">
              <FingerprintRow label={t('hostkey.pinned')} value={hostKeyAlarm.old_fp} copyLabel={t('hostkey.copy')} />
              <FingerprintRow label={t('hostkey.received')} value={hostKeyAlarm.new_fp} copyLabel={t('hostkey.copy')} />
            </dl>
            {hostKeyAlarm.changed_at != null && (
              <p className="mt-2 text-xs text-slate-500">
                {t('hostkey.changedAt', { when: typeof hostKeyAlarm.changed_at === 'number' ? fmtTs(hostKeyAlarm.changed_at) : String(hostKeyAlarm.changed_at) })}
              </p>
            )}
            <p className="mt-3 text-sm leading-relaxed text-slate-300">{t('hostkey.meaning')}</p>
            <div className="mt-5 flex flex-wrap justify-end gap-2">
              <button onClick={() => setHostKeyAlarm(null)}
                className="rounded-md px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800">
                {t('hostkey.keepBlocking')}
              </button>
              <button onClick={acceptHostKey} disabled={hostKeyBusy}
                className="rounded-md bg-rose-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-rose-700 disabled:opacity-50">
                {t('hostkey.accept')}
              </button>
            </div>
          </TrapDialog>
        </div>
      )}
      {/* anunțuri pentru cititoarele de ecran (schimbare de tab / context) */}
      <div aria-live="polite" className="sr-only">{srAnnounce}</div>
      <Toasts items={toasts} onDismiss={(id) => setToasts((t) => t.filter((x) => x.id !== id))} onHoldChange={onToastHold} />
      {/* pre-idle-lock: non-modal, nu fură focusul; anunţul live e textul STABIL (titlul), nu
          numărătoarea — altfel cititorul de ecran ar repeta cifra la fiecare secundă */}
      {idleWarn != null && !idleDismissed && (
        <div className="fixed left-1/2 top-3 z-50 flex max-w-md -translate-x-1/2 items-center gap-3 rounded-xl border border-amber-500/40 bg-ink-900 px-4 py-2 text-sm text-slate-200 shadow-2xl">
          <span role="alert" className="sr-only">{t('idle.warnTitle')}</span>
          <div className="min-w-0" aria-hidden="true">
            <div className="wt-warn font-medium">{t('idle.warnTitle')}</div>
            <div className="text-xs text-slate-400">{t('idle.warnBody', { s: idleWarn })}</div>
          </div>
          <button onClick={stillHere}
            className="shrink-0 rounded-md bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-700">
            {t('idle.stillHere')}
          </button>
          <button onClick={() => setIdleDismissed(true)} aria-label={t('app.close')}
            className="shrink-0 rounded-md px-2 py-1 text-slate-500 hover:bg-ink-800 hover:text-slate-300">
            <CloseIcon size={14} />
          </button>
        </div>
      )}
      <CopyToast />
      {/* transferuri (upload/download) pe ORICE ecran — widget plutitor jos-dreapta, portat în
          <body>; se ascunde singur când nu e nimic. `activeSession` = ţinta pentru „inserează
          calea" (doar în sesiunea activă a aceluiaşi host). */}
      <TransfersWidget hosts={hosts} insertSid={activeSession?.id} insertHostId={activeSession?.host_id} />
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
            <CloseIcon size={14} />
          </button>
        </div>
      )}
    </div>
  )
}

