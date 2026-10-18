import { forwardRef, lazy, Suspense, useCallback, useEffect, useRef, useState } from 'react'
import { startAuthentication } from '@simplewebauthn/browser'
import { FitAddon } from '@xterm/addon-fit'
import { SearchAddon } from '@xterm/addon-search'
import { WebLinksAddon } from '@xterm/addon-web-links'
import { IDisposable, Terminal } from '@xterm/xterm'
import { modeRestoreSeq, pasteModeUntrusted, trustedBracketed } from '../lib/termmodes'
import { errText, api, CommandGuard, CommandRule, Host, Session, withStepup } from '../lib/api'
import { hostAt, hostColor, protoLabel, reachState } from '../lib/host'
import { Command, CommandTracker, cmdDuration, matchCommandRule, screenResetScan, splitAfterMarks } from '../lib/commands'
import { EchoTracker, LineKey, countCprReplies, countCprRequests, reportOnly, sendIsReport, sentArgs } from '../lib/echo'
import { ACCEPT_AND_HOLD, CTRL_O, ECHO_GRACE_MS, LocalVerdict, acceptsLine, broadcastDecision, escapeClears, escapeScope, localRunDecision, PeerState, PeerVerdict, RuleHit, guardActive, isSubmitKey, judgeLocal, judgePeers, metaAccept, opaqueInput, runDecision, splitLines, stripControls, submitsLine, unbracket } from '../lib/broadcastGuard'
import { anyHost, canOn, usePerms } from '../lib/perms'
import { clearCwd, parseOsc7, setCwd } from '../lib/cwd'
import { FONT_STORAGE_KEY, preferredFont, setPreferredFont } from '../lib/font'
import { extractUrls } from '../lib/urls'
import { useI18n } from '../lib/i18n'
import { fmtTs } from '../lib/tz'
import { hostScheme, termTheme } from '../lib/termtheme'
import { useElementWidth } from '../lib/useElementWidth'
import { sessionTitle } from '../lib/sessionTitle'
import CommandsPanel from './CommandsPanel'
import HostLoadRing from './HostLoadRing'
import FilePanel from './FilePanel'
import GitPanel from './GitPanel'
import ForwardsPanel from './ForwardsPanel'
import DockerPanel from './DockerPanel'
import ServicesPanel from './ServicesPanel'
// AI tools se deschide rar (din meniul contextual) → bundle separat, ca FileEditor
const AiToolsPanel = lazy(() => import('./AiToolsPanel'))
import ToolboxPanel from './ToolboxPanel'
import { ArrowDownIcon, ArrowUpIcon, CheckIcon, ChevronIcon, ClockIcon, CloseIcon, CopyIcon, DockerIcon, DownloadIcon, ExternalLinkIcon, EyeIcon, FileIcon, FilesIcon, FolderIcon, ForwardIcon, FullscreenIcon, GitBranchIcon, KeyIcon, KeyboardIcon, LockIcon, MenuIcon, MoreIcon, NoteIcon, PasteIcon, PencilIcon, PlayIcon, PopoutIcon, RefreshIcon, SearchIcon, ServicesIcon, ShareIcon, ShieldIcon, SparkleIcon, StopIcon, TerminalPromptIcon, ToolboxIcon, TrashIcon, UploadIcon, WarningIcon } from './Icons'
import { Badge, Button, IconButton } from './ui'
import { MenuUnreadBadge, useUnreadAlerts } from './AlertsPanel'
import { menuLabel } from '../lib/alerts'
import MobileKeybar from './MobileKeybar'
import SnippetsMenu from './SnippetsMenu'
import TranscriptPlayer from './TranscriptPlayer'
import { shortcutFor } from '../lib/shortcuts'
import StatusBar from './StatusBar'
import HostOfflineOverlay from './HostOfflineOverlay'
import { copyText, readText } from '../lib/clipboard'
import { clearAll as clearClipHistory, copySession, history as clipHistory, remove as removeClip, setLabel as setClipLabel, type ClipEntry } from '../lib/cliphistory'
import PastePicker from './PastePicker'
import { notify, notifyError, notifyToast } from '../lib/notify'
import { useConfirm } from '../lib/confirm'
import { useFocusTrap } from '../lib/useFocusTrap'
import { dismissUpload, lingerDone, startUpload } from '../lib/uploads'
import { isWriteDenied, uploadAndMoveAsRoot } from '../lib/rootmove'
import { uploadStore } from '../lib/uploadStore'
import { capturePasteContext, ensureInbox, inboxName, isGenericName, markPasteHintSeen, notTypedReasonKey, pasteDest, pasteHintSeen, pasteSubject, pasteSubjectText, pasteToastKey, pruneInbox, registerInsertTarget, resolveHome, typePastedPaths, typingElsewhere, type PasteContext } from '../lib/transfers'
import type { PasteDest } from '../lib/transfers'
import { baseName, looksLikePath, resolveTermPath } from '../lib/termpath'
import CoachTip from './CoachTip'
import { TIP_TERMINAL_PASTE, TIP_TOOLBAR, isTipDismissed } from '../lib/coachtips'
import { isWalkthroughDone } from '../lib/walkthrough'
import { lockTextKeys, ssoStepupRedirect, stepupPrompt, unlockLabelKey, wsUnlockMessage, type StepupCred, type StepupMethod } from '../lib/stepup'

// FileEditor (Monaco) e greu → lazy, exact ca-n FilePanel: intră în bundle doar când deschizi
// o cale-fişier din meniul contextual. Refolosim ACEEAŞI componentă (siguranţa la fişiere mari gratis).
const FileEditor = lazy(() => import('./FileEditor'))

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

/** Setări → Preferinţe → Terminal → „Randarea terminalului" (3.6.19): 'webgl' (implicit) | 'canvas' | 'dom',
    per browser; citită la fiecare (re)încărcare a renderer-ului. */
function readRendererPref(): string {
  try { const v = localStorage.getItem('wt_renderer'); return v === 'canvas' || v === 'dom' ? v : 'webgl' } catch { return 'webgl' }
}

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


/** Ce înregistrează un panou de split în App: trimiterea + starea lui pentru guardrail-ul unui
    Enter difuzat (linia tastată şi dacă o putem crede — vezi lib/broadcastGuard). */
export interface PaneHandle {
  send: (d: string | Uint8Array, kind?: 'key' | 'report' | 'auto') => void
  state: () => PeerState
}

/** cheia toastului unui paste/drop: unică şi după o remontare (review N2) — contor de modul + timp */
let pasteToastSeq = 0

export default function SessionView(props: {
  session: Session
  host?: Host
  initialSearch?: string | null
  searchNonce?: number
  popout?: boolean
  inSplit?: boolean               // e într-un split (orice panou) → border de delimitare
  activeInSplit?: boolean         // e panoul ACTIV din split → border-accent
  onSplitView?: () => void        // right-click „Add to split view" (deschide wizard-ul)
  paneActive?: boolean
  /** panoul se VEDE (în split: toate panourile afişate, nu doar cel focalizat). Lipsă = paneActive.
      Decide recuperarea rendererului la revenirea tabului — un panou vizibil dar nefocalizat
      rămânea alb după ce browserul elibera contextul WebGL (3.6.12). */
  paneVisible?: boolean
  /** creşte → terminalul primeşte focusul tastaturii (intrarea într-un split, Alt+←/→ între panouri) */
  focusNonce?: number
  /** creşte → panoul îşi reclamă dimensiunea ca dispozitiv ACTIV (split montat, formă schimbată,
      divider eliberat): toate panourile vizibile ale split-ului, nu doar cel focalizat */
  layoutNonce?: number
  actionTarget?: boolean          // ținta acțiunilor de sesiune (în split = panoul focusat)
  /** false = tab montat dar invizibil: serverul pune fluxul pe pauză
      (economie de trafic); la revenire se face resync automat */
  streamActive?: boolean
  /** Ceremonia de step-up (passkey sau, fără WebAuthn, parola contului). Vine din App,
      unde e definită o singură dată — SessionView avea o a doua implementare, care ştia
      DOAR de passkey: pe o instalare pe IP gol (fără WebAuthn) sesiunea blocată devenea
      irecuperabilă, fiindcă nu exista nicio cale de deblocare. */
  stepupCredential?: (hostId: number, code?: string) => Promise<StepupCred | null>
  /** factorul contului (`/api/state.stepup_method`) + dacă WebAuthn e disponibil: eticheta
      butonului de deblocare spune ce se va cere (passkey / cod / SSO), nu mereu „passkey" */
  stepupMethod?: StepupMethod | null
  webauthn?: boolean
  onMenu: () => void
  sidebarCollapsed?: boolean
  onPopout?: () => void
  onChanged: () => void
  onDeleted: () => void
  /** hostul-părinte (`via_host_id`) al unei ţinte SSH/telnet-jump — overlay-ul „host offline"
      vorbeşte despre el când tunelul agentului lui a căzut */
  viaHost?: Host
  /** pagina unui host (overlay-ul „host offline"); lipsă în pop-out → link spre aplicaţie */
  onOpenHost?: (id: number) => void
  /** deschide o sesiune existentă (după sid) — folosit de panoul de forward-uri
      pentru a lansa o sesiune telnet-bastion într-un tab de terminal */
  onOpenSession?: (sid: string) => void
  /** deschide un shell într-un container Docker (docker exec într-un tab nou) */
  onOpenContainerShell?: (host: Host, container: string) => void
  /** „Logs" dintr-un container: sesiune cu `docker logs -f` într-un tab nou */
  onOpenContainerLogs?: (host: Host, container: string, name?: string) => void
  onJournal?: (host: Host, unit: string) => void
  /** deschide o sesiune care rulează CLI-ul unei conexiuni DB salvate */
  onOpenConnection?: (host: Host, connId: number) => void
  /** guardrail de comenzi (verificat la Enter, via OSC 133) */
  commandGuard?: CommandGuard | null
  /** broadcast (grid): înregistrează funcţia de trimitere a acestui panou sus, ca App să poată
      difuza tastele către toate panourile; raportează tastele locale; afişează indicatorul */
  registerSend?: (sid: string, handle: PaneHandle | null) => void
  onUserData?: (sid: string, d: string | Uint8Array, kind?: 'key' | 'report') => void
  broadcasting?: boolean
  /** broadcast: starea CELORLALTE panouri ale split-ului (linia tastată via OSC 133 + flux viu +
      ecou primit) — guardrail-ul verifică fiecare panou-ţintă, nu doar originea (3.6.12) */
  peerStates?: (sid: string) => PeerState[]
}) {
  const { session } = props
  const { t } = useI18n()
  const unreadAlerts = useUnreadAlerts()
  // 3.6 roluri (audit 2026-10-17, FL-09): uneltele din bară urmează permisiunile de pe ACEST host —
  // cosmetic (serverul refuză oricum cu 403), dar omul află ÎNAINTE de gest, nu după (docs/design/
  // ROLES-AND-SSH.md §A.9 „hide vs disable": ascuns când n-ai permisiunea pe niciun host, dezactivat
  // cu motivul în tooltip când o ai altundeva). Până la primul răspuns totul e permis (lib/perms).
  const perms = usePerms()
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
  /** preferinţa de renderer aplicată ultima dată (Setări → Terminal): un panou ascuns (stiva keep-alive,
      split neactiv) nu primeşte evenimentul cât e ascuns — la reactivare compară şi reîncarcă dacă s-a schimbat */
  const appliedRendererRef = useRef<string>('webgl')
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
  // 3.6: ataşare read-only (rolul dă doar `session.watch`, sau sesiunea e a altcuiva): tastatura
  // e inertă şi pastila „watching (read-only)" o spune. Serverul aruncă oricum input-ul.
  const readOnlyRef = useRef(false)
  const [readOnly, setReadOnly] = useState(false)
  // Input cât socketul NU e deschis: PAUZĂ explicită, nu buffer. Serverul rejoacă la fiecare
  // (re)conectare doar OUTPUT-ul (tail-ul tmux), niciodată input-ul, şi nu confirmă octeţii
  // primiţi — deci un buffer trimis „orb" la onopen ar ateriza într-un shell a cărui stare
  // s-a schimbat între timp (comanda anterioară s-a terminat, un TUI s-a deschis), iar
  // utilizatorul care n-a văzut nimic întâmplându-se a retastat deja comanda → dublu `rm`.
  // Numărăm tastele pierdute şi le anunţăm la reconectare; cortina de mai jos face pauza vizibilă.
  const droppedRef = useRef(0)
  const everOpenRef = useRef(false)          // prima conectare e „connecting", nu „reconnecting"
  const flashTimerRef = useRef<ReturnType<typeof setTimeout> | 0>(0)
  const [inputFlash, setInputFlash] = useState(false)
  const [inputNotice, setInputNotice] = useState<string | null>(null)
  // un singur anunţ sub cortină la un moment dat: cel nou îl înlocuieşte pe cel vechi ŞI timerul lui
  // (altfel timerul unui anunţ mai vechi îl stingea pe cel nou după o secundă)
  const noticeTimerRef = useRef<ReturnType<typeof setTimeout> | 0>(0)
  const showInputNotice = useCallback((msg: string, ms = 8000) => {
    clearTimeout(noticeTimerRef.current)
    setInputNotice(msg)
    noticeTimerRef.current = setTimeout(() => setInputNotice(null), ms)
  }, [])
  // închidere cu cod terminal de la gateway (4401 auth / 4403 interzis): fără buclă de retry
  const [wsDenied, setWsDenied] = useState<'auth' | 'forbidden' | null>(null)
  const replayRef = useRef(false)   // scriem istoric, nu activitate live (vezi OSC 133)
  // ecou (guardrail broadcast, review 3.6.12 M1): câte trimiteri au plecat spre host şi până la a
  // câta a sosit output DUPĂ ele. echoed < input = linia din tracker poate fi dinaintea ultimelor taste.
  // ecou (guardrail, review 3.6.12 M1; strâns + per trimitere în 3.6.13): câte trimiteri au plecat spre
  // host şi care au primit ecou — vezi lib/echo.ts
  const echoRef = useRef(new EchoTracker())
  // un paste e în curs (handler-ul de captură → xterm.paste → onData, sincron): datele lui nu sunt rapoarte
  const pastingRef = useRef(false)
  // începutul neterminat al unei secvenţe de la capătul output-ului anterior (vezi screenResetScan)
  const resetCarryRef = useRef<Uint8Array>(new Uint8Array(0))
  // cereri CPR (`CSI 6 n`) din output încă fără răspuns: doar atunci `CSI 1;n R` e un raport (LOW-B)
  const cprRef = useRef(0)
  const rttRef = useRef<number | null>(null)
  const streamDecoderRef = useRef(new TextDecoder('utf-8'))   // pt. captura output-ului
  // termen de căutare care așteaptă finalizarea replay-ului de istoric
  const pendingFindRef = useRef<string | null>(null)
  // keep-alive (tab-uri ținute montate): la comutare, terminalul rămas ascuns
  // ar păstra focusul tastaturii — refocalizăm explicit pe cel devenit vizibil
  useEffect(() => {
    if (!props.paneActive) return
    // într-un split, selecţia poate veni din focusul pus de user pe un buton al ACESTUI panou
    // (Tab până la bara lui / header): nu-i furăm focusul înapoi în terminal (3.6.12)
    const ae = document.activeElement as HTMLElement | null
    const pane = rootRef.current?.closest('[data-split-pane]')
    if (pane && ae && ae !== document.body && pane.contains(ae) && !ae.closest('.xterm')) return
    termRef.current?.focus()
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
  // motivul blocării, din mesajul `locked` (3.5.13): `stepup_max` = plafonul de 60 min de la
  // factorul care a autorizat terminalul; altfel (idle / ataşare fără step-up) textul de idle-lock
  const [lockReason, setLockReason] = useState('')
  // codul ultimului refuz de deblocare (ex. `stepup.totp`): următoarea încercare cere exact
  // factorul pe care serverul l-a cerut, nu iar parola
  const unlockCodeRef = useRef('')
  const [unlockCode, setUnlockCode] = useState('')   // acelaşi cod, pentru eticheta butonului
  const unlockBtnRef = useRef<HTMLButtonElement>(null)
  const [reconnecting, setReconnecting] = useState(false)
  // titlul implicit «Session N» se arată tradus; se salvează doar dacă omul îl schimbă
  const [title, setTitle] = useState(() => sessionTitle(session.title, t))
  const [note, setNote] = useState(session.note)
  const [showNote, setShowNote] = useState(!!session.note)
  const [showSearch, setShowSearch] = useState(false)
  const [snippetsOpen, setSnippetsOpen] = useState(false)
  const [showPlayer, setShowPlayer] = useState(false)
  // guardrail de comenzi: config live într-un ref (handler-ul de taste e capturat la
  // montare, deci nu poate citi prop-ul direct), + dialog de confirmare + mesaj tranzitoriu
  const commandGuardRef = useRef(props.commandGuard)
  /** Prima linie dintr-un text (lipit) care atinge o regulă de guardrail (+ tiparul regulii, ca
      mesajul să spună DE CE, ca în fleet/panouri), sau null. */
  const guardedLine = (text: string): { line: string; pattern: string } | null => {
    for (const line of splitLines(text)) {
      const l = line.trim()
      const rule = l ? matchCommandRule(l, commandGuardRef.current) : null
      if (rule) return { line: l, pattern: rule.pattern }
    }
    return null
  }
  useEffect(() => { commandGuardRef.current = props.commandGuard }, [props.commandGuard])
  // `t` prin ref, ca `commandGuard` de mai sus. Efectul terminalului depinde doar de
  // `session.id` (are `eslint-disable` pe `exhaustive-deps`, deliberat: re-rularea lui ar
  // distruge şi ar reconstrui terminalul viu la fiecare schimbare de limbă). Dar `t` intra în
  // handlerul de taste, care trăieşte cât sesiunea — deci după comutarea limbii mesajul de
  // guardrail rămânea în limba veche până la remontare. Ref-ul e citit la momentul apelului,
  // deci mereu proaspăt, fără să atingem ciclul de viaţă al terminalului.
  const tRef = useRef(t)
  tRef.current = t
  // numele panoului în dialogul guardrail-ului broadcast (ce panou ar rula linia)
  const paneLabelRef = useRef('')
  paneLabelRef.current = title || props.host?.name || ''
  // `unknown` = broadcast cu un panou-ţintă neverificabil (pauză / fără ecou încă) — nu o regulă;
  // `run` = ce pleacă la „Rulează" (implicit Enter; un snippet multi-linie îşi trimite textul)
  // `hits` (broadcast) = TOATE liniile care ating o regulă, cu panourile lor — dialogul le arată pe toate;
  // `recheck` (broadcast) = verdictul refăcut la „Rulează", pe ORICE dialog: Enter-ul pleacă doar dacă
  // e ok sau acelaşi set de confirmări văzut, altfel escaladează (review final 3.6.12, M; L-e).
  // FĂRĂ `recheck` = dialog deschis fără broadcast: „Rulează" / golirea liniei rămân LOCALE, chiar
  // dacă broadcast-ul a pornit între timp (verificare 3.6.12, F2).
  // `unreadable` = id-urile panourilor neverificabile acceptate în dialog (F5); `opaque` = input cu
  // taste de editare, textul verificat nu e cel care rulează (F4)
  /** `run` = text reţinut, NEtastat (snippet, chunk de paste): „Rulează" îl trimite întreg, Anulează nu goleşte nimic;
      `submit` = tasta de trimitere reţinută (`\r`, `\n`, `\x0f`, `ESC a` sau `a`-ul de după un Escape singur — SV-01)
      a unei linii deja tastate: „Rulează" o trimite pe EA (semantica shell-ului rămâne: istoric / păstrare în buffer) */
  const [cmdConfirm, setCmdConfirm] = useState<{ cmd: string; pattern: string; below?: boolean; unknown?: boolean; run?: string; submit?: string; hits?: RuleHit[]; recheck?: () => PeerVerdict; unreadable?: string[]; opaque?: boolean; echo?: boolean; localRecheck?: () => LocalVerdict } | null>(null)
  const [guardMsg, setGuardMsg] = useState<string | null>(null)
  // confirm()/alert() native → dialoguri proprii + toast-uri (vezi lib/confirm.tsx: de ce)
  const { confirm } = useConfirm()
  // Dialogul de guardrail: focusul intră pe „Anulează" când apare (altfel rămânea în textarea
  // xterm, unde Enter/Escape se duceau în SHELL — adică exact comanda pe care o verificam).
  // La închidere handlerele redau focusul terminalului.
  const cmdCancelBtnRef = useRef<HTMLButtonElement>(null)
  // containerul dialogului: Escape-ul e al nostru doar cu focusul în el / în panou (SV-04)
  const cmdDialogRef = useRef<HTMLDivElement>(null)
  useEffect(() => { if (cmdConfirm) cmdCancelBtnRef.current?.focus() }, [cmdConfirm])
  // comenzi (OSC 133) — apar doar cu shell integration activă pe host
  const trackerRef = useRef<CommandTracker>()
  // ultimul rând al ecranului poate fi bara de stare tmux (CommandTracker.pendingBelow)
  if (trackerRef.current) trackerRef.current.tmuxBacked = props.host?.backend === 'tmux'
  // sub tmux (agent tmux / SSH) `bracketedPasteMode` e lipicios — nu-l credem (termmodes.ts, hotfix 3.6.13)
  const pasteUntrustedRef = useRef(true)
  pasteUntrustedRef.current = pasteModeUntrusted(props.host)
  // dialogul guardrail-ului deschis: inserarea unei căi aşteaptă (review hotfix 3.6.13, L2)
  const cmdConfirmOpenRef = useRef(false)
  cmdConfirmOpenRef.current = !!cmdConfirm
  const cwdRef = useRef<string | null>(null)   // cwd curent, pt. raportarea în istoric (fără stale closure)
  const decorationsRef = useRef<IDisposable[]>([])
  const [commands, setCommands] = useState<Command[]>([])
  const [showCommands, setShowCommands] = useState(false)
  // panourile din dreapta (comenzi / fișiere / git / forward-uri) împart marginea → unul o dată
  const [showFiles, setShowFiles] = useState(false)
  const [showForwards, setShowForwards] = useState(false)
  const [showGit, setShowGit] = useState(false)
  const [showDocker, setShowDocker] = useState(false)
  const [showServices, setShowServices] = useState(false)
  const [showToolbox, setShowToolbox] = useState(false)
  const [showAi, setShowAi] = useState(false)
  // un singur panou din dreapta o dată: la deschiderea unuia, le închid pe celelalte
  const closeOthers = (keep: 'files' | 'cmd' | 'fwd' | 'git' | 'docker' | 'services' | 'toolbox' | 'ai') => {
    if (keep !== 'ai') setShowAi(false)
    if (keep !== 'files') setShowFiles(false)
    if (keep !== 'cmd') setShowCommands(false)
    if (keep !== 'fwd') setShowForwards(false)
    if (keep !== 'git') setShowGit(false)
    if (keep !== 'docker') setShowDocker(false)
    if (keep !== 'services') setShowServices(false)
    if (keep !== 'toolbox') setShowToolbox(false)
  }
  const toggleFiles = () => setShowFiles((v) => { if (!v) closeOthers('files'); return !v })
  const toggleCommands = () => setShowCommands((v) => { if (!v) closeOthers('cmd'); return !v })
  const toggleForwards = () => setShowForwards((v) => { if (!v) closeOthers('fwd'); return !v })
  const toggleGit = () => setShowGit((v) => { if (!v) closeOthers('git'); return !v })
  const toggleDocker = () => setShowDocker((v) => { if (!v) closeOthers('docker'); return !v })
  const toggleServices = () => setShowServices((v) => { if (!v) closeOthers('services'); return !v })
  const toggleToolbox = () => setShowToolbox((v) => { if (!v) closeOthers('toolbox'); return !v })
  const [activeCmd, setActiveCmd] = useState<number | null>(null)
  const activeCmdRef = useRef<number | null>(null)   // citit de stepCommand (handler-ul de taste e capturat la montare)
  // cwd raportat de shell prin OSC 7 (apare doar cu shell integration activă)
  const [cwd, setCwdState] = useState<string | null>(null)

  // -- transferuri din terminal: drop pe terminal / paste de fişiere ----------------------
  // Hostul trebuie să aibă agent (fs API); pe SSH direct / telnet nu interceptăm nimic.
  const canTransfer = !!props.host && (!props.host.connection_type || props.host.connection_type === 'agent')
  const [dropHover, setDropHover] = useState(false)
  const dragDepth = useRef(0)      // dragenter/dragleave vin şi de la copii — numărăm, nu comutăm
  const hasFiles = (dt: DataTransfer | null) => !!dt && Array.from(dt.types).includes('Files')
  /** directorul ţintă al unui drop/paste „în sesiune": cwd-ul din OSC 7 când îl ştim, altfel
      home-ul hostului (rezolvat absolut, ca inserarea să dea o cale pe care o înţelege orice CLI) */
  const sessionDir = useCallback(async (): Promise<string> =>
    cwdRef.current ?? await resolveHome(props.host!.id), [props.host])
  const uploadFiles = useCallback((dir: string, files: { file: File; name: string }[], onDone?: (name: string) => void,
    pasteCtx?: PasteContext): Promise<string[]> => {
    const host = props.host!
    // rolul nu poate scrie fişiere pe hostul ăsta: refuzăm înainte de orice cerere — apelanţii
    // (drop / paste) îşi înlocuiesc toastul „Uploading…" cu eroarea, nu cu „Saved" (altfel toastul
    // era urmat de 403) — serverul rămâne verificarea reală (audit P1, FL-09)
    if (!canOn(perms, host.id, 'files.write')) return Promise.reject(new Error(t('files.needsWrite')))
    // întoarcem id-urile (rezolvate la finalul primei treceri): apelantul citeşte starea finală din
    // store ca să decidă toastul de „gata" vs eroare — un singur toast per paste, nu unul per fişier
    return Promise.all(files.map(({ file, name }) =>
      startUpload({ hostId: host.id, hostName: host.name, dest: `${dir.replace(/\/$/, '')}/${name}`, file,
                    then: 'insert-path', sid: session.id, pasteCtx })
        .then((id) => { if (onDone && uploadStore.get(id)?.state === 'done') onDone(name); return id })))
  }, [props.host, session.id, perms, t])
  // Toast de final (sau de eroare) după ce toate fişierele unui paste/drop au trecut. Explică
  // SEMANTICA paste-ului (salvat unde + calea inserată la prompt), complementar cu widgetul de
  // transferuri (care arată job-ul). Un singur toast, indiferent câte fişiere.
  // `tkey`: cheia toastului paste-ului — rezultatul ÎNLOCUIEŞTE „Se încarcă…" (un paste = un toast)
  const finishPaste = (ids: string[], dest: PasteDest, subject: string, kind: ReturnType<typeof pasteSubject>['kind'], tkey: string) => {
    const jobs = ids.map((id) => uploadStore.get(id))
    const failed = jobs.filter((j) => !j || j.state !== 'done')
    if (failed.length) { notifyError(t('transfers.uploadFailedTitle'), failed[0]?.error || t('files.genericErr'), tkey); return }
    // calea NETASTATĂ (un program rulează — hotfix 3.6.13): toastul nu mai spune „adăugată la prompt";
    // rândul din Transferuri (deschis automat) oferă „Tastează în terminal" + „Copy path"
    const notTyped = jobs.find((j) => j?.inserted === false)
    if (notTyped) {
      // 'notPrompt': rândul are deja explicaţia întreagă (de ce + ce poţi face) lângă buton — toastul
      // rămâne O linie (pe telefon cel lung acoperea jumătate de ecran). Celelalte motive (fără ţintă,
      // text nesigur, refuzat) n-au buton/explicaţie în rând, deci le spunem aici.
      const why = notTyped.insertOutcome === 'notPrompt' ? '' : ` ${t(notTypedReasonKey(notTyped.insertOutcome ?? 'refused'))}`
      notifyToast(`${t('transfers.pasteNotTyped', { subject })}${why}`, 'warn', tkey)
      return
    }
    let msg = t(pasteToastKey('done', dest, kind), { subject })
    // prima captură lipită: o propoziţie în plus despre LA CE foloseşte (o singură dată)
    if (kind === 'screenshot' && !pasteHintSeen()) { msg += ' ' + t('transfers.pasteFirstHint'); markPasteHintSeen() }
    notifyToast(msg, 'info', tkey)
  }
  // 3.6.9: drop/paste în cwd-ul unui shell root (dosar al lui root) — userul agentului nu poate scrie
  // acolo. În loc de doar o eroare: oferim „urcă în inbox + tastează comanda `sudo install`" (nu o
  // rulează nimeni; Enter îl apasă omul). true = am tratat refuzul (oferit sau anulat).
  const offerRootMove = async (ids: string[], dir: string, items: { file: File; name: string }[], tkey: string): Promise<boolean> => {
    const host = props.host!
    const refused = ids.map((id) => uploadStore.get(id))
      .filter((j) => j && j.state === 'err' && isWriteDenied(j.errorCode))
    if (!refused.length) return false
    const names = new Set(refused.map((j) => (j!.dest.split('/').pop() ?? '')))
    const files = items.filter((it) => names.has(it.name))
    const ok = await confirm({
      title: t('transfers.rootMoveTitle'),
      message: `${refused[0]!.error ?? ''} ${t('transfers.rootMoveAsk', { user: host.agent_user || '?' })}`,
      confirmLabel: t('files.denied.optRoot'),
    })
    if (!ok) { notifyError(t('transfers.uploadFailedTitle'), refused[0]!.error || t('files.genericErr'), tkey); return true }
    for (const j of refused) dismissUpload(j!.id)
    try {
      const r = await uploadAndMoveAsRoot({ hostId: host.id, hostName: host.name, dir, files, sid: session.id })
      if (r.failed.length) notifyError(t('transfers.uploadFailedTitle'), t('files.denied.inboxFailed', { names: r.failed.slice(0, 3).join(', ') }), tkey)
      else if (r.typed) notifyToast(t('files.denied.typedToast'), 'info', tkey)
      else if (await copyText(r.command)) notifyToast(t('transfers.rootMoveCopied'), 'warn', tkey)
      else notifyError(t('transfers.uploadFailedTitle'), t('transfers.rootMoveNotTyped'), tkey)
    } catch (e) { notifyError(t('transfers.uploadFailedTitle'), errText(e, t) || t('files.genericErr'), tkey) }
    return true
  }
  /** 3.6.16: căile unui paste/drop, tastate ca un paste în ORDINEA selecţiei (ids = ordinea fişierelor),
      fiecare re-verificată (lib/transfers.ts typePastedPaths). Upload-urile amânate (uploads.ts) n-au
      încă rezultat; aici îl scriem în rând — 'notPrompt' aduce „Type into terminal" + motivul. */
  /** Finalul unui gest (review N3): dacă fluxul a aruncat ÎNAINTE de typePasted, upload-urile deja
      terminate ale gestului au rămas fără rezultat (amânate în uploads.ts) — le dăm unul ('refused':
      nimic tastat, rândul oferă Copy path / Insert path) şi le lăsăm să expire ca orice upload gata.
      Apoi contextul se închide: un retry ulterior urmează regulile vechi. */
  const closePaste = (ctx: PasteContext | undefined) => {
    if (!ctx) return
    if (!ctx.closed) {
      for (const j of uploadStore.snapshot().values()) {
        if (j.sid === session.id && j.then === 'insert-path' && j.state === 'done' && j.insertOutcome === undefined) {
          uploadStore.patch(j.id, { inserted: false, insertOutcome: 'refused' })
          lingerDone(j.id)
        }
      }
    }
    ctx.closed = true
  }
  const typePasted = (ids: string[], ctx: PasteContext | undefined) => {
    if (!ctx) return
    const jobs = ids.map((id) => uploadStore.get(id))
      .filter((j): j is NonNullable<typeof j> => !!j && j.state === 'done' && j.then === 'insert-path' && j.insertOutcome === undefined)
    const res = typePastedPaths(ctx, jobs.map((j) => j.dest))
    jobs.forEach((j, i) => {
      const { outcome, stale } = res[i]
      uploadStore.patch(j.id, { inserted: outcome === 'typed', insertOutcome: outcome,
        pasteStale: outcome === 'notPrompt' && stale ? stale : undefined })
      if (outcome === 'typed') lingerDone(j.id)
    })
  }
  const onTermDrop = async (files: File[]) => {
    // contextul gestului, ÎNAINTE de orice await (3.6.16): calea se tastează ca un paste doar cât
    // terminalul, panoul activ şi inputul rămân cele de acum (lib/transfers.ts typeIntoPasted)
    const ctx = capturePasteContext(session.id)
    const tkey = `paste-${session.id}-${Date.now()}-${++pasteToastSeq}`   // un gest = un toast, actualizat pe loc
    const subj = pasteSubject(files)
    const subject = pasteSubjectText(subj, t)
    // feedback IMEDIAT (înainte de orice await): tragerea fişierelor trebuie să se simtă confirmată
    notifyToast(t(pasteToastKey('start', 'cwd', subj.kind), { subject }), 'info', tkey)
    try {
      const dir = await sessionDir()
      const items = files.map((f) => ({ file: f, name: f.name }))
      const ids = await uploadFiles(dir, items, undefined, ctx)
      typePasted(ids, ctx)
      if (await offerRootMove(ids, dir, items, tkey)) return
      finishPaste(ids, 'cwd', subject, subj.kind, tkey)
    } catch (e) { notifyError(t('transfers.uploadFailedTitle'), errText(e, t) || t('files.genericErr'), tkey) }
    finally { closePaste(ctx) }   // un retry ulterior nu mai e „paste": regulile vechi
  }
  // Paste de imagine/fişier: un CLI cu AI rulat aici NU vede clipboardul browserului — îi dăm
  // fişierul pe host (inbox-ul `~/.webterm/inbox`, sau cwd-ul, după preferinţă) şi calea la
  // prompt. Numele: timestamp + extensie din MIME; fişierele cu nume îl păstrează, prefixat.
  const pasteFiles = async (files: File[]) => {
    const ctx = capturePasteContext(session.id)      // vezi onTermDrop: înainte de orice await
    const tkey = `paste-${session.id}-${Date.now()}-${++pasteToastSeq}`
    const host = props.host!
    const dest: PasteDest = pasteDest()
    const toInbox = dest === 'inbox'
    const subj = pasteSubject(files)
    const subject = pasteSubjectText(subj, t)
    // feedback IMEDIAT, înainte de ensureInbox/resolveHome (round-trip): Ctrl+V trebuie confirmat pe loc
    notifyToast(t(pasteToastKey('start', dest, subj.kind), { subject }), 'info', tkey)
    try {
      const dir = toInbox ? await ensureInbox(host.id) : await sessionDir()
      const when = new Date()
      let generic = 0
      const items = files.map((f) => ({ file: f, name: inboxName(f, when, isGenericName(f.name) ? ++generic : 1) }))
      // retenţia inbox-ului rulează după un upload reuşit, niciodată peste fişierul tocmai urcat
      const ids = await uploadFiles(dir, items, toInbox ? (name) => { void pruneInbox(host.id, dir, name) } : undefined, ctx)
      typePasted(ids, ctx)
      if (!toInbox && await offerRootMove(ids, dir, items, tkey)) return
      finishPaste(ids, dest, subject, subj.kind, tkey)
    } catch (e) { notifyError(t('transfers.uploadFailedTitle'), errText(e, t) || t('files.genericErr'), tkey) }
    finally { closePaste(ctx) }   // un retry ulterior nu mai e „paste": regulile vechi
  }
  const pasteFilesRef = useRef(pasteFiles)
  pasteFilesRef.current = pasteFiles
  const canTransferRef = useRef(canTransfer)
  canTransferRef.current = canTransfer
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
  // după „Generate link" butonul apăsat dispare odată cu formularul → focusul cădea pe <body>.
  // Îl mutăm pe primul buton al barei cu linkul generat (Copy) — audit funcţional 3.6.3
  const shareBarRef = useRef<HTMLDivElement>(null)
  const shareUrlSeen = useRef<string | null>(null)
  useEffect(() => {
    if (shareUrl && shareUrl !== shareUrlSeen.current) shareBarRef.current?.querySelector<HTMLElement>('button')?.focus()
    shareUrlSeen.current = shareUrl
  }, [shareUrl])
  const [shareOpen, setShareOpen] = useState(false)          // panoul de opțiuni
  const [shareWritable, setShareWritable] = useState(false)  // opțiune: writable?
  const [shareExpiry, setShareExpiry] = useState(1440)       // opțiune: minute
  // share-ul ACTIV (de pe server): supravieţuieşte reload-ului. URL-ul (`shareUrl`) există doar în
  // tab-ul care l-a generat — token-ul e hash-uit pe server, deci nu se poate reconstrui; după un
  // reload rămân starea (read-only/writable, expirare) şi butonul de revocare.
  const [shareActive, setShareActive] = useState<{ writable: boolean; expires?: number } | null>(null)
  useEffect(() => {
    if (props.popout) return           // fereastra popout n-are UI de share
    let alive = true
    api<{ active: boolean; writable?: boolean; expires?: number }>(`/api/sessions/${session.id}/share`)
      .then((r) => { if (alive) setShareActive(r.active ? { writable: !!r.writable, expires: r.expires } : null) })
      .catch(() => { /* gateway vechi / fără drept: rămâne starea locală */ })
    return () => { alive = false }
  }, [session.id, props.popout])
  // link expirat → bara dispare singură (altfel „Revocă" ar rămâne pe un link deja mort)
  useEffect(() => {
    if (!shareActive?.expires) return
    const ms = shareActive.expires * 1000 - Date.now()
    const clear = () => { setShareActive(null); setShareUrl(null) }
    if (ms <= 0) { clear(); return }
    const timer = window.setTimeout(clear, Math.min(ms, 2 ** 31 - 1))
    return () => clearTimeout(timer)
  }, [shareActive])
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
  // Bara de unelte se pliază după LĂŢIMEA PANOULUI, nu a ferestrei (audit funcţional 3.6.3, #5):
  // într-un split 2×2 la 1440px fiecare panou are ~570px, dar `lg:`/`sm:` vedeau 1440 — Fullscreen
  // şi Stop ieşeau din panou, de neatins. Pragurile sunt cele de dinainte (sm 640 / lg 1024).
  const headerRef = useRef<HTMLElement>(null)
  const paneW = useElementWidth(headerRef)
  const roomy = paneW >= 640    // uneltele principale (Files, Git, Docker…) în bară
  const wide = paneW >= 1024    // şi cele secundare (Note, Share, Fullscreen…) — altfel în ⋯
  // „Mai multe" = disclosure (3.6.3, U23): trigger cu aria-expanded/aria-controls; Escape (şi din
  // afara panoului, cât e deschis) închide şi întoarce focusul pe trigger
  const moreId = `session-more-${session.id}`
  const moreBtnRef = useRef<HTMLButtonElement>(null)
  const morePanelRef = useRef<HTMLDivElement>(null)
  const closeMore = useCallback((restore: boolean) => {
    setMoreOpen(false)
    if (restore) requestAnimationFrame(() => moreBtnRef.current?.focus())
  }, [])
  useEffect(() => {
    if (!moreOpen) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return
      const a = document.activeElement
      // focusul e pe trigger / în panou → închidem şi îl lăsăm pe trigger; din terminal (focusul
      // rămâne acolo la clic, onMouseDown preventDefault) doar închidem, fără să-l furăm
      const ours = a === moreBtnRef.current || !!morePanelRef.current?.contains(a)
      closeMore(ours)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [moreOpen, closeMore])
  // paste picker: history-ul de clipboard GLOBAL, comun tuturor terminalelor (Cmd+Shift+V) — vezi
  // lib/cliphistory. Eticheta sursei = titlul sesiunii sau numele hostului, ţinută la zi aici.
  const [pasteItems, setPasteItems] = useState<ClipEntry[] | null>(null)
  const clipLabel = session.title || props.host?.name || ''
  useEffect(() => { setClipLabel(session.id, clipLabel) }, [session.id, clipLabel])
  // meniul „Linkuri": URL-urile din buffer, extrase la deschidere (nu continuu) — vezi lib/urls
  const [linksOpen, setLinksOpen] = useState(false)
  const [links, setLinks] = useState<string[]>([])
  const openLinks = useCallback(() => {
    setLinks(extractUrls(termRef.current))
    setLinksOpen(true)
  }, [])
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number } | null>(null)
  // meniu contextual → acţiuni de fişiere. `filesReveal`/`filesAction` conduc FilePanel prin
  // `revealPath`/`initialAction`; `filesNonce` FORŢEAZĂ remontarea (prop-ul de reveal se citeşte
  // doar la montare) ca „Descarcă…/Fişier nou” să re-navigheze chiar dacă panoul era deja deschis.
  const [filesReveal, setFilesReveal] = useState<string | undefined>(undefined)
  const [filesAction, setFilesAction] = useState<'newFile' | 'newFolder' | undefined>(undefined)
  const [filesNonce, setFilesNonce] = useState(0)
  // o cale-fişier selectată se deschide DIRECT în FileEditor (aceeaşi componentă ca panoul)
  const [editorFile, setEditorFile] = useState<{ path: string; name: string } | null>(null)
  const uploadInputRef = useRef<HTMLInputElement>(null)
  // cât submeniul „Fişiere ▸” e deschis, el îşi tratează propriul Escape (←/Esc îl închide),
  // deci handlerul global de Escape al meniului nu trebuie să închidă TOT meniul peste el
  const submenuOpenRef = useRef(false)
  const longPressRef = useRef<number | null>(null)
  const remoteResizeReloadRef = useRef<number | null>(null)   // debounce pt. recrearea rendererului la resize de la alt client
  // Escape închide meniul contextual (înainte ca xterm să trimită Esc în shell)
  useEffect(() => {
    if (!ctxMenu) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        // submeniul deschis îşi înghite propriul Escape (îl închide doar pe el); altfel închidem tot
        if (submenuOpenRef.current) return
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

  // ── Sfaturi contextuale (coach tips) ─────────────────────────────────────────────────────
  // Completează walkthrough-ul de primă rulare (nu-l dublează): arătate o dată, la momentul
  // potrivit, lângă UI-ul concret. Scalonate — întâi paste/drop (doar unde transferul merge),
  // apoi, DUPĂ ce acela e închis, toolbar-ul — ca două callout-uri să nu apară simultan.
  const [showPasteTip, setShowPasteTip] = useState(false)
  const [showToolbarTip, setShowToolbarTip] = useState(false)
  // într-un split sfaturile apar doar în panoul ACTIV — nu câte o copie în fiecare panou
  const tipPane = !props.inSplit || !!props.activeInSplit
  useEffect(() => {
    if (!isLive) return
    let cancelled = false
    let timer = 0
    // Walkthrough-ul are prioritate: fie e deja marcat gata, fie nu e montat acum. Dacă e
    // deschis, reîncercăm scurt până se închide — poll mărginit, fără sleep fix (ar bloca e2e).
    const allowed = () => isWalkthroughDone() || !document.querySelector('[data-testid="walkthrough"]')
    const start = () => {
      if (cancelled) return
      if (!allowed()) { timer = window.setTimeout(start, 600); return }
      // paste întâi (doar pe hosturi cu transfer, adică agent); altfel direct toolbar
      if (canTransfer && !isTipDismissed(TIP_TERMINAL_PASTE)) setShowPasteTip(true)
      else if (!isTipDismissed(TIP_TOOLBAR)) setShowToolbarTip(true)
    }
    timer = window.setTimeout(start, 900)   // după ce terminalul s-a aşezat
    return () => { cancelled = true; clearTimeout(timer) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isLive])
  // paste închis → toolbar, scalonat (nu simultan); dacă toolbar-ul e deja văzut, nu mai apare
  const onPasteTipDismiss = () => {
    setShowPasteTip(false)
    if (!isTipDismissed(TIP_TOOLBAR)) window.setTimeout(() => setShowToolbarTip(true), 500)
  }

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
        api<{ url: string; writable: boolean; expires?: number }>(`/api/sessions/${session.id}/share`, {
          method: 'POST', body: JSON.stringify({ writable: shareWritable, expires_minutes: shareExpiry }),
        }))
      setShareUrl(r.url)
      setShareActive({ writable: r.writable, expires: r.expires })
      setShareOpen(false)
    } catch (e) {
      notifyError(t('session.shareLink'), errText(e, t) || t('session.shareLinkFailed'))
    }
  }

  async function revokeShare() {
    // Un clic omora instantaneu linkul, fără drum înapoi: cine îl are deschis vede pagina
    // de 403, iar linkul nu se poate reactiva — se generează altul. Era singura acţiune
    // distructivă din produs fără confirmare, deşi restul cer chiar şi pentru mai puţin.
    if (!(await confirm({
      title: t('session.revokeShareTitle'), message: t('session.confirmRevokeShare'),
      danger: true, confirmLabel: t('session.revoke'),
    }))) return
    // starea se curăţă DOAR la succes: înainte, un DELETE eşuat (step-up refuzat, reţea) ascundea
    // linkul din UI deşi rămânea VALID pe server — owner-ul credea că l-a revocat.
    try {
      await withStepup(session.host_id, () =>
        api(`/api/sessions/${session.id}/share`, { method: 'DELETE' }))
      setShareUrl(null)
      setShareActive(null)
    } catch (e) {
      notifyError(t('session.shareRevokeFailed'), errText(e, t))
    }
  }

  // owner scoate un invitat din sesiune — cu confirmare: un ✕ de 24px lângă rândul tău din
  // roster e uşor de nimerit greşit, iar celălalt pierde terminalul fără avertisment
  const kick = async (c: { id: string; label: string; ip?: string; agent?: string }) => {
    setShowRoster(false)
    const who = (c.label === 'self' ? t('session.roleSelf') : c.label === 'guest' ? t('session.roleGuest') : c.label)
      + (c.ip || c.agent ? ` (${[c.ip, c.agent ? shortAgent(c.agent) : ''].filter(Boolean).join(' · ')})` : '')
    if (!(await confirm({
      title: t('session.removeFromSession'), message: t('session.confirmKick', { who }),
      danger: true, confirmLabel: t('session.kick'),
    }))) return
    const ws = wsRef.current
    if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'kick', id: c.id }))
  }

  // „Sunt încă aici" din bannerul de pre-idle-lock (App): `hub.last_interaction` pe server se
  // împrospătează doar din INPUT-ul owner-ului sau din mesajul de control `{"type":"touch"}`
  // (api.py browser_ws → hub.touch) — prezenţă fără taste, pe acelaşi canal şi cu aceeaşi
  // încredere ca o tastă; un GET HTTP nu-l atinge. Un hub deja blocat nu se deblochează aşa.
  useEffect(() => {
    const onPing = () => {
      const ws = wsRef.current
      if (!isLive || locked || ws?.readyState !== WebSocket.OPEN) return
      ws.send(JSON.stringify({ type: 'touch' }))
    }
    window.addEventListener('wt-idle-ping', onPing)
    return () => window.removeEventListener('wt-idle-ping', onPing)
  }, [isLive, locked])

  /** starea liniei pentru ecoul strâns (lib/echo.ts): ecran, cursor absolut, linia tastată (OSC 133).
      null = nicio linie de shell citibilă (fără shell integration, comandă în curs, TUI) → ecou grosier,
      ca înainte: acolo guardrail-ul nu aşteaptă oricum ecoul (judgePeers: doar `atPrompt && !echoed`). */
  const lineKeyRef = useRef((): LineKey | null => {
    const term = termRef.current
    const tr = trackerRef.current
    if (!term || !tr || !tr.atPrompt()) return null
    const b = term.buffer.active
    // EXACT ce e pe ecran, cu spaţiul de la capăt: un spaţiu tastat la capăt de rafală trebuie să schimbe
    // linia, altfel ecoul se desincronizează până la următorul Enter (hotfix 3.6.17; vezi typedLine)
    const line = tr.typedLine() ?? ''
    const row = b.baseY + b.cursorY
    return { k: `${b.type}\u0000${row}\u0000${b.cursorX}\u0000${line}`, line }
  })
  /** ecoul ultimelor taste (vezi echoSettled): `requireOutput` la broadcast, nu într-un singur panou */
  const echoedNow = useCallback((requireOutput: boolean): boolean =>
    echoRef.current.echoed(requireOutput, performance.now(), rttRef.current, lineKeyRef.current()), [])
  /** inputul trimis spre terminal (fără rapoarte) — vezi InsertTarget.inputSeq (3.6.16) */
  const inputSeqRef = useRef(0)
  /** panoul e ţinta acţiunilor (tab activ; în split, panoul focalizat) — InsertTarget.isActive (3.6.16) */
  const actionTargetRef = useRef<boolean | undefined>(true)
  /** creşte la fiecare (re)activare a panoului — InsertTarget.activeEpoch (3.6.16, review L1) */
  const activeEpochRef = useRef(0)
  /** ultimul chunk plecat spre host (null după un raport de terminal: şi el consumă prefixul shell-ului).
      Un Escape singur = shell-ul aşteaptă a doua tastă a unei legături meta: `a` de după el e `ESC a`
      (zsh accept-and-hold), iar un Ctrl+U de golire are nevoie întâi de o tastă care stinge prefixul
      (re-review SV-01; vezi clearLineSeq) */
  const prevKeyRef = useRef<string | null>(null)
  /** `kind`: 'key' = tastă (urmărită pentru ecou), 'report' = raport de terminal (neurmărit),
      'auto' = clasificat după formă — DOAR pentru datele venite din alt panou prin broadcast (în
      panoul de origine le-a clasificat deja userInput). Textul inserat (snippet, paletă, „rulează din
      nou") e mereu 'key': un snippet în forma unui răspuns DCS nu sare urmărirea (review 3.6.13, L1). */
  const send = useCallback((data: string | Uint8Array, kind: 'key' | 'report' | 'auto' = 'key') => {
    if (muteRef.current || readOnlyRef.current) return
    const ws = wsRef.current
    if (ws?.readyState === WebSocket.OPEN) {
      ws.send(typeof data === 'string' ? new TextEncoder().encode(data) : data)
      // rapoartele terminalului (mouse, focus, CPR, DA…) nu sunt taste: nu aşteaptă ecou (review 3.6.13, M2)
      if (sendIsReport(kind, data, pastingRef.current, cprRef.current > 0)) { prevKeyRef.current = null; return }
      const prev = prevKeyRef.current
      prevKeyRef.current = typeof data === 'string' ? data : null
      inputSeqRef.current += 1     // input real: contextul unui paste de fişiere în curs s-a schimbat (3.6.16)
      // prima tastă de după B: promptul e pictat — rândul lui se verifică la Enter (review 3.6.13, H1)
      // fără taste în aşteptare (nimic tastat încă după B, niciun typeahead): linia începe la cursor
      trackerRef.current?.notePromptPainted(!echoRef.current.waiting)
      // un accept-line adevărat a plecat (CR / LF / Ctrl+O — nu `ESC a`, vezi acceptsLine): fără C,
      // rândurile următoare continuă comanda (PS2)
      if (typeof data === 'string' && acceptsLine(data)) trackerRef.current?.noteSubmitSent()
      // Enter, Ctrl+O, `ESC a` sau `a` după un Escape singur (SV-01): ecoul lui e orice schimbare a
      // liniei, închide tot ce era înaintea lui
      const a = sentArgs(data, prev)
      const { seq, needBase } = echoRef.current.sent(a.text, performance.now(), a.submit, a.raw)
      // referinţa liniei: după ce xterm a parsat tot ce sosise ÎNAINTE de trimitere (write gol, în ordine)
      if (needBase) termRef.current?.write('', () => echoRef.current.setBase(seq, lineKeyRef.current()))
      return
    }
    // socket închis/în reconectare: tasta NU pleacă (vezi droppedRef). O numărăm şi facem
    // cortina să „clipească" — feedback imediat că n-a ajuns nicăieri, nu tăcere.
    if (exitedRef.current) return
    inputSeqRef.current += 1       // tastă pierdută = tot o tastă: omul a continuat (3.6.16)
    droppedRef.current += 1
    setInputFlash(true)
    clearTimeout(flashTimerRef.current)
    flashTimerRef.current = setTimeout(() => setInputFlash(false), 250)
  }, [])
  // onUserData / peerCommands prin ref: handlerele terminalului sunt capturate la montare, iar un
  // panou trece din stiva keep-alive în split (şi înapoi) FĂRĂ remontare (3.6.12)
  const onUserDataRef = useRef(props.onUserData)
  onUserDataRef.current = props.onUserData
  const peerStatesRef = useRef(props.peerStates)
  peerStatesRef.current = props.peerStates
  const broadcastingRef = useRef(!!props.broadcasting)
  broadcastingRef.current = !!props.broadcasting
  /** difuzarea către CELELALTE panouri (App o ignoră fără broadcast). Un panou doar-vizualizare
      (sau în replay) nu trimite nimic nici local — deci nici în panourile vecine (review 3.6.12, L7).
      Audit 2026-10-17: rapoartele terminalului (mouse, focus, CPR, DA, X10) nu pleacă niciodată în
      celelalte panouri — sunt răspunsurile ACESTUI terminal (SV-02); iar o origine care nu poate
      trimite local (socket în reconectare, sesiune încheiată) nu difuzează nimic şi o spune — altfel
      tastele „netrimise" rulau în celelalte panouri, iar retastarea le rula a doua oară (SV-05). */
  const bcastHeldAtRef = useRef(-Infinity)
  const broadcastOut = useCallback((d: string | Uint8Array, kind: 'key' | 'report' = 'key') => {
    const dec = broadcastDecision(kind, {
      readOnly: readOnlyRef.current, muted: muteRef.current, exited: exitedRef.current,
      socketOpen: wsRef.current?.readyState === WebSocket.OPEN,
    })
    if (dec === 'broadcast') { onUserDataRef.current?.(session.id, d, 'key'); return }
    if ((dec === 'held-reconnecting' || dec === 'held-ended') && broadcastingRef.current) {
      // anunţul: o dată la câteva secunde, nu la fiecare tastă (cortina clipeşte oricum la fiecare)
      const now = performance.now()
      if (now - bcastHeldAtRef.current < 3000) return
      bcastHeldAtRef.current = now
      showInputNotice(tRef.current(dec === 'held-ended' ? 'session.broadcastHeldEnded' : 'session.broadcastHeldReconnecting'))
    }
  }, [session.id, showInputNotice])
  /** trimite LOCAL + (cu broadcast activ) către celelalte panouri — rezultatul guardrail-ului
      (golirea liniei / rularea confirmată) trebuie să ajungă în TOATE panourile-ţintă */
  const sendAll = useCallback((d: string) => {
    send(d)
    broadcastOut(d)
  }, [send, broadcastOut])

  // ── Enter-ul prin guardrail (local + toate panourile-ţintă la broadcast) ─────────────────
  // input reţinut cât aşteptăm ecoul panourilor-ţintă (≤ ECHO_GRACE_MS); null = nu aşteptăm.
  // INVARIANT: o singură buclă de aşteptare pe ref — orice cale care ar porni a doua (Enter, paste,
  // snippet, „Paste & run") intră în coadă cât una e activă (re-review 3.6.12, L-a)
  const submitWaitRef = useRef<(string | Uint8Array)[] | null>(null)
  const submitTimerRef = useRef(0)
  // keydown-ul Enter tocmai a trecut verificarea → `\r`-ul din onData care urmează e al lui
  const enterOkAtRef = useRef(-Infinity)
  // demontare în timpul aşteptării: timerul nu mai trimite nimic într-un panou dispărut
  useEffect(() => () => {
    clearTimeout(submitTimerRef.current)
    submitWaitRef.current = null
  }, [])
  /** Starea ACESTUI panou pentru guardrail-ul broadcast: citită de App pentru celelalte panouri şi
      de checkPeers pentru panoul de origine (care e şi el o ţintă — re-review 3.6.12, L-b). */
  const paneState = useCallback((): PeerState => {
    const ws = wsRef.current
    const tr = trackerRef.current
    return {
      // tastele nu pleacă deloc (doar-vizualizare, sesiune încheiată, socket închis, replay)
      inert: readOnlyRef.current || exitedRef.current || muteRef.current || ws?.readyState !== WebSocket.OPEN,
      // primeşte output live: fluxul nu e pe pauză şi nu rejucăm istoric
      live: streamActiveRef.current && !replayRef.current,
      atPrompt: tr?.atPrompt() === true,
      echoed: echoedNow(true),
      pending: tr?.pendingCommand() ?? null,
      pendingAlts: tr?.pendingVariants() ?? [],
      pendingBelow: tr?.pendingBelow() ?? [],
      // după un replay (ataşare / reconectare / reluare) linia unui shell cu integration e
      // necunoscută până la următorul prompt live (re-review 3.6.12, M1)
      known: tr ? tr.lineKnown() : true,
      id: session.id,
      label: paneLabelRef.current || session.id.slice(0, 8),
      // TAB într-un bracketed paste = text doar dacă shell-ul a cerut bracketed paste (3.6.13)
      // sub tmux modul nu e al panoului → TAB lipit = „nu pot verifica" (review hotfix 3.6.13, M1)
      bracketed: trustedBracketed(pasteUntrustedRef.current, termRef.current?.modes.bracketedPasteMode === true),
    }
  }, [session.id, echoedNow])
  /** regula atinsă: block → Ctrl+U în toate panourile-ţintă + mesaj; confirm → dialog. `below` = potrivirea
      e DOAR în textul de sub linia cursorului (judgeLocal / judgePeers o coboară la confirmare): dialogul
      spune asta, iar Anulează nu goleşte linia (textul de dedesubt poate să nu fie al ei). */
  /** Ctrl+U care goleşte linia şi când ultima tastă plecată a fost un Escape singur (Esc apoi Enter /
      `a`): shell-ul e în prefix meta, iar `ESC ^U` nu e legat nici în bash, nici în zsh (emacs) — îl
      consumă fără să golească (până acum linia rămânea). Primul ^U stinge prefixul, al doilea goleşte;
      `ESC ESC` n-ar merge: în bash e `complete` (re-review SV-01). */
  const clearLineSeq = useCallback(() => (prevKeyRef.current?.endsWith('\x1b') ? '\x15\x15' : '\x15'), [])
  const applyRule = (rule: CommandRule, cmd: string, run?: string, hits?: RuleHit[], recheck?: () => PeerVerdict, below = false, submit?: string) => {
    const onlyBelow = hits?.length ? hits.every((h) => h.below) : below
    if (rule.action === 'block' && !onlyBelow) {
      if (!run) sendAll(clearLineSeq())   // un text reţinut n-a fost tastat: nu e nimic de şters
      setGuardMsg(tRef.current('session.blockedByGuardrail', { cmd: cmd.slice(0, 70), pattern: rule.pattern }))
      window.setTimeout(() => setGuardMsg((m) => (m && m.includes(cmd.slice(0, 70)) ? null : m)), 4000)
    } else {
      setCmdConfirm({ cmd, pattern: rule.pattern, run, submit, hits, recheck, below: onlyBelow })
    }
  }
  /** Panourile-ţintă ale unui broadcast (inclusiv originea): true = trimite acum; false = reţinut
      (regulă / dialog „nu pot verifica" / aşteptăm ecoul — atunci `onOk` rulează singur dacă
      verificarea trece). Apelantul a verificat deja că NU e o aşteptare în curs. */
  const checkPeers = (lineOf: ((p: string | null) => string | null) | undefined, onOk: () => void,
    originCmd: string, run?: string, extra: string[] = [], opaque = false, submit?: string): boolean => {
    const verdict = (final: boolean) =>
      judgePeers([paneState(), ...(peerStatesRef.current?.(session.id) ?? [])], commandGuardRef.current, final, lineOf, extra, opaque)
    const recheck = () => verdict(true)
    const settle = (v: PeerVerdict, queued: (string | Uint8Array)[] = []) => {
      if (v.kind === 'rule') applyRule(v.rule, v.cmd, run, v.hits, recheck, false, submit)
      else if (v.kind === 'unknown') setCmdConfirm({ cmd: originCmd, pattern: '', unknown: true, run, submit, hits: v.hits, recheck, unreadable: v.unreadable, opaque })
      noticeQueued(queued)
    }
    return waitVerdict(verdict, onOk, settle)
  }
  /** Bucla de aşteptare a ecoului (≤ ECHO_GRACE_MS), comună broadcast-ului şi panoului singur (3.6.13):
      true = verdict ok imediat (apelantul trimite); false = reţinut — `onOk` rulează singur dacă
      verificarea trece, altfel `settle` (dialog / blocare), cu tastele din coadă anunţate. */
  const waitVerdict = <V extends { kind: string }>(verdict: (final: boolean) => V, onOk: () => void,
    settle: (v: V, queued?: (string | Uint8Array)[]) => void): boolean => {
    const v = verdict(false)
    if (v.kind === 'ok') return true
    if (v.kind !== 'wait') { settle(v); return false }
    submitWaitRef.current = []
    const t0 = performance.now()
    const tick = () => {
      submitTimerRef.current = 0
      if (!submitWaitRef.current) return   // demontat între timp
      const v2 = verdict(performance.now() - t0 >= ECHO_GRACE_MS)
      if (v2.kind === 'wait') { submitTimerRef.current = window.setTimeout(tick, 15); return }
      const queued = submitWaitRef.current
      submitWaitRef.current = null
      if (v2.kind === 'ok') {
        onOk()
        for (const q of queued) ioRef.current.userInput(q)   // în ordine; un Enter din coadă e re-verificat
      } else settle(v2, queued)
    }
    submitTimerRef.current = window.setTimeout(tick, 15)
    return false
  }
  /** tastele de după Enter, reţinute cât aşteptam, nu mai pleacă orbeşte — dar nici în tăcere */
  const noticeQueued = (queued: (string | Uint8Array)[]) => {
    if (!queued.length) return
    showInputNotice(tRef.current('session.queuedNotSent', { count: queued.length }))
  }
  /** Enter / chunk FĂRĂ broadcast, cu guardrail activ (3.6.13): aceeaşi aşteptare a ecoului ca la
      broadcast — Ctrl+P / ↑ + Enter rapid nu mai trimite o linie nevăzută (vezi judgeLocal).
      `lineOf` / `extra` ca la checkPeers. Trimiterea reţinută pleacă DOAR local (ca dialogul fără
      broadcast, F2: dacă broadcast-ul porneşte cât aşteptăm, linia n-a fost verificată în rest). */
  const checkLocal = (run: string, lineOf: (p: string | null) => string | null = (p) => p, extra: string[] = [], submit = false): boolean => {
    const verdict = (final: boolean) => {
      const tr = trackerRef.current
      return judgeLocal({
        atPrompt: tr?.atPrompt() === true,
        echoed: echoedNow(false),
        pending: tr?.pendingCommand() ?? null,
        pendingAlts: tr?.pendingVariants() ?? [],
        pendingBelow: tr?.pendingBelow() ?? [],
        unechoed: echoRef.current.unechoed(),
        lineLost: tr?.promptLost === true,
      }, commandGuardRef.current, final, lineOf, extra)
    }
    const settle = (v: LocalVerdict, queued: (string | Uint8Array)[] = []) => {
      // tastă de trimitere (Enter / Ctrl+O / ESC a): linia E tastată (block → Ctrl+U o şterge; „Rulează"
      // trimite tasta originală); altfel `run` e un chunk reţinut, netastat
      const held = submit ? undefined : run
      const key = submit ? run : undefined
      if (v.kind === 'rule') applyRule(v.rule, v.cmd, held, undefined, undefined, v.below === true, key)
      else if (v.kind === 'unknown') {
        // „Rulează" re-judecă linia ACUM (review 3.6.13, L4): între timp ecoul a sosit, iar o regulă
        // care atinge linia devenită vizibilă nu trebuie ocolită
        setCmdConfirm({ cmd: (lineOf(trackerRef.current?.pendingCommand() ?? null) ?? '').trim(), pattern: '', unknown: true, run: held, submit: key, echo: true, localRecheck: () => verdict(true) })
        // diagnoză (fără conţinutul tastelor): de ce linia n-a fost confirmată
        console.warn('[wt-echo] ' + JSON.stringify({ now: Math.round(performance.now()), rtt: rttRef.current,
          lost: trackerRef.current?.promptLostReason() ?? null, ...echoRef.current.debug() }))
      }
      noticeQueued(queued)
    }
    return waitVerdict(verdict, () => send(run), settle)
  }
  /** O tastă de trimitere (isSubmitKey: Enter CR/LF, Ctrl+O `\x0f`, `ESC a`, sau `a` după un Escape
      singur — SV-01): comanda tastată aici + (broadcast) în fiecare panou-ţintă. true = poate pleca.
      Cât o verificare aşteaptă ecoul, Enter-ul intră în coadă (re-verificat la rând), nu porneşte
      a doua buclă (re-review 3.6.12, L-a). Reţinută, „Rulează" trimite exact tasta `seq`. */
  const checkSubmit = (seq: string): boolean => {
    if (submitWaitRef.current) { submitWaitRef.current.push(seq); return false }
    const bc = broadcastingRef.current && !readOnlyRef.current
    // un singur panou: linia se citeşte DUPĂ ecoul ultimelor taste (3.6.13), ca la broadcast
    if (!bc) return checkLocal(seq, undefined, [], true)
    const cmd = trackerRef.current?.pendingCommand() ?? null
    const rule = cmd ? matchCommandRule(cmd, commandGuardRef.current) : null
    // broadcast: doar un BLOCK local scurtcircuitează; un confirm local trece prin judgePeers (originea
    // e şi ea ţintă), ca dialogul să nu ascundă un block / o linie neverificabilă din alt panou
    if (rule && cmd && rule.action === 'block') { applyRule(rule, cmd, undefined, undefined, undefined, false, seq); return false }
    return checkPeers(undefined, () => sendAll(seq), cmd ?? '', undefined, [], false, seq)
  }
  /** Un chunk de input care conţine Enter-uri dar NU e un Enter gol: commit IME („ls\r"), paste,
      Alt+Enter. Fiecare linie trece prin guardrail — prima lipită de ce e deja tastat — aici şi, la
      broadcast, în fiecare panou (prima linie lipită de linia LUI). Un chunk reţinut nu e tastat
      deloc; „Rulează" din dialog îl trimite întreg (re-review 3.6.12, L-d). true = poate pleca. */
  /** bracketed paste cerut de shell aici şi (la broadcast) în toate panourile-ţintă (vezi opaqueInput) */
  const allBracketed = (bc: boolean): boolean => paneState().bracketed === true
    && (!bc || (peerStatesRef.current?.(session.id) ?? []).every((p) => p.inert || p.bracketed === true))
  const submitChunk = (d: string): boolean => {
    // fără caractere de control: Alt+Enter (`\x1b\r`) = Enter pe linia curentă (review final 3.6.12, L)
    const lines = splitLines(unbracket(d)).map(stripControls)
    const cur = trackerRef.current?.pendingCommand() ?? ''
    const checked = [cur + lines[0], ...lines.slice(1)]
    const bc = broadcastingRef.current && !readOnlyRef.current
    // taste de editare în chunk (Ctrl+U, DEL, ESC-. …, TAB în afara unui bracketed paste — 3.6.13):
    // linia rulată nu e cea verificată → „nu pot verifica", aici şi la broadcast (verificare 3.6.12,
    // F4; un block cunoscut câştigă totuşi). TAB-ul dintr-un paste e text doar dacă TOATE panourile-
    // ţintă au cerut bracketed paste.
    const opaque = opaqueInput(d, allBracketed(bc)) && guardActive(commandGuardRef.current)
    for (const raw of checked) {
      const line = raw.trim()
      const rule = line ? matchCommandRule(line, commandGuardRef.current) : null
      // broadcast: doar un BLOCK scurtcircuitează (vezi checkSubmit); confirmările le adună judgePeers
      if (rule && (!bc || rule.action === 'block')) { applyRule(rule, line, d); return false }
    }
    if (!bc) {
      if (opaque) { setCmdConfirm({ cmd: (cur + lines[0]).trim(), pattern: '', unknown: true, run: d, opaque: true }); return false }
      // fără broadcast: aceeaşi aşteptare a ecoului ca un Enter (3.6.13)
      return checkLocal(d, (p) => ((p ?? '') + lines[0]) || null, lines.slice(1))
    }
    return checkPeers((p) => ((p ?? '') + lines[0]) || null, () => sendAll(d), cur + lines[0], d, lines.slice(1), opaque)
  }
  /** Input-ul utilizatorului (tastatură via onData, keybar, rejucarea celui reţinut): local +
      broadcast. Un Enter „gol" care NU a trecut prin keydown (IME pe mobil, keybar) trece şi el
      prin guardrail (review 3.6.12, L6), la fel un chunk cu Enter în el (re-review, L-d) — şi un
      Ctrl+O (`\x0f`, audit 2026-10-17 SV-01): bash/zsh execută linia cu el exact ca la Enter; la fel
      `a` / `A` imediat după un Escape trimis singur (zsh: tot `ESC a`, accept-and-hold — Esc de pe
      tastatură sau de pe keybar, apoi litera; re-review SV-01). */
  const userInput = (d: string | Uint8Array, report = false) => {
    // rapoartele terminalului (mouse, focus, CPR…) nu sunt taste: nu aşteaptă în coada unei verificări
    // şi nu aşteaptă ecou (review 3.6.13, M2). DAR clasificarea nu ocoleşte niciodată guardrail-ul
    // (HIGH-1): un chunk care conţine CR/LF trece mereu pe calea normală, iar datele unui paste nu
    // sunt niciodată rapoarte (un text lipit poate avea exact forma unui răspuns OSC)
    if (reportOnly(d, report, pastingRef.current, cprRef.current > 0)) {
      if (typeof d === 'string') cprRef.current = Math.max(0, cprRef.current - countCprReplies(d))
      send(d, 'report')
      broadcastOut(d, 'report')   // panourile-ţintă primesc clasificarea originii (review 3.6.13, L-a)
      return
    }
    if (submitWaitRef.current) { submitWaitRef.current.push(d); return }
    if (typeof d === 'string' && isSubmitKey(d, prevKeyRef.current)) {
      const checked = performance.now() - enterOkAtRef.current < 250
      enterOkAtRef.current = -Infinity
      if (!checked && !checkSubmit(d)) return
    } else {
      // o tastă verificată la keydown e urmată IMEDIAT de byte-ul ei (xterm emite sincron): orice
      // altceva stinge fereastra, ca un Enter de mai târziu să nu treacă pe „bonul" ei (re-review
      // SV-01: pe alt layout, keydown-ul poate verifica un Ctrl+O pe care xterm îl trimite ca altă tastă)
      enterOkAtRef.current = -Infinity
      if (typeof d === 'string' && submitsLine(d) && !submitChunk(d)) return
    }
    send(d)
    broadcastOut(d)
  }
  /** Text inserat (snippet, „rulează din nou", inserare din paletă): local + broadcast, iar dacă
      conţine Enter-uri, fiecare linie (prima lipită de ce e deja tastat) trece prin guardrail —
      în panoul ăsta şi, la broadcast, în fiecare panou-ţintă. Un text reţinut nu e tastat deloc. */
  const typeText = (body: string) => {
    if (submitWaitRef.current) { submitWaitRef.current.push(body); return }
    // un text inserat care e exact `a` / `A` imediat după un Escape plecat singur încheie un `ESC a`
    // (zsh accept-and-hold): aceeaşi cale ca tasta (re-review SV-01)
    if (metaAccept(prevKeyRef.current, body)) { userInput(body); return }
    if (submitsLine(body)) {
      const cur = trackerRef.current?.pendingCommand() ?? ''
      const lines = splitLines(body)
      const hit = guardedLine([cur + lines[0], ...lines.slice(1)].join('\n'))
      if (hit) {
        setGuardMsg(tRef.current('session.insertGuarded', { cmd: hit.line.slice(0, 70), pattern: hit.pattern }))
        window.setTimeout(() => setGuardMsg(null), 5000)
        return
      }
      // review 3.6.13 (L5): aceleaşi verificări ca un chunk tastat — TAB / taste de editare (textul e
      // trimis ca atare, fără bracketed paste, deci TAB-ul e completare) şi aşteptarea ecoului
      const bc = broadcastingRef.current && !readOnlyRef.current
      const opaque = opaqueInput(body, false) && guardActive(commandGuardRef.current)
      const lineOf = (p: string | null) => ((p ?? '') + lines[0]) || null
      if (!bc) {
        if (opaque) { setCmdConfirm({ cmd: (cur + lines[0]).trim(), pattern: '', unknown: true, run: body, opaque: true }); return }
        if (!checkLocal(body, lineOf, lines.slice(1))) return
      } else if (!checkPeers(lineOf, () => sendAll(body), cur + lines[0], body, lines.slice(1), opaque)) return
    }
    send(body)
    broadcastOut(body)
  }
  // handlerele terminalului sunt capturate la montare → citesc funcţiile curente prin ref
  const ioRef = useRef({ checkSubmit, userInput, typeText })
  ioRef.current = { checkSubmit, userInput, typeText }

  // Guardrail, Escape = anulează (şterge linia), prins la nivel de document în CAPTURE: nu ajunge
  // nici la xterm, nici la scurtăturile globale. Enter nu poate scăpa — focusul e pe buton (vezi
  // cmdCancelBtnRef), nu în textarea. Stă DUPĂ `send` (const → TDZ în lista de dependenţe).
  // Audit 2026-10-17 (SV-04): dialogul stă ÎN panou, iar celelalte panouri ale split-ului rămân
  // interactive — deci Escape-ul e al nostru DOAR cu focusul în dialog sau în panoul ăsta (escapeScope);
  // un Escape din vim-ul din B nu mai închide dialogul lui A şi nu mai trimite Ctrl+U peste tot, iar cu
  // două dialoguri deschise se închide doar cel cu focusul. Ctrl+U („Cancel & clear") pleacă doar când
  // focusul era în dialog (escapeClears): dintr-un alt loc al panoului un dialog de broadcast se
  // închide fără să golească linii pe care omul nu le privea.
  // aria-modal e onorat ÎN panou: Tab / Shift+Tab circulă doar între butoanele dialogului (capcana
  // globală useFocusTrap ar trage focusul şi din celelalte panouri şi ar asculta Escape pe tot
  // documentul — exact ce corectăm aici). `actionTargetRef` = panoul-ţintă al acţiunilor (3.6.16).
  useEffect(() => {
    if (!cmdConfirm) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Tab') {
        const el = cmdDialogRef.current
        if (!el || !el.contains(document.activeElement)) return
        const f = Array.from(el.querySelectorAll<HTMLElement>('button:not([disabled])'))
        if (f.length === 0) { e.preventDefault(); return }
        const first = f[0]
        const last = f[f.length - 1]
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus() }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus() }
        return
      }
      if (e.key !== 'Escape') return
      const scope = escapeScope(document.activeElement, document.body, cmdDialogRef.current, rootRef.current, !!actionTargetRef.current)
      if (scope === 'none') return
      e.preventDefault(); e.stopPropagation()
      // „nu pot verifica" / snippet reţinut: linia rămâne de editat; regulă pe linia tastată: o golim
      // (doar local dacă dialogul s-a deschis fără broadcast — F2)
      if (!cmdConfirm.unknown && !cmdConfirm.run && !cmdConfirm.below && escapeClears(scope, !!cmdConfirm.recheck)) {
        (cmdConfirm.recheck ? sendAll : send)(clearLineSeq())
      }
      setCmdConfirm(null); termRef.current?.focus()
    }
    document.addEventListener('keydown', onKey, true)
    return () => document.removeEventListener('keydown', onKey, true)
  }, [cmdConfirm, sendAll, send, clearLineSeq])

  // broadcast: înregistrează `send`-ul acestui panou în harta din App (sid → send), ca tastele
  // dintr-un panou să poată fi difuzate în toate. `send` e stabil (useCallback []), deci se
  // înregistrează o dată şi se curăţă la demontare.
  const registerSend = props.registerSend
  const bcastSid = session.id
  useEffect(() => {
    registerSend?.(bcastSid, { send, state: paneState })
    return () => registerSend?.(bcastSid, null)
  }, [registerSend, bcastSid, send, paneState])

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
  // fit() DEFENSIV — guard unic pentru TOATE apelurile. Pe un terminal demontat/în teardown (ex.
  // tranziţia split↔tab, unde un panou se demontează cât un reattach/replay async încă apelează
  // fit), FitAddon citeşte `_renderService.dimensions` şi aruncă `undefined (reading 'dimensions')`.
  // isConnected prinde demontarea; try/catch prinde rendererul nepregătit. Următorul fit real corectează.
  const safeFit = useCallback((): boolean => {
    const term = termRef.current
    const fit = fitRef.current
    if (!term || !fit || !term.element?.isConnected) return false
    try { fit.fit(); return true } catch { return false }
  }, [])
  const refit = useCallback((active = false) => {
    const term = termRef.current
    if (!term) return
    const before = term.rows * 100000 + term.cols
    if (!safeFit()) return
    if (active || term.rows * 100000 + term.cols !== before) sendResize(active)
    // forțează un repaint chiar dacă dimensiunea n-a schimbat: după un upgrade de
    // agent (reconectare în masă), tab-urile din fundal pot rămâne cu un render
    // „stricat" deși dimensiunea e corectă — fit()-ul singur (no-op) nu-l curăță.
    // refresh redesenează bufferul curent, exact ce făcea A−/A+ prin schimbarea fontului.
    try { term.refresh(0, term.rows - 1) } catch { /* teardown */ }
  }, [sendResize])

  // Auto-recuperare a desincronizării de dimensiune xterm↔container: la revenirea
  // pe terminal (focus fereastră, tab redevine vizibil, pane redevine activ) forțăm
  // un re-fit. Fără asta, dacă xterm rămâne la o dimensiune veche (ex. fereastra
  // s-a redimensionat cât eram pe alt tab/app), TUI-urile (Claude Code) se strică
  // și doar A−/A+ manual repara. ResizeObserver-ul prinde doar schimbările de
  // container, nu și cazul „am revenit și xterm-ul e la altă dimensiune".
  // 3.6.12: VIZIBIL ≠ FOCALIZAT. Într-un split toate panourile se văd, dar doar unul e focalizat:
  // cele nefocalizate tot trebuie să-şi recreeze rendererul la revenirea tabului (altfel rămâneau
  // albe), doar că se re-potrivesc PASIV (nu reclamă dimensiunea la fiecare focus de fereastră).
  const paneVisible = props.paneVisible ?? props.paneActive
  const paneFocused = props.paneActive !== false
  useEffect(() => {
    if (paneVisible === false) return
    const activate = () => refit(paneFocused)  // focalizat: devenim dispozitivul activ → reclamăm dimensiunea
    // preferinţa de renderer s-a schimbat cât panoul era ascuns: o aplicăm acum (nu creăm WebGL în display:none)
    if (readRendererPref() !== appliedRendererRef.current) reloadRendererRef.current?.()
    activate()                                // la (re)activarea pane-ului
    // Tab revenit vizibil: recreează rendererul WebGL. Browserul poate elibera contextul GPU
    // al unui tab din fundal (fără a emite mereu `contextlost`) → la revenire ecranul e ALB deşi
    // bufferul xterm are tot textul; `refresh()` nu ajută (contextul GL e mort). Reload-ul îl
    // recreează şi repaintează din buffer — cauza „b" din analiza de resync (renderer, nu date).
    const onVis = () => { if (!document.hidden) { reloadRendererRef.current?.(); activate() } }
    // Preferinţa de renderer schimbată din Setări: reîncărcăm pe loc (dispose + addon-ul ales)
    const onRenderer = () => reloadRendererRef.current?.()
    window.addEventListener('wt-renderer', onRenderer)
    const onFocus = () => { if (paneFocused) activate() }
    window.addEventListener('focus', onFocus)
    document.addEventListener('visibilitychange', onVis)
    return () => {
      window.removeEventListener('focus', onFocus)
      document.removeEventListener('visibilitychange', onVis)
      window.removeEventListener('wt-renderer', onRenderer)
    }
  }, [paneVisible, paneFocused, refit])

  // focus cerut explicit (intrarea într-un split, Alt+←/→ între panouri): terminalul existent
  // primeşte tastatura; unul abia montat o primeşte la creare (paneActive)
  useEffect(() => {
    if (props.focusNonce && props.paneActive) termRef.current?.focus()
  }, [props.focusNonce]) // eslint-disable-line react-hooks/exhaustive-deps
  // split montat / formă schimbată / divider eliberat: TOATE panourile vizibile reclamă dimensiunea
  // (active=true). Altfel serverul putea ignora resize-ul pasiv al unui panou nefocalizat, iar
  // PTY-ul rămânea la dimensiunea altui client (telefonul) — panoul arăta tăiat.
  useEffect(() => {
    if (!props.layoutNonce || paneVisible === false) return
    const id = requestAnimationFrame(() => refit(true))
    return () => cancelAnimationFrame(id)
  }, [props.layoutNonce]) // eslint-disable-line react-hooks/exhaustive-deps

  // acțiunile de sesiune venite din scurtături / paletă (App emite, panoul
  // ACTIV răspunde — altfel toate tab-urile montate ar reacționa deodată). În split,
  // ținta e panoul FOCUSAT (actionTarget), nu ambele — un snippet trebuie să meargă
  // pe un singur host. Fallback la paneActive dacă prop-ul nu e pasat.
  const isActionTarget = props.actionTarget ?? props.paneActive
  // (re)activare: epoca nouă — un paste făcut înainte de „plecat şi revenit" nu mai e al contextului de acum
  if (isActionTarget !== false && actionTargetRef.current === false) activeEpochRef.current += 1
  actionTargetRef.current = isActionTarget
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
      ioRef.current.typeText((e as CustomEvent<string>).detail)   // guardrail + broadcast (L6)
      termRef.current?.focus()
    }
    // Alt+E (3.6.14): deschide / închide panoul de fişiere — doar pe un host cu panou de fişiere
    const onFiles = () => { if (props.host) toggleFiles() }
    window.addEventListener('wt-session-search', onSearch)
    window.addEventListener('wt-session-snippets', onSnippets)
    window.addEventListener('wt-session-font', onFont)
    window.addEventListener('wt-session-insert', onInsert)
    window.addEventListener('wt-session-files', onFiles)
    return () => {
      window.removeEventListener('wt-session-files', onFiles)
      window.removeEventListener('wt-session-search', onSearch)
      window.removeEventListener('wt-session-snippets', onSnippets)
      window.removeEventListener('wt-session-font', onFont)
      window.removeEventListener('wt-session-insert', onInsert)
    }
  }, [isActionTarget, send]) // eslint-disable-line react-hooks/exhaustive-deps -- toggleFiles/props.host: doar setteri de stare + hostul sesiunii (fix)

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
    tracker.tmuxBacked = props.host?.backend === 'tmux'
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
      // istoricul rejucat nu e activitate live — dar dovedeşte shell integration: după replay,
      // „nu e la prompt" = linie necunoscută, nu „fără integration" (re-review 3.6.12, M1)
      if (!replayRef.current) tracker.handle(data)
      else tracker.noteReplayedMark(data)
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
      // ISTORICUL rejucat NU e o acțiune live (la fel ca marcajele OSC 133 de mai sus): la
      // resync-ul de schimbare de tab, transcriptul poate conține un OSC 52 VECHI (o selecție
      // anterioară). Rejucat, el ar suprascrie clipboardul cu valoarea veche — exact simptomul
      // „între taburi rămâne valoarea veche în loc de cea nouă". Iar poarta de input de mai jos
      // NU-l prinde: schimbarea tabului e ea însăși input proaspăt, deci fereastra de 10s e
      // deschisă fix când se rejoacă istoricul. Îl ignorăm cât scriem replay-ul.
      if (replayRef.current) return true
      // Doar ca urmare a unei acțiuni recente a operatorului (selecție cu mouse-ul
      // / tastare). Fără poarta asta, orice output al hostului (`cat` la un fișier
      // ostil, un program compromis) poate suprascrie clipboardul cu, de ex.,
      // `curl evil|sh\n` și aștepta un paste. Plus un plafon de dimensiune.
      if (Date.now() - lastInputRef.current > 10000) return true
      if (payload.length > 200000) return true
      try {
        const bytes = Uint8Array.from(atob(payload), (ch) => ch.charCodeAt(0))
        copySession(session.id, new TextDecoder().decode(bytes))
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
    // ţintă pentru „insert path" (motorul de upload tastează calea aici după commit)
    // false = n-am tastat (doar-citire / mut / socket închis): apelantul oferă „Copy" în loc
    // Tastăm doar ca bracketed paste, când programul din prim-plan l-a cerut (shell/readline) —
    // altfel literele ar fi comenzi în mc/vim/less/htop (lib/transfers.ts typeIntoOutcome).
    registerInsertTarget(session.id, {
      send: (text) => {
        if (muteRef.current || readOnlyRef.current || wsRef.current?.readyState !== WebSocket.OPEN) return false
        // guardrail în aşteptare (ecou / dialog): o cale tastată acum ar ocoli reţinerea (review hotfix 3.6.13, L2)
        if (submitWaitRef.current || cmdConfirmOpenRef.current) return false
        send(text)
        // focusul trece în terminal DOAR dacă omul nu scrie în alt câmp al paginii (căutare, filtru,
        // redenumire, paletă) — altfel Enter-ul lui ar pleca în promptul programului (review M1)
        if (!typingElsewhere(term.textarea)) term.focus()
        return true
      },
      bracketedPaste: () => term.modes.bracketedPasteMode === true,
      viaTmux: () => pasteUntrustedRef.current,
      canType: () => !readOnlyRef.current && !muteRef.current,
      // sub tmux DECSET 2004 nu ajunge la xterm; marcajele OSC 133 ale shell-ului da
      atPrompt: () => !replayRef.current && trackerRef.current?.atPrompt() === true,
      hasFocus: () => !!term.textarea && document.activeElement === term.textarea,
      altScreen: () => term.buffer.active.type === 'alternate',
      commandRunning: () => trackerRef.current?.running === true,
      // shell integration văzută (OSC 133): sub tmux e singura citire care dovedeşte „acelaşi prompt";
      // fără ea fereastra de paste e cea scurtă (audit P1, FS-03 — lib/transfers.ts modesBlind)
      shellIntegration: () => trackerRef.current?.integrated === true,
      // contextul unui paste/drop de fişiere (3.6.16, lib/transfers.ts typeIntoPasted)
      inputSeq: () => inputSeqRef.current,
      isActive: () => actionTargetRef.current !== false && !replayRef.current,
      activeEpoch: () => activeEpochRef.current,
      keyboardHere: () => {
        const a = document.activeElement
        return !a || a === document.body || (!!term.textarea && a === term.textarea)
      },
    })
    // Paste cu FIŞIERE (captură, înaintea handler-ului xterm de pe textarea): preluăm doar când
    // clipboardul aduce fişiere/imagini; textul simplu nu trece pe aici — xterm îl lipeşte ca
    // până acum (bracketed paste) — cu excepţia unui text multi-linie care atinge guardrail-ul.
    const onPasteFiles = (e: ClipboardEvent) => {
      // datele pe care xterm le emite din acest paste (sincron, din handler-ul lui de pe textarea)
      // nu sunt rapoarte de terminal, oricum ar arăta (review 3.6.13, HIGH-1)
      pastingRef.current = true
      window.setTimeout(() => { pastingRef.current = false }, 0)
      const cd = e.clipboardData
      if (!cd) return
      // fişierele merg doar prin agent; guardrail-ul pe textul lipit se aplică oriunde
      const files = canTransferRef.current ? Array.from(cd.files) : []
      if (!files.length && canTransferRef.current) {
        for (const it of Array.from(cd.items)) {
          if (it.kind === 'file') { const f = it.getAsFile(); if (f) files.push(f) }
        }
      }
      if (!files.length) {
        // Text cu mai multe linii: fără bracketed paste în shell, fiecare linie se EXECUTĂ la lipire,
        // ocolind verificarea de la Enter. Dacă vreo linie atinge o regulă, nu lipim deloc.
        const text = cd.getData('text/plain')
        // CR singur („cmd\r") execută şi el, ca LF (review 3.6.12, L6)
        const hit = submitsLine(text) ? guardedLine(text) : null
        if (hit) {
          e.preventDefault()
          e.stopPropagation()
          setGuardMsg(tRef.current('session.pasteGuarded', { cmd: hit.line.slice(0, 70), pattern: hit.pattern }))
          window.setTimeout(() => setGuardMsg(null), 5000)
        }
        return
      }
      e.preventDefault()
      e.stopPropagation()
      void pasteFilesRef.current(files)
    }
    containerRef.current!.addEventListener('paste', onPasteFiles, true)

    const onData = term.onData((d) => {
      lastInputRef.current = Date.now()
      // local + broadcast (App difuzează către CELELALTE panouri din grilă; fără broadcast
      // activ, App ignoră). Un Enter fără keydown (IME mobil) trece şi el prin guardrail.
      ioRef.current.userInput(d)
    })
    const onBinary = term.onBinary((d) => {
      const bytes = new Uint8Array(d.length)
      for (let i = 0; i < d.length; i++) bytes[i] = d.charCodeAt(i) & 0xff
      ioRef.current.userInput(bytes, true)   // xterm emite binar doar rapoarte de mouse X10
    })
    // mouse-selection copy (tmux → OSC 52) is a pointer gesture; count it too
    const markInput = () => {
      lastInputRef.current = Date.now()
      // click pe acest dispozitiv = e cel activ → reclamă dimensiunea PTY dacă un
      // alt client (ex. telefonul) ne-a micșorat. Fără asta, dacă fereastra n-a
      // pierdut focus-ul în browser nu se declanșează niciun re-fit și rămâi mic
      // până la A−/A+. `fit` e idempotent, iar serverul deduplică dacă e deja corectă.
      safeFit()
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
    // Enter-ul ţinut de guardrail (keydown → false): xterm ar emite totuşi '\r' din keypress-ul care
    // urmează (Terminal._keyPress nu ştie că keydown-ul a fost refuzat), adică un AL DOILEA Enter —
    // după aşteptarea ecoului ar fi plecat şi el, sau ar fi cerut un dialog nou (e2e 3.6.13)
    let heldEnter = false
    term.attachCustomKeyEventHandler((e) => {
      if (e.type === 'keypress' && heldEnter && (e.charCode === 13 || e.charCode === 10 || e.key === 'Enter')) {
        heldEnter = false
        return false
      }
      // litera LOGICĂ (e.key), nu tasta fizică (e.code): xterm derivă byte-ul din keyCode-ul
      // layout-ului, deci pe Dvorak tasta fizică „O" e Ctrl+R pentru shell (re-review SV-01)
      const letter = e.key.length === 1 ? e.key.toLowerCase() : ''
      if (e.type === 'keyup' && (e.key === 'Enter' || letter === 'j' || letter === 'o' || letter === 'a')) heldEnter = false
      if (e.type !== 'keydown') return true
      heldEnter = false
      // Guardrail de comenzi: la Enter, verificăm comanda TASTATĂ (via OSC 133) ÎNAINTE s-o
      // trimitem. block → curăță linia; confirm → dialog. Fără shell integration (promptRow
      // lipsă) sau într-un TUI, pendingCommand e null → trece. Shift/Ctrl+Enter şi Ctrl+J
      // execută şi ele linia în shell (CR / LF) — scăpau verificării până în 3.5.2. Ctrl+O
      // (`\x0f`: bash `operate-and-get-next`, zsh `accept-line-and-down-history`) o execută şi el
      // — scăpa până la auditul 2026-10-17 (SV-01); trece prin EXACT aceeaşi verificare. La fel
      // Alt+A / Alt+Shift+A (`ESC a` / `ESC A`: zsh `accept-and-hold` execută linia şi o păstrează;
      // re-review SV-01). Pe Mac fără macOptionIsMeta, Option+A tastează „å" (e.key) şi xterm nu
      // emite ESC a — nu se potriveşte, corect.
      const ctrlOnly = e.ctrlKey && !e.shiftKey && !e.altKey && !e.metaKey
      const altOnly = e.altKey && !e.ctrlKey && !e.metaKey
      const submitSeq = e.key === 'Enter' && !e.altKey && !e.metaKey ? '\r'
        : ctrlOnly && letter === 'j' ? '\n'
        : ctrlOnly && letter === 'o' ? CTRL_O
        : altOnly && letter === 'a' ? ACCEPT_AND_HOLD[e.shiftKey ? 1 : 0]
        : null
      // Broadcast: Enter-ul pleacă în TOATE panourile, deci se verifică linia din fiecare —
      // istoricul / completarea pot face ca acelaşi text tastat să fie altă comandă în alt shell;
      // un panou-ţintă pe pauză sau fără ecou încă cere confirmare (lib/broadcastGuard, 3.6.12).
      // Cât aşteptăm ecoul, Enter-ul următor intră în coadă (onData), nu se verifică de două ori.
      if (submitSeq !== null && !submitWaitRef.current) {
        if (!ioRef.current.checkSubmit(submitSeq)) {
          heldEnter = true
          // xterm nu mai vede tasta (handler → false), deci nu o anulează el: un Ctrl+O reţinut ar
          // deschide dialogul „Open file" al browserului, un Ctrl+J panoul de descărcări (Chrome);
          // pentru Enter e inofensiv
          e.preventDefault()
          return false   // NU trimite Enter la host
        }
        enterOkAtRef.current = performance.now()
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
        copySession(session.id, sel).then(flashCopied)
        term.clearSelection()
        return false
      }
      // Cmd/Ctrl+Shift+V: paste picker din history-ul GLOBAL (toate terminalele). Cmd+V simplu rămâne
      // paste normal (nu-l interceptăm — lipirea a ceva copiat din alt app trebuie să meargă).
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'v' || e.key === 'V')) {
        openPastePicker()
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
        copySession(session.id, sel).then(flashCopied)
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

    // debounce ~100 ms: un drag de divider / o schimbare de formă schimbă containerul la fiecare
    // cadru; fiecare `fit` + `resize` trimis ar face o furtună de SIGWINCH în TUI-uri (3.6.12)
    let roTimer: ReturnType<typeof setTimeout> | 0 = 0
    const observer = new ResizeObserver(() => {
      if (roTimer) clearTimeout(roTimer)
      roTimer = setTimeout(() => {
        roTimer = 0
        if (!safeFit()) return   // demontare/teardown (split→tab): sări, următorul fit corectează
        sendResize()
      }, 100)
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
      // Setări → Preferinţe → „Terminal renderer" (3.6.19): WebGL e implicit, dar un driver GPU
      // (Chrome/Edge pe Windows, rapoarte cu nano sub tmux: rânduri suprapuse la derularea linie
      // cu linie) poate strica randarea fără ca bufferul să fie greşit — omul poate trece pe Canvas
      // sau pe DOM fără să aştepte un fix; valoarea e per browser (localStorage), ca fontul
      const pref = readRendererPref()
      appliedRendererRef.current = pref
      if (pref === 'dom') return         // renderer-ul DOM implicit al xterm
      if (pref !== 'canvas') try {
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
      // opt-in din Setări, lazy (chunk separat, încărcat DOAR când e activat); se aplică la
      // (re)deschiderea terminalului, ca modul screen-reader. (Ligaturile NU sunt aici: addon-ul
      // xterm cere API-uri Node/Electron — font-finder pe `fs` — deci nu merge în browser pur.)
      if (localStorage.getItem('wt_unicode11') === '1') {
        try {
          const { Unicode11Addon } = await import('@xterm/addon-unicode11')
          if (termRef.current === term) { term.loadAddon(new Unicode11Addon()); term.unicode.activeVersion = '11' }
        } catch { /* lăţimi Unicode implicite */ }
      }
      if (termRef.current === term) connect()
    })()
    if (paneActiveRef.current !== false) term.focus()

    const container = containerRef.current
    return () => {
      observer.disconnect()
      if (roTimer) clearTimeout(roTimer)
      // dispune rendererul WebGL/Canvas ÎNAINTE de term.dispose(): altfel bucla lui de randare
      // (requestAnimationFrame) mai poate trage un cadru pe terminalul demontat (split→tab), iar
      // `_renderService` deja nul → „undefined (reading 'dimensions')". Oprim bucla întâi.
      try { rendererRef.current?.dispose() } catch { /* deja dispus */ }
      rendererRef.current = undefined
      container?.removeEventListener('pointerdown', markInput)
      container?.removeEventListener('paste', onPasteFiles, true)
      registerInsertTarget(session.id, null)
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
      // doar dacă intrarea e încă A NOASTRĂ: la o remontare cu acelaşi sid (cheie stabilă) noul
      // terminal se poate înregistra înaintea curăţării vechiului
      const terms = (window as unknown as { __wtTerms?: Map<string, Terminal> }).__wtTerms
      if (terms?.get(session.id) === term) terms.delete(session.id)
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
    const onStorage = (e: StorageEvent) => {
      if (e.key === FONT_STORAGE_KEY) sync()
      if (e.key === 'wt_renderer') reloadRendererRef.current?.()   // popout-urile nu primesc Event('wt-renderer')
    }
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
    safeFit()
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
    // sb/rows: serverul pune istoricul real al pane-ului tmux (capture-pane) deasupra cozii de
    // transcript, cât încape în scrollback-ul NOSTRU (10000 desktop / 3000 mobil), şi împinge
    // ultimul ecran în scrollback cu `rows` (plafonate server-side; vezi core.attach_replay)
    const rows = termRef.current?.rows ?? 0
    const ws = new WebSocket(
      `${proto}://${window.location.host}/ws/sessions/${session.id}?sb=${SCROLLBACK}&rows=${rows}`)
    ws.binaryType = 'arraybuffer'
    wsRef.current = ws
    setConn('connecting')
    setWsDenied(null)

    // resetat la FIECARE mesaj (date sau ping); dacă expiră, socketul e half-open → close
    const petWatchdog = () => {
      clearTimeout(watchdogRef.current)
      watchdogRef.current = setTimeout(() => {
        try { ws.close() } catch { /* deja închis */ }   // → onclose → reconnect cu backoff
      }, WATCHDOG_MS)
    }

    ws.onopen = () => {
      retryRef.current.delay = 1000
      everOpenRef.current = true
      petWatchdog()
      expectTailRef.current = true
      setReplaying(true)
      // tastele apăsate cât eram deconectaţi n-au plecat (vezi droppedRef): spune-i cât şi că
      // trebuie retastate — altfel „am scris comanda şi n-a făcut nimic" rămâne un mister
      if (droppedRef.current > 0) {
        const n = droppedRef.current
        droppedRef.current = 0
        showInputNotice(tRef.current('session.inputDropped', { count: n }))
      }
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
            rttRef.current = Math.round(performance.now() - t0)
          }
        } else if (msg.type === 'init' || msg.type === 'readonly') {
          if (msg.type === 'init') yourIdRef.current = msg.your_id ?? null   // ca să ne marcăm în roster
          // `readonly` la init = ataşare doar-vizualizare; mesajul `readonly` = retrogradat în timp
          // ce erai conectat (rolul s-a schimbat). Nu revenim la scriere pe acelaşi socket.
          // la `init` starea vine din nou de la server (o reconectare după ce ai primit dreptul de
          // scriere înapoi o ridică); `readonly` doar coboară
          const ro = msg.type === 'readonly' || msg.readonly === true
          readOnlyRef.current = ro
          setReadOnly(ro)
          if (termRef.current) termRef.current.options.disableStdin = ro
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
          setLocked(true); setLockErr(''); unlockCodeRef.current = ''; setUnlockCode('')
          setLockReason(typeof msg.reason === 'string' ? msg.reason : '')
          // idle-lock: history-ul de clipboard (posibile parole/tokenuri) nu supravieţuieşte blocării
          clearClipHistory(); setPasteItems(null)
        } else if (msg.type === 'unlocked') {
          setLocked(false); setUnlocking(false); setLockErr(''); unlockCodeRef.current = ''; setUnlockCode('')
        } else if (msg.type === 'unlock_failed') {
          setUnlocking(false)
          const code = typeof msg.code === 'string' ? msg.code : ''
          unlockCodeRef.current = code
          setUnlockCode(code)
          if (code === 'host.needs2faSso') {
            // user SSO: re-auth PROASPĂT la IdP; la întoarcere, „Deblochează" trece pe fereastra
            // deschisă de callback (≤120 s, ca orice factor proaspăt)
            ssoStepupRedirect(session.host_id)
          } else if (code === 'stepup.needsFactor') {
            setLockErr(t('err.stepup.needsFactor'))
            void props.stepupCredential?.(session.host_id, code)   // dialogul cu drum spre Setări
          } else if (code === 'stepup.totp') {
            setLockErr(t('err.stepup.totp'))
          } else {
            setLockErr(t('session.passkeyInvalid'))
          }
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
        } else if (msg.type === 'osc133') {
          // starea OSC 133 a hub-ului în punctul în care începe fluxul live (vine după tail, înaintea
          // oricărui octet live): aplicată după ce xterm a parsat tail-ul — un write gol, în ordine.
          // Fără tail primit (nu ar trebui să se întâmple) o ignorăm: linia rămâne necunoscută.
          if (!expectTailRef.current) {
            const st: unknown = msg
            term.write('', () => { trackerRef.current?.applyHubState(st) })
          }
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
        safeFit()
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
        const replaySeq = echoRef.current.inputSeq
        term.write(new Uint8Array(ev.data), () => {
          replayRef.current = false
          // tail-ul complet = starea ecranului de după tot ce trimisesem înainte de reconectare
          echoRef.current.replayed(replaySeq)
          cprRef.current = 0          // răspunsurile la cererile rejucate nu pleacă (muteRef)
          muteRef.current = false
          // reconciliere post-replay: dacă dimensiunile s-au schimbat cât timp
          // scriam (redimensionare de fereastră, sidebar închis), aliniem
          // xterm-ul și anunțăm serverul (tmux redesenează la SIGWINCH)
          safeFit()
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
        // output-ul „exact" al unei comenzi (clipboard, markdown) se ia din FLUX, nu de pe ecran — sub
        // tmux panoul e repictat asincron faţă de marcaje. Bucăţile (despărţite DUPĂ fiecare marcaj
        // OSC 133) se dau tracker-ului în ORDINEA PARSĂRII, cu starea de la începutul fiecăreia — nu
        // la sosire: xterm parsează asincron, iar starea de la sosire putea fi a unei comenzi vechi
        // (e2e 3.6.13). Decodorul vede toţi octeţii, în ordine (un caracter UTF-8 rupt între chunk-uri).
        const tr = trackerRef.current
        const parts = splitAfterMarks(bytes)
        // ecou: output sosit DUPĂ ultimele taste trimise; marcat abia după ce xterm l-a parsat
        // (trackerul OSC 133 vede atunci linia la zi) — guardrail-ul se bazează pe el. Strâns
        // (3.6.13): doar dacă a schimbat linia / cursorul faţă de instantaneul de la trimitere
        const echo = echoRef.current
        const seq = echo.inputSeq
        // cereri de poziţie a cursorului: doar după una, `CSI 1;n R` e un răspuns, nu F3 (LOW-B)
        cprRef.current += countCprRequests(bytes)
        // scrieri încă neparsate: cât sunt, fluxul nu e „liniştit" (LOW-C)
        echo.writeStart()
        const tracked = seq > echo.coarseSeq || echo.waiting
        parts.forEach((part, i) => {
          term.write('', () => {
            // ştergere de ecran / RIS / regiune de scroll mutată: rândul promptului devine suspect
            const scan = screenResetScan(resetCarryRef.current, part)
            resetCarryRef.current = scan.carry
            if (tr && scan.hit) tr.noteScreenReset()
            const text = streamDecoderRef.current.decode(part, { stream: true })
            if (tr?.capturing) tr.feed(text)
          })
          if (i < parts.length - 1) term.write(part)
          else if (tracked) {
            term.write(part, () => {
              tr?.endChunk()
              echo.writeEnd()
              echo.output(seq, lineKeyRef.current, performance.now(), rttRef.current)
            })
          } else term.write(part, () => { tr?.endChunk(); echo.writeEnd() })
        })
      }
    }
    ws.onclose = (ev) => {
      wsRef.current = null
      clearTimeout(watchdogRef.current)
      if (!termRef.current) return // component unmounted
      // sesiune moartă: fetch-ul de istoric e one-shot — nu reprograma reconnect (gardă
      // directă pe exitedRef, robustă chiar dacă starea conn a fost cumva alterată)
      if (exitedRef.current) return
      // Codurile TERMINALE ale gateway-ului (api.py browser_ws). Atenţie: un close() ÎNAINTE
      // de accept() ajunge la browser ca handshake 403 = cod 1006, deci 4401/4403/4404 se văd
      // doar când vin DUPĂ accept — 4401 de la revalidarea periodică (cookie expirat/logout),
      // 4403 la revocare, 4404 când sesiunea a dispărut. Fără asta reconectam la nesfârşit,
      // iar la 4401 aplicaţia se înlocuia tăcut cu pagina de login la următorul poll.
      // 4408 (kick / pong timeout) şi orice altceva (1006, proxy, sleep) păstrează backoff-ul.
      if (ev.code === 4401) {
        setWsDenied('auth')
        setConn('ended')
        window.dispatchEvent(new Event('wt-unauth'))   // App arată motivul + „Sign in again"
        return
      }
      if (ev.code === 4403) {
        setWsDenied('forbidden')
        setConn('ended')
        return
      }
      if (ev.code === 4404) {
        // sesiunea nu mai există pe gateway: UI-ul existent de „lost", fără retry
        setExited({ status: null, reason: 'session_gone' })
        setConn('ended')
        exitedRef.current = true
        props.onChanged()
        return
      }
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
        ? await props.stepupCredential(session.host_id, unlockCodeRef.current || undefined)
        : await (async () => {
            const options = await api<Record<string, unknown>>('/api/webauthn/stepup/options', {
              method: 'POST', body: JSON.stringify({ host_id: session.host_id }),
            })
            const credential = await startAuthentication({ optionsJSON: options as never })
            const r = await api<{ grant: string }>('/api/webauthn/stepup/verify', {
              method: 'POST', body: JSON.stringify({ host_id: session.host_id, credential }),
            })
            return { stepup_grant: r.grant } as StepupCred
          })()
      if (!cred) { setUnlocking(false); return }        // anulat de utilizator
      // the HTTP credential (`stepup_totp`) mapped onto the WS unlock fields (`totp`)
      wsRef.current?.send(JSON.stringify(wsUnlockMessage(cred)))
      // 'unlocked' de la server curăţă `locked`/`unlocking`
    } catch (e) {
      setUnlocking(false)
      setLockErr(errText(e, t) || t('session.passkeyAuthFailed'))
    }
  }

  async function saveMeta(next: { title?: string; note?: string }) {
    // Eşecul era înghiţit (`.catch(() => {})`): redenumirea/nota păreau salvate, iar la următorul
    // poll reveneau tăcut la valoarea veche. Acum spunem ce n-a mers; textul rămâne în câmp.
    try {
      await api(`/api/sessions/${session.id}`, {
        method: 'PATCH',
        body: JSON.stringify(next),
      })
    } catch (e) {
      notifyError(next.title !== undefined ? t('session.renameFailed') : t('session.noteSaveFailed'), errText(e, t))
    }
    props.onChanged()
  }

  async function copySelection() {
    const sel = termRef.current?.getSelection()
    if (sel) {
      if (await copySession(session.id, sel)) {
        setCopied(true)
        setTimeout(() => setCopied(false), 1200)
      }
    }
  }

  // -- acţiuni de fişiere din meniul contextual al terminalului ------------------------------
  // Toate refolosesc panoul de fişiere / editorul / motorul de upload existente — NU duplicăm
  // nimic din transfer engine. Ancora e cwd-ul din OSC 7; fără el (shell integration oprită)
  // cădem pe home-ul rezolvat, ca drop-ul/paste-ul de fişiere.
  const filesAnchorDir = async (): Promise<string> => cwdRef.current ?? await resolveHome(props.host!.id)

  // (Re)deschide FilePanel la o cale (sau la cwd, când `dir` lipseşte → urmăreşte cwd-ul). Remontăm
  // prin nonce ca prop-ul `revealPath` să fie recitit chiar dacă panoul era deja deschis altundeva.
  const revealFiles = (dir?: string, action?: 'newFile' | 'newFolder') => {
    setFilesReveal(dir)
    setFilesAction(action)
    setFilesNonce((n) => n + 1)
    closeOthers('files')
    setShowFiles(true)
  }

  // „Deschide calea": fişier → editor (Monaco; siguranţa la fişiere mari vine gratis din FileEditor),
  // director sau necunoscut → panoul la acea cale. `fs` listează doar directoare, `fs/preview` doar
  // fişiere — le folosim ca sonde ca să alegem corect, fără un endpoint de `stat` separat.
  const openSelectedPath = async (raw: string) => {
    const host = props.host
    if (!host) return
    const p = resolveTermPath(raw, await filesAnchorDir())
    try {
      await api(`/api/hosts/${host.id}/fs?path=${encodeURIComponent(p)}`)
      revealFiles(p); return                                   // e director
    } catch { /* nu e director */ }
    try {
      await api(`/api/hosts/${host.id}/fs/preview?path=${encodeURIComponent(p)}`)
      setEditorFile({ path: p, name: baseName(p) }); return    // e fişier
    } catch { /* nici fişier lizibil */ }
    revealFiles(p)                                             // necunoscut → panoul arată propria eroare
  }

  // „Încarcă aici…": urcăm direct prin motorul de upload (lib), fără cuplare la FilePanel. Un
  // singur toast de sumar (ca la paste/drop), nu unul per fişier.
  const uploadHere = async (files: File[]) => {
    const host = props.host
    if (!host || !files.length) return
    if (!canOn(perms, host.id, 'files.write')) { notifyToast(t('files.needsWrite'), 'warn'); return }   // FL-09
    const dir = (await filesAnchorDir()).replace(/\/+$/, '')
    const ids = await Promise.all(files.map((f) =>
      startUpload({ hostId: host.id, hostName: host.name, dest: `${dir}/${f.name}`, file: f }).catch(() => null)))
    const failed = ids.filter((id) => !id || uploadStore.get(id)?.state !== 'done').length
    if (failed) notifyToast(t('session.ctxFilesUploadErr', { failed, total: files.length }), 'warn')
    else notifyToast(t('session.ctxFilesUploadOk', { count: files.length, dir }), 'info')
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
      notify(t('session.commandOutputTitle'), t('session.cannotExtractOutput'), 'warn')
      return
    }
    if (!text) return
    // plafon de dimensiune, ca la OSC 52: un output uriaș nu trebuie să umple
    // clipboardul cu megaocteți dintr-un singur click
    if (await copySession(session.id, text.slice(0, 200_000))) {
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
    typeText(c.text)   // fără Enter; cu broadcast, în toate panourile (ca tastarea)
    termRef.current?.focus()
  }

  const copyCommand = async (c: Command) => {
    flashCopied(await copySession(session.id, c.text))
  }

  // „Ca markdown": comandă + output + exit/durată, gata de lipit într-un ticket/chat.
  const copyMarkdown = async (c: Command) => {
    const out = trackerRef.current?.outputOf(c)
    const meta = [c.exitCode != null ? `exit ${c.exitCode}` : null, c.endedAt ? cmdDuration(c) : null]
      .filter(Boolean).join(' · ')
    const body = out == null ? t('session.outputUnavailable') : out.slice(0, 200_000).replace(/\n+$/, '')
    const md = '```console\n$ ' + c.text + (meta ? `   # ${meta}` : '') + '\n' + body + '\n```\n'
    flashCopied(await copySession(session.id, md))
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
      if (!(await confirm({
        title: t('session.shellIntegrationTitle'), message: t('session.confirmShellIntegration'),
        confirmLabel: t('session.typeAndRun'),
      }))) return
      send(r.command + '\n')
      termRef.current?.focus()
    } catch {
      notifyError(t('session.shellIntegrationTitle'), t('session.cannotGetSetupCommand'))
    }
  }

  /** xterm.paste() cu marcajul „paste în curs": datele emise (sincron, prin onData) nu sunt niciodată
      rapoarte de terminal (review 3.6.13, a treia trecere, LOW-1) — singura cale către term.paste */
  function termPaste(text: string) {
    const prev = pastingRef.current
    pastingRef.current = true
    try { termRef.current?.paste(text) } finally { pastingRef.current = prev }
  }

  async function paste() {
    const text = await readText()
    // Citirea nu are cale de rezervă: `execCommand('paste')` e blocat peste tot, iar
    // `navigator.clipboard` lipseşte pe origini nesecurizate. Spunem asta în loc să
    // pară că butonul nu face nimic — Ctrl+V direct în terminal merge oricum.
    if (text === null) {
      notifyError(t('session.clipboardTitle'), t('session.clipboardBlocked'))
      return
    }
    // prin xterm.paste(), nu send() direct: doar așa textul e împachetat în
    // bracketed paste (\x1b[200~…) — altfel un paste multi-linie execută
    // fiecare linie imediat în shell și strică indentarea în vim/nano
    if (text) termPaste(text)
    termRef.current?.focus()
  }

  // paste picker: deschidem cu un SNAPSHOT al history-ului global (nu live, ca lista să nu
  // sară sub degete cât alegi); se reîmprospătează doar la ✕ / „Clear history". Închiderea = null.
  function openPastePicker() {
    setPasteItems(clipHistory())
  }
  function pasteFromHistory(text: string, run: boolean) {
    setPasteItems(null)
    // bracketed paste (ca `paste()`): multi-linie rămâne inert. „run" adaugă Enter DUPĂ,
    // deliberat separat, ca auto-execuţia să fie o alegere, nu implicit.
    const cur = trackerRef.current?.pendingCommand() ?? ''   // ÎNAINTE de paste: linia la care se adaugă
    termPaste(text)
    // „lipeşte şi rulează" nu ocoleşte guardrail-ul: dacă o linie atinge o regulă, lipim fără
    // Enter — verificarea de la Enter (sau dialogul de confirmare) decide apoi, ca la tastare
    const hit = run ? guardedLine(cur + text) : null
    if (hit) setGuardMsg(t('session.pasteGuarded', { cmd: hit.line.slice(0, 70), pattern: hit.pattern }))
    // Enter-ul ia ACEEAŞI cale ca un Enter tastat (userInput): cât o verificare aşteaptă ecoul intră
    // în coadă, altfel e verificat — local şi, cu broadcast, în toate panourile (review 3.6.12 L4,
    // re-review L-a: nu o a doua buclă de aşteptare pe acelaşi ref)
    else if (run) {
      enterOkAtRef.current = -Infinity   // nu e Enter-ul unui keydown deja verificat
      ioRef.current.userInput('\r')
    }
    termRef.current?.focus()
  }

  async function killSession() {
    if (!(await confirm({
      title: t('session.killTitle'), message: t('session.confirmKill'),
      danger: true, confirmLabel: t('session.stopSession'),
    }))) return
    // host cu 2FA → 403 de step-up: withStepup rulează ceremonia passkey și reîncearcă o dată
    await withStepup(session.host_id, () =>
      api(`/api/sessions/${session.id}/kill`, { method: 'POST' }))
      .catch((e) => notifyError(t('session.killFailed'), errText(e, t)))
  }

  async function deleteSession() {
    if (!(await confirm({
      title: t('host.deleteTitle'), message: t('session.confirmDelete'),
      danger: true, confirmLabel: t('session.delete'),
    }))) return
    try {
      await api(`/api/sessions/${session.id}`, { method: 'DELETE' })
      props.onDeleted()
    } catch (e) {
      notifyError(t('host.deleteTitle'), errText(e, t) || t('session.deleteFailed'))
    }
  }

  // „reconectare…" DOAR pentru sesiuni vii — la o sesiune terminată bucla de
  // reconectare (care aduce istoricul) nu trebuie să pară o problemă de conexiune
  // prima conectare (socketul n-a fost NICIODATĂ deschis) e „connecting", neutră — nu o
  // problemă de conexiune; „reconnecting" apare doar după ce am avut o conexiune şi am pierdut-o
  const connBadge =
    isLive && (conn === 'reconnecting' || conn === 'connecting')
      ? everOpenRef.current || conn === 'reconnecting'
        ? { text: t('session.reconnecting'), cls: 'bg-amber-900/70 text-amber-200' }
        : { text: t('session.connecting'), cls: 'bg-ink-800 text-slate-300' }
      : null
  // cortina de pauză a tastaturii: sesiune vie, socket închis, cortina de replay trasă NU e
  // (aceea acoperă deja prima încărcare) şi nu e o închidere terminală (bara ei e mai jos)
  const inputPaused = isLive && conn !== 'open' && !replaying && !wsDenied

  const hostAccent = props.host ? hostColor(props.host) : '#64748b'
  // Docker / Servicii / Toolbox: doar host-uri de agent (rulează prin op-ul `run`) — aceeaşi
  // regulă pentru butoanele din bară şi pentru itemii din meniul ⋯
  const agentHost = !props.host?.connection_type || props.host.connection_type === 'agent'
  const reach = props.host ? reachState(props.host) : 'offline'
  // FL-09: Git (rulează prin `run`), Docker (`docker.view`), Servicii (`services.view`) — aceleaşi
  // permisiuni pe care le cere serverul (api.py host_git / docker / services). `show` = o ai pe măcar
  // un host (altfel unealta nu apare deloc); `disabled` + motiv = n-o ai pe ACEST host.
  const toolGate = (perm: string) => {
    const may = canOn(perms, props.host?.id, perm)
    return { show: anyHost(perms, perm), disabled: !may, reason: may ? undefined : t('authz.notHere', { perm }) }
  }
  const gitGate = toolGate('run')
  const dockerGate = toolGate('docker.view')
  const servicesGate = toolGate('services.view')

  return (
    <div ref={rootRef} className={`wt-window flex h-full flex-col ${
      // delimitarea panourilor de split: broadcast = ambră; panoul ACTIV = accent albastru clar;
      // orice alt panou de split = border subtil (înainte inactivele n-aveau niciun contur → graniţă invizibilă)
      // broadcast: TOATE panourile în ambră, dar cel focalizat mai gros — altfel nu mai vedeai unde
      // e focusul (ţinta căutării / fontului / Ctrl+W) cât broadcast-ul era pornit (3.6.12)
      props.broadcasting ? (props.activeInSplit ? 'ring-[3px] ring-inset ring-amber-300' : 'ring-1 ring-inset ring-amber-500/70')
        : props.activeInSplit ? 'ring-2 ring-inset ring-sky-500'
        : props.inSplit ? 'ring-1 ring-inset ring-ink-600'
        : ''}`}>
      {/* broadcast activ: bandă de avertizare vizibilă în FIECARE panou al grilei — tastezi în
          toate host-urile deodată, deci ambiguitatea „unde scriu" trebuie să fie zero */}
      {props.broadcasting && (
        <div className="shrink-0 bg-amber-500/90 px-2 py-0.5 text-center text-2xs font-semibold text-ink-950">
          <span className="inline-flex items-center gap-1"><KeyboardIcon size={12} />{t('grid.broadcastOn')}</span>
        </div>
      )}
      {/* bandă de identitate = culoarea host-ului (o vezi și în tab) */}
      <div className="h-[3px] shrink-0" style={{ background: hostAccent }} aria-hidden="true" />
      {/* header (titlebar în tema macOS) */}
      {/* min-w-0 + gap mai mic pe mobil: fără ele, badge-ul hostului și butoanele
          împing toolbarul în afara ecranului (iPhone SE / Galaxy S9) */}
      <header ref={headerRef} className="flex min-w-0 items-center gap-1 border-b border-ink-800 bg-ink-900 px-2 py-2 md:gap-2 md:px-3">
        <IconButton size="md" onClick={props.onMenu} label={menuLabel(t('session.openHostList'), unreadAlerts, t)}
          className={`relative ${props.sidebarCollapsed ? '' : 'md:hidden'}`}>
          <MenuIcon />
          <MenuUnreadBadge n={unreadAlerts} />
        </IconButton>
        {props.host && (
          <span className="flex min-w-0 shrink items-center gap-1.5 rounded-md px-1.5 py-1"
            style={{ background: `${hostAccent}1f` }}
            title={`${props.host.name} · ${protoLabel(props.host)} · ${reach === 'online' ? t('host.statusOnline') : reach === 'ondemand' ? t('session.onDemand') : t('host.statusOffline')}`}>
            {/* starea nu e doar culoare: online = punct plin (pulsează), on-demand = inel gol,
                offline = gri; textul complet e în span-ul sr-only (title-ul nu e citit de SR) */}
            <span aria-hidden="true"
              className={`h-2 w-2 shrink-0 rounded-full ${reach === 'online' ? 'dot-live' : reach === 'ondemand' ? 'border-2' : ''}`}
              style={reach === 'offline' ? { background: '#64748b' } : reach === 'ondemand' ? { borderColor: hostAccent } : { background: hostAccent }} />
            <span className="max-w-[120px] truncate font-mono text-xs font-medium md:max-w-[220px]" style={{ color: hostAccent }}>
              {hostAt(props.host)}
            </span>
            <span className="sr-only">
              {' — '}{reach === 'online' ? t('host.statusOnline') : reach === 'ondemand' ? t('session.onDemand') : t('host.statusOffline')}
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
            onBlur={() => title !== session.title && title !== sessionTitle(session.title, t) && saveMeta({ title })}
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
            <span className={`rounded-md px-2 py-0.5 text-xs ${connBadge.cls}`}>{connBadge.text}</span>
          )}
        </span>
        <div className="ml-auto flex shrink-0 items-center gap-0.5">
          {/* Încărcarea host-ului activ, dintr-o privire (CPU + memorie). Din metricile pe care
              app-ul le ia oricum la poll — vezi HostLoadRing. Stă între nume şi butoane. */}
          {props.host && <HostLoadRing host={props.host} />}
          {/* roster: apare când mai e cineva conectat; owner-ul poate da kick. La ORICE lăţime
              (era `lg:flex`, deci pe telefon/tabletă nu vedeai cine se uită şi nu puteai scoate
              pe nimeni) — şi în header, care rămâne vizibil şi pe telefonul în peisaj, unde
              `.wt-compact-y` ascunde toată bara de stare cu avertismentul „👁 N conectaţi". */}
          {roster.length > 1 && (
            <div className="relative">
              <button
                onClick={() => setShowRoster((v) => !v)}
                title={t('session.whoConnected')}
                aria-label={`${t('session.whoConnected')}: ${roster.length}`}
                aria-expanded={showRoster}
                data-testid="session-roster"
                className="wt-warn wt-touch flex items-center gap-1 rounded-md px-1.5 py-1 text-xs tabular-nums ring-1 ring-ink-700 hover:bg-ink-800"
              ><EyeIcon /> {roster.length}</button>
              {showRoster && (
                <>
                  <div className="fixed inset-0 z-30" onClick={() => setShowRoster(false)} />
                  {/* telefon: foaie de jos (butonul poate sta oriunde în bară → un dropdown ancorat ar ieşi
                      din ecran la stânga); de la sm în sus, dropdown sub buton */}
                  <div className="fixed inset-x-2 bottom-[calc(var(--wt-keybar-h,0px)+0.5rem)] z-40 max-h-[60dvh] overflow-y-auto rounded-xl bg-ink-900 p-1.5 text-xs ring-1 ring-ink-700 shadow-xl sm:absolute sm:inset-x-auto sm:bottom-auto sm:right-0 sm:top-full sm:mt-1 sm:w-72">
                    <div className="px-2 py-1 text-2xs uppercase tracking-wide text-slate-500">{t('session.connectedCount', { count: roster.length })}</div>
                    {roster.map((c) => (
                      <div key={c.id} className="rounded-md py-0.5 hover:bg-ink-800">
                        <div className="flex items-center gap-2 px-2 py-1">
                        <span className="min-w-0 flex-1 truncate text-slate-200">
                          {c.label === 'self' ? t('session.roleSelf')
                            : c.label === 'guest' ? t('session.roleGuest')
                            : c.label}{c.id === yourIdRef.current ? ` ${t('session.you')}` : ''}
                        </span>
                        {c.owner
                          ? <span className="shrink-0 text-2xs text-slate-500">owner</span>
                          : <span className={`shrink-0 text-2xs ${c.writable ? 'wt-warn' : 'text-slate-500'}`}>{c.writable ? t('session.canWrite') : t('session.canView')}</span>}
                        {!c.owner && (
                          <IconButton touch={false} onClick={() => { void kick(c) }} label={t('session.removeFromSession')}
                            variant="danger"><CloseIcon size={14} /></IconButton>
                        )}
                        </div>
                        {/* De unde e ataşat. Fără asta „mai e cineva conectat" nu-ţi spunea
                            dacă e telefonul tău sau altcineva — deci nu puteai reacţiona. */}
                        {(c.ip || c.agent) && (
                          <div className="flex items-center gap-1.5 px-2 pb-1 text-2xs text-slate-500">
                            <span className="min-w-0 truncate">{c.ip}{c.agent ? ' · ' + shortAgent(c.agent) : ''}</span>
                            {c.known === false && (
                              <span title={t('session.deviceNewTitle')}
                                className="wt-warn shrink-0 rounded-md bg-amber-500/15 px-1">{t('session.deviceNew')}</span>
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
          {/* Pe mobil ține DOAR esențialul în bară (căutare + paste); restul
              intră în meniul ⋯. Pe iPhone SE, cinci butoane + badge + titlu
              împingeau toolbarul afară din ecran. */}
          <ToolButton title={t('session.searchScrollback', { shortcut: shortcutFor('search') })} active={showSearch} toggle onClick={() => setShowSearch(!showSearch)}><SearchIcon /></ToolButton>
          {/* comenzi (OSC 133): navighezi între ele cu Alt+↑/↓. Eticheta era „⌘N" — tasta Cmd de
              pe Mac, fără sens pe Linux/Windows; „❯" e promptul, neutru pe orice platformă. */}
          <span className={roomy ? 'contents' : 'hidden'}>
            <ToolButton
              title={commands.length ? t('session.commandsCount', { count: commands.length }) : t('session.commandsActivate')}
              active={showCommands} toggle
              onClick={toggleCommands}
            >
              <span className="inline-flex items-center font-mono text-xs"><ChevronIcon size={14} />{commands.length > 0 ? commands.length : ''}</span>
            </ToolButton>
          </span>
          {/* fișiere: navighezi/editezi/transferi; urmărește cwd-ul din terminal */}
          <span className={roomy ? 'contents' : 'hidden'}>
            <ToolButton title={t('session.filesTooltip')} active={showFiles} toggle onClick={toggleFiles}>
              <FilesIcon />
            </ToolButton>
          </span>
          {/* git: status/diff/stage/commit pe repo-ul din cwd-ul terminalului */}
          {gitGate.show && (
            <span className={roomy ? 'contents' : 'hidden'}>
              <ToolButton title={gitGate.reason ?? t('session.gitTooltip')} name={t('session.gitTooltip')} active={showGit} toggle disabled={gitGate.disabled} onClick={toggleGit}>
                <GitBranchIcon />
              </ToolButton>
            </span>
          )}
          {/* port forwards: expune servicii web de pe host prin browser */}
          <span className={roomy ? 'contents' : 'hidden'}>
            <ToolButton title={t('session.forwardsTooltip')} active={showForwards} toggle onClick={toggleForwards}>
              <ForwardIcon />
            </ToolButton>
          </span>
          {/* docker: containere/imagini/volume/reţele + shell în container. Doar host-uri de
              agent (docker CLI e local pe host; SSH/telnet n-au op-ul `run`). */}
          {agentHost && dockerGate.show && (
            <span className={roomy ? 'contents' : 'hidden'}>
              <ToolButton title={dockerGate.reason ?? t('session.dockerTooltip')} name={t('session.dockerTooltip')} active={showDocker} toggle disabled={dockerGate.disabled} onClick={toggleDocker}>
                <DockerIcon />
              </ToolButton>
            </span>
          )}
          {/* servicii systemd: listă + start/stop/restart. Doar host-uri de agent (systemctl e
              local pe host, prin op-ul `run` — ca Docker). */}
          {agentHost && servicesGate.show && (
            <span className={roomy ? 'contents' : 'hidden'}>
              <ToolButton title={servicesGate.reason ?? t('session.servicesTooltip')} name={t('session.servicesTooltip')} active={showServices} toggle disabled={servicesGate.disabled} onClick={toggleServices}>
                <ServicesIcon />
              </ToolButton>
            </span>
          )}
          {/* Toolbox: lansatoare de conexiuni DB. Doar host-uri de agent (CLI-ul rulează pe host). */}
          {agentHost && (
            <span className={roomy ? 'contents' : 'hidden'}>
              <ToolButton title={t('session.toolboxTooltip')} active={showToolbox} toggle onClick={toggleToolbox}>
                <ToolboxIcon />
              </ToolButton>
            </span>
          )}
          {/* Comenzi salvate: montat la ORICE lăţime (doar butonul-declanşator e ascuns pe telefon).
              Înainte tot meniul stătea într-un `hidden sm:contents`, deci itemul din ⋯ şi Alt+S
              deschideau un dropdown invizibil; pe telefon apare acum ca foaie de jos. */}
          {isLive && (
            <SnippetsMenu
              open={snippetsOpen}
              onOpenChange={setSnippetsOpen}
              triggerClassName={roomy ? 'grid' : 'hidden'}
              onInsert={(b) => { typeText(b); termRef.current?.focus() }}
            />
          )}
          <ToolButton title={t('session.paste')} onClick={paste}><PasteIcon /></ToolButton>
          <ToolButton title={t('paste.fromHistoryTitle', { shortcut: shortcutFor('pastePicker') })} active={pasteItems !== null} onClick={openPastePicker}><ClockIcon /></ToolButton>

          {/* Secundar: inline doar pe ecrane mari. Pe tablete (iPad Mini/Pro),
              zece butoane × 44px (ținte tactile) depășeau lățimea — trec în ⋯. */}
          <div className={`${wide ? 'flex' : 'hidden'} items-center gap-0.5`}>
            <span className="mx-0.5 h-4 w-px bg-ink-700" aria-hidden="true" />
            <ToolButton title={t('session.linksTooltip')} active={linksOpen} onClick={openLinks}><ExternalLinkIcon /></ToolButton>
            <ToolButton title={t('session.note')} active={showNote} toggle onClick={() => setShowNote(!showNote)}><NoteIcon /></ToolButton>
            <ToolButton title={t('session.copySelection')} onClick={copySelection}>{copied ? <CheckIcon size={16} /> : <CopyIcon />}</ToolButton>
            <ToolButton title={t('session.fontSmaller')} name={`A− ${t('session.fontSmaller')}`} onClick={() => setPreferredFont(fontSize - 1)}><span className="text-sm">A−</span></ToolButton>
            <ToolButton title={t('session.fontLarger')} name={`A+ ${t('session.fontLarger')}`} onClick={() => setPreferredFont(fontSize + 1)}><span className="text-sm">A+</span></ToolButton>
            {!props.popout && (
              <ToolButton title={t('session.shareLinkTooltip')} active={!!shareUrl || !!shareActive || shareOpen} onClick={share}><ShareIcon /></ToolButton>
            )}
            {props.onPopout && !props.popout && (
              <ToolButton title={t('session.detachWindow', { shortcut: shortcutFor('popout') })} onClick={props.onPopout}><PopoutIcon /></ToolButton>
            )}
            <ToolButton
              title={t('session.fullscreen')}
              onClick={() => {
                if (document.fullscreenElement) document.exitFullscreen()
                else document.documentElement.requestFullscreen().catch(() => {})
              }}
            ><FullscreenIcon /></ToolButton>
          </div>

          {/* overflow: mobil ȘI tablete */}
          <div className={wide ? 'hidden' : 'relative'}>
            <ToolButton ref={moreBtnRef} title={t('session.more')} active={moreOpen} onClick={() => setMoreOpen((v) => !v)}
              aria-expanded={moreOpen} aria-controls={moreId}><MoreIcon /></ToolButton>
            {moreOpen && (
              <>
                <div className="fixed inset-0 z-30 bg-black/40 sm:bg-transparent" aria-hidden="true" onClick={() => setMoreOpen(false)} />
                {/* disclosure (U23): telefon = foaie de jos, lată, cu acţiuni etichetate de 44px;
                    tabletă = panou sub buton. Escape închide şi întoarce focusul pe „Mai multe". */}
                <div id={moreId} ref={morePanelRef} data-testid="session-more"
                  role="group" aria-label={t('session.more')}
                  className="wt-sheet-bottom fixed inset-x-0 bottom-0 z-40 max-h-[70dvh] overflow-y-auto rounded-t-2xl border-t border-ink-700 bg-ink-900 p-2 shadow-2xl sm:absolute sm:inset-x-auto sm:bottom-auto sm:right-0 sm:mt-1 sm:max-h-[calc(100dvh-5rem)] sm:w-56 sm:rounded-xl sm:border sm:p-1">
                  {/* acțiunile scoase din bară pe ecrane înguste — ACELEAŞI reguli de
                      disponibilitate ca butoanele din bară (Docker/Servicii/Toolbox: doar agent) */}
                  <span className={roomy ? 'hidden' : ''}>
                    <MoreItem onClick={() => { if (!showCommands) toggleCommands(); setMoreOpen(false) }}>
                      <ChevronIcon size={16} /> {t('session.commands')}{commands.length ? ` (${commands.length})` : ''}
                    </MoreItem>
                    <MoreItem onClick={() => { if (!showFiles) toggleFiles(); setMoreOpen(false) }}>
                      <FilesIcon /> {t('session.files')}
                    </MoreItem>
                    {gitGate.show && (
                      <MoreItem onClick={() => { if (!showGit) toggleGit(); setMoreOpen(false) }} disabled={gitGate.disabled} title={gitGate.reason}>
                        <GitBranchIcon /> Git
                      </MoreItem>
                    )}
                    <MoreItem onClick={() => { if (!showForwards) toggleForwards(); setMoreOpen(false) }}>
                      <ForwardIcon /> {t('session.portForwards')}
                    </MoreItem>
                    {agentHost && dockerGate.show && (
                      <MoreItem onClick={() => { if (!showDocker) toggleDocker(); setMoreOpen(false) }} disabled={dockerGate.disabled} title={dockerGate.reason}>
                        <DockerIcon /> {t('docker.title')}
                      </MoreItem>
                    )}
                    {agentHost && servicesGate.show && (
                      <MoreItem onClick={() => { if (!showServices) toggleServices(); setMoreOpen(false) }} disabled={servicesGate.disabled} title={servicesGate.reason}>
                        <ServicesIcon /> {t('services.title')}
                      </MoreItem>
                    )}
                    {agentHost && (
                      <MoreItem onClick={() => { if (!showToolbox) toggleToolbox(); setMoreOpen(false) }}>
                        <ToolboxIcon /> {t('toolbox.title')}
                      </MoreItem>
                    )}
                    {isLive && (
                      <MoreItem onClick={() => { setSnippetsOpen(true); setMoreOpen(false) }}>
                        <TerminalPromptIcon /> {t('session.savedCommands')}
                      </MoreItem>
                    )}
                  </span>
                  {roster.length > 1 && (
                    <MoreItem onClick={() => { setShowRoster(true); setMoreOpen(false) }}>
                      <EyeIcon size={16} /> {t('session.connectedCount', { count: roster.length })}
                    </MoreItem>
                  )}
                  <MoreItem onClick={() => { openLinks(); setMoreOpen(false) }}><ExternalLinkIcon /> {t('session.links')}</MoreItem>
                  <MoreItem onClick={() => { setShowNote(!showNote); setMoreOpen(false) }}><NoteIcon /> {t('session.note')}</MoreItem>
                  <MoreItem onClick={() => { copySelection(); setMoreOpen(false) }}><CopyIcon /> {t('session.copySelection')}</MoreItem>
                  <MoreItem onClick={() => setPreferredFont(fontSize + 1)}>A+ {t('session.fontLarger')}</MoreItem>
                  <MoreItem onClick={() => setPreferredFont(fontSize - 1)}>A− {t('session.fontSmaller')}</MoreItem>
                  {!props.popout && (
                    <MoreItem onClick={() => { share(); setMoreOpen(false) }}><ShareIcon /> {t('session.shareLink')}</MoreItem>
                  )}
                  <MoreItem onClick={() => {
                    if (document.fullscreenElement) document.exitFullscreen()
                    else document.documentElement.requestFullscreen().catch(() => {})
                    setMoreOpen(false)
                  }}><FullscreenIcon /> {t('session.fullscreen')}</MoreItem>
                  {/* oprirea, cu etichetă text: în bară e doar pictograma ■, uşor de confundat cu
                      „închide tab-ul" (care NU opreşte sesiunea) */}
                  {isLive && (
                    <>
                      <div className="my-1 h-px bg-ink-800" aria-hidden="true" />
                      <MoreItem onClick={() => { setMoreOpen(false); void killSession() }}>
                        <span className="wt-danger flex items-center gap-2"><StopIcon /> {t('session.stopSessionMenu')}</span>
                      </MoreItem>
                    </>
                  )}
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
      {pasteItems !== null && (
        <PastePicker
          items={pasteItems}
          onPaste={(txt) => pasteFromHistory(txt, false)}
          onPasteRun={(txt) => pasteFromHistory(txt, true)}
          onRemove={(txt) => { removeClip(txt); setPasteItems(clipHistory()) }}
          onClear={() => { clearClipHistory(); setPasteItems([]) }}
          onClose={() => setPasteItems(null)}
        />
      )}
      {linksOpen && (
        <LinksDialog links={links} onClose={() => setLinksOpen(false)}
          onCopy={async (u) => flashCopied(await copySession(session.id, u))} />
      )}

      {/* Panou de opțiuni share (înainte de generare) */}
      {shareOpen && !shareUrl && !shareActive && (
        <div className="flex flex-wrap items-center gap-3 border-b border-ink-800 bg-ink-900/70 px-3 py-2 text-sm">
          <label className="flex cursor-pointer items-center gap-1.5 text-xs text-slate-300">
            <input type="checkbox" checked={shareWritable} onChange={(e) => setShareWritable(e.target.checked)} className="h-3.5 w-3.5 rounded-md accent-sky-600" />
            {t('session.allowWrite')}
            {shareWritable && <span className="wt-warn" title={t('session.writableWarning')} aria-label={t('session.writableWarning')} role="img"><WarningIcon /></span>}
          </label>
          <label className="flex items-center gap-1.5 text-xs text-slate-400">
            {t('session.expiresIn')}
            <select value={shareExpiry} aria-label={t('session.shareExpiry')} onChange={(e) => setShareExpiry(Number(e.target.value))}
              className="rounded-md border border-ink-700 bg-ink-900 px-1.5 py-1 text-xs text-slate-200">
              <option value={15}>{t('session.expiry15m')}</option>
              <option value={60}>{t('session.expiry1h')}</option>
              <option value={480}>{t('session.expiry8h')}</option>
              <option value={1440}>{t('session.expiry24h')}</option>
            </select>
          </label>
          <Button variant="primary" size="sm" onClick={createShareLink}>
            {t('session.generateLink')}
          </Button>
          <button onClick={() => setShareOpen(false)} className="rounded-md px-2 py-1 text-xs text-slate-400 hover:bg-ink-800">
            {t('session.cancel')}
          </button>
          {/* riscul scris în clar, nu doar într-un tooltip (U14): un link scriptibil = shell pe host */}
          {shareWritable && (
            <p role="note" data-testid="share-writable-warning" className="wt-warn flex w-full items-start gap-1.5 text-xs">
              <WarningIcon size={14} /><span>{t('session.writableRisk')}</span>
            </p>
          )}
        </div>
      )}

      {/* Link generat */}
      {(shareUrl || shareActive) && (
        <div ref={shareBarRef} className="flex flex-wrap items-center gap-2 border-b border-ink-800 bg-ink-900/70 px-3 py-2 text-sm">
          <span className={`shrink-0 rounded-md px-1.5 py-0.5 text-2xs ${shareActive?.writable ? 'wt-warn bg-amber-500/15' : 'bg-ink-800 text-slate-400'}`}>
            {shareActive?.writable ? t('session.shareWritable') : t('session.shareReadOnly')}
          </span>
          {shareUrl ? (
            <code className="wt-good min-w-0 flex-1 truncate rounded-md bg-black/40 px-2 py-1 font-mono text-xs">{shareUrl}</code>
          ) : (
            <span className="min-w-0 flex-1 text-xs text-slate-400">{t('session.shareActiveNoUrl')}</span>
          )}
          {shareUrl && <Button variant="primary" size="sm"
            onClick={() => { copyText(shareUrl).then((ok) => { if (!ok) return
              setCopied(true); setTimeout(() => setCopied(false), 1200) }) }} className="shrink-0">
            {copied ? <CheckIcon /> : t('session.copy')}
          </Button>}
          <button onClick={revokeShare} className="wt-danger shrink-0 rounded-md px-2 py-1 text-xs hover:bg-ink-800">
            {t('session.revoke')}
          </button>
          {/* expirarea pe rândul ei, pe ORICE lăţime (U14): era `hidden sm:inline`, deci pe
              telefon nu vedeai cât mai trăieşte un link activ */}
          {shareActive?.expires && (
            <span data-testid="share-expires" className="w-full text-2xs text-slate-500">
              {t('session.shareExpires', { time: fmtTs(shareActive.expires) })}
            </span>
          )}
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
            className="w-56 rounded-md bg-ink-800 px-2 py-1 text-sm ring-1 ring-ink-700"
          />
          <button aria-label={t('session.prevResult')} className="text-xs text-slate-400 hover:text-slate-200" onClick={() => searchRef.current?.findPrevious(search)}><ArrowUpIcon size={14} /></button>
          <button aria-label={t('session.nextResult')} className="text-xs text-slate-400 hover:text-slate-200" onClick={() => searchRef.current?.findNext(search)}><ArrowDownIcon size={14} /></button>
        </div>
      )}

      {/* închidere terminală de la gateway (4401/4403): motivul real + acţiunea, în loc de
          „reconnecting…" la nesfârşit sau de o pagină de login apărută fără explicaţie */}
      {wsDenied && (
        <div role="alert"
          className="flex flex-wrap items-center gap-2 border-b border-rose-500/30 bg-rose-950/40 px-4 py-2 text-sm">
          {wsDenied === 'auth' ? (
            <>
              <span className="font-medium text-rose-200">{t('session.authExpired')}</span>
              <span className="text-slate-300">{t('session.authExpiredBody')}</span>
              <Button variant="primary" size="sm"
                onClick={() => window.dispatchEvent(new Event('wt-unauth'))} className="ml-auto">
                {t('session.signInAgain')}
              </Button>
            </>
          ) : (
            <span className="text-rose-200">{t('session.wsForbidden')}</span>
          )}
        </div>
      )}

      {readOnly && !exited && (
        <div role="status" aria-live="polite" data-readonly-pill
          className="flex items-center gap-2 border-b border-ink-800 bg-ink-900/80 px-4 py-1.5 text-sm">
          <Badge tone="info" size="md"><EyeIcon size={12} /> {t('term.readonlyPill')}</Badge>
          <span className="min-w-0 truncate text-xs text-slate-400">{t('term.readonlyBody')}</span>
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
            <span className="wt-danger">
              {t('session.sessionLost')} ({exited.reason === 'gone_from_agent' ? t('session.serverRestarted') : exited.reason === 'session_gone' ? t('session.wsGone') : exited.reason}){t('session.historyBelow')}
            </span>
          )}
          {session.kind === 'telnet' && (
            <Button variant="primary" size="sm"
              onClick={reconnectTelnet}
              disabled={reconnecting}
              title={t('session.reconnectTelnetTooltip')} className="ml-auto">
              {reconnecting ? t('session.reconnectingBtn') : <><RefreshIcon size={12} /> {t('session.reconnect')}</>}
            </Button>
          )}
          <button
            onClick={() => setShowPlayer(true)}
            className={`inline-flex items-center gap-1 text-xs wt-link hover:underline${session.kind === 'telnet' ? '' : ' ml-auto'}`}
          >
            <PlayIcon size={10} /> {t('session.playHistory')}
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
        <TranscriptPlayer sid={session.id} title={title} onClose={() => setShowPlayer(false)}
          shareHostId={session.state === 'closed' ? session.host_id : undefined} />
      )}

      {/* terminal — click-dreapta deschide meniul propriu de acțiuni; oprim
          butonul 2 în capture ca xterm să nu-l trimită aplicației/tmux-ului
          (altfel ar apărea și meniul tmux peste al nostru) */}
      <div className="flex min-h-0 flex-1">
      <div
        className="relative min-h-0 min-w-0 flex-1 p-1.5"
        style={{ background: termBg }}
        // Drop de fişiere pe terminal → upload în directorul sesiunii + calea tastată la prompt.
        // Fără asta browserul NAVIGA la fişierul local şi omora SPA-ul (vezi FilePanel). Drag-ul
        // de text nu e atins (nu avea nicio tratare şi n-are nici acum).
        onDragEnter={(e) => {
          if (!canTransfer || !hasFiles(e.dataTransfer)) return
          e.preventDefault()
          dragDepth.current += 1
          setDropHover(true)
        }}
        onDragOver={(e) => {
          if (!canTransfer || !hasFiles(e.dataTransfer)) return
          e.preventDefault()
          e.dataTransfer.dropEffect = 'copy'
        }}
        onDragLeave={(e) => {
          if (!canTransfer || !hasFiles(e.dataTransfer)) return
          dragDepth.current = Math.max(0, dragDepth.current - 1)
          if (dragDepth.current === 0) setDropHover(false)
        }}
        onDrop={(e) => {
          if (!canTransfer || !hasFiles(e.dataTransfer)) return
          e.preventDefault()
          dragDepth.current = 0
          setDropHover(false)
          const files = Array.from(e.dataTransfer.files)
          if (files.length) void onTermDrop(files)
        }}
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
        {/* Hint sr-only PERMANENT: un user nevăzător care intră în terminal cu modul screen-reader
            OPRIT primea tăcere totală şi niciun indiciu că modul există. Îl anunţăm aici — vizibil
            doar pentru cititoarele de ecran — cum îl activează + cum iese (Ctrl+M). Vezi audit A4. */}
        <span className="sr-only">{t('session.srHint')}</span>
        {/* host căzut: card ne-modal sus, ÎNAINTEA terminalului în ordinea DOM — ajungi la butoane
            cu Tab din header fără ca terminalul să-şi piardă focusul singur (nu se autofocusează) */}
        <HostOfflineOverlay
          session={session}
          host={props.host}
          viaHost={props.viaHost}
          lostReason={exited && session.state !== 'closed' && exited.reason !== 'exited' && exited.reason !== 'session_gone'
            ? exited.reason : null}
          onOpenHost={props.onOpenHost}
          onReconnect={session.kind === 'telnet' ? reconnectTelnet : undefined}
          reconnecting={reconnecting}
        />
        <div ref={containerRef} role="application" aria-label={t('session.terminalAria')} className="h-full w-full" />

        {/* Sfaturi contextuale ancorate la terminal: paste/drop jos-stânga, iar unealta-bară
            sus-dreapta (spre butoanele din header). z-20 → sub overlay-ul de drop (z-30). */}
        {canTransfer && (
          <CoachTip
            tipKey={TIP_TERMINAL_PASTE}
            show={showPasteTip && tipPane}
            onDismiss={onPasteTipDismiss}
            icon={<PasteIcon />}
            title={t('tips.terminal.paste.title')}
            body={t('tips.terminal.paste.body')}
            className="absolute bottom-3 left-3"
          />
        )}
        <CoachTip
          tipKey={TIP_TOOLBAR}
          show={showToolbarTip && tipPane}
          icon={<ToolboxIcon />}
          title={t('tips.toolbar.title')}
          body={t('tips.toolbar.body')}
          className="absolute right-3 top-3"
        />

        {/* Drop pe terminal: spune UNDE aterizează fişierul (cwd din OSC 7 sau home) înainte să
            dai drumul. Butonul e o ţintă de drop alternativă: lăsat pe el, deschide panoul de
            fişiere, de unde alegi directorul şi re-tragi. */}
        {dropHover && (
          <div role="status"
            className="pointer-events-none absolute inset-1.5 z-30 flex flex-col items-center justify-center gap-2 rounded-md border-2 border-dashed border-sky-400/70 bg-ink-950/85 p-4 text-center backdrop-blur-sm">
            <span aria-hidden="true" className="wt-info"><UploadIcon size={22} /></span>
            <div className="max-w-full truncate font-mono text-sm text-slate-100" title={cwd ?? '~'}>
              {t('transfers.dropTo', { dir: cwd ?? '~' })}
            </div>
            <div className="text-xs text-slate-400">{cwd ? t('transfers.dropCwdNote') : t('transfers.dropHomeNote')}</div>
            <button type="button"
              className="pointer-events-auto mt-1 rounded-md bg-ink-800 px-3 py-1.5 text-xs text-slate-200 ring-1 ring-ink-600 hover:bg-ink-700"
              title={t('transfers.chooseFolderHint')}
              onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); e.dataTransfer.dropEffect = 'none' }}
              onDrop={(e) => {
                e.preventDefault(); e.stopPropagation()
                dragDepth.current = 0; setDropHover(false)
                if (!showFiles) toggleFiles()
              }}
              onClick={() => { setDropHover(false); if (!showFiles) toggleFiles() }}>
              {t('transfers.chooseFolder')}
            </button>
          </div>
        )}

        {/* Guardrail: comandă blocată (mesaj tranzitoriu) */}
        {guardMsg && (
          <div role="status" aria-live="assertive"
            className="wt-danger pointer-events-none absolute bottom-3 left-1/2 z-30 -translate-x-1/2 rounded-xl bg-ink-900/95 px-3 py-1.5 text-xs ring-1 ring-rose-500/30 shadow-lg">
            <span className="inline-flex items-center gap-1.5"><ShieldIcon size={13} />{guardMsg}</span>
          </div>
        )}

        {/* Guardrail: confirmare comandă periculoasă */}
        {cmdConfirm && (
          <div ref={cmdDialogRef} tabIndex={-1}
            role="alertdialog" aria-modal="true" aria-labelledby="wt-guard-title" aria-describedby="wt-guard-desc"
            // tabIndex=-1: un click pe fundal / pe text focalizează dialogul, nu <body> — altfel Escape-ul
            // următor ar fi „al panoului" şi „Cancel & clear" n-ar mai goli linia; selecţia textului
            // comenzii rămâne posibilă (audit P1, SV-04 review)
            className="absolute inset-0 z-30 grid place-items-center bg-ink-950/80 p-6 backdrop-blur-sm outline-none">
            <div className="w-full max-w-md rounded-xl bg-ink-900 p-4 ring-1 ring-ink-700 shadow-2xl">
              <div id="wt-guard-title" className="wt-warn flex items-center gap-2 text-sm font-semibold"><ShieldIcon />
                {' '}{cmdConfirm.opaque ? t('session.inputUnknownTitle') : cmdConfirm.echo ? t('session.echoUnknownTitle') : cmdConfirm.unknown ? t('session.peerUnknownTitle') : t('session.dangerousCommand')}</div>
              {cmdConfirm.cmd && !cmdConfirm.hits?.length && (
                <div className="mt-2 rounded-md bg-ink-950 px-3 py-2 font-mono text-compact text-slate-200 break-all ring-1 ring-ink-800">
                  {cmdConfirm.cmd}
                </div>
              )}
              {/* regula care a prins comanda — fleet şi panourile o arătau deja; fără ea nu ştiai
                  DE CE e „periculoasă" şi nici ce regulă să ajustezi în Setări → Securitate */}
              <div id="wt-guard-desc" className="mt-2 text-xs text-slate-400">
                {cmdConfirm.opaque ? t('session.inputUnknownDesc') : cmdConfirm.echo ? t('session.echoUnknownDesc') : cmdConfirm.unknown ? t('session.peerUnknownDesc') : cmdConfirm.hits?.length ? t('session.guardLinesIntro') : (<>
                  <span className="break-all font-mono text-slate-300">{t('session.guardRule', { pattern: cmdConfirm.pattern })}</span>
                  {' · '}{t('session.sureToRun')}
                </>)}
                {cmdConfirm.below && !cmdConfirm.unknown && <div className="mt-2" data-guard-below>{t('session.guardBelow')}</div>}
                {/* broadcast: FIECARE linie distinctă care atinge o regulă, cu panourile ei (review final 3.6.12) */}
                {!!cmdConfirm.hits?.length && (<>
                  {cmdConfirm.unknown && <div className="mt-2">{t('session.guardLinesIntro')}</div>}
                  <ul className="mt-2 max-h-48 space-y-1.5 overflow-y-auto">
                    {cmdConfirm.hits.map((h) => (
                      <li key={`${h.rule.pattern}\u0000${h.cmd}`} className="rounded-md bg-ink-950 px-3 py-2 ring-1 ring-ink-800">
                        <div className="font-mono text-compact text-slate-200 break-all">{h.cmd}</div>
                        <div className="mt-0.5 break-all">
                          <span className="font-mono text-slate-300">{t('session.guardRule', { pattern: h.rule.pattern })}</span>
                          {' · '}{t('session.guardInPanes', { panes: h.labels.join(', ') })}
                          {h.below && <>{' · '}{t('session.guardBelowHit')}</>}
                        </div>
                      </li>
                    ))}
                  </ul>
                  {!cmdConfirm.unknown && <div className="mt-2">{t('session.sureToRunAll')}</div>}
                </>)}
              </div>
              <div className="mt-4 flex justify-end gap-2">
                {/* focusul iniţial pe Anulează: acţiunea sigură e implicitul într-un dialog
                    de comandă periculoasă (acelaşi tipar ca ConfirmModal cu `danger`) */}
                <button
                  ref={cmdCancelBtnRef}
                  onClick={() => {
                    // regulă pe linia tastată: o golim; „nu pot verifica" / snippet reţinut: rămâne de editat
                    if (!cmdConfirm.unknown && !cmdConfirm.run && !cmdConfirm.below) (cmdConfirm.recheck ? sendAll : send)(clearLineSeq())
                    setCmdConfirm(null); termRef.current?.focus()
                  }}
                  className="rounded-md bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700"
                >{cmdConfirm.unknown || cmdConfirm.run || cmdConfirm.below ? t('common.cancel') : t('session.cancelClear')}</button>
                <Button variant="danger"
                  onClick={() => {
                    // broadcast, ORICE dialog: verdictul se reface ACUM; Enter-ul pleacă doar dacă e ok
                    // sau exact setul de confirmări văzut. Altfel escaladare: block → blocare, alt set →
                    // dialog nou, panou neverificabil (sau unul NOU faţă de cele acceptate) → „nu pot
                    // verifica" (review final 3.6.12, M; L-e; F5). Dialog fără broadcast → doar local (F2).
                    const c = cmdConfirm
                    setCmdConfirm(null)
                    if (c.localRecheck) {
                      // dialog „încă nu pot verifica" (un singur panou): linia re-judecată acum
                      const lv = c.localRecheck()
                      // tasta de trimitere reţinută pleacă EA (`\x0f` aduce istoricul, `a` încheie un `ESC a`
                      // al cărui Escape a plecat deja: un `\r` după el n-ar rula nimic — re-review SV-01)
                      if (localRunDecision(lv) === 'send') send(c.run ?? c.submit ?? '\r')
                      else if (lv.kind === 'rule') applyRule(lv.rule, lv.cmd, c.run, undefined, undefined, lv.below === true, c.submit)
                      termRef.current?.focus()
                      return
                    }
                    const v = c.recheck ? c.recheck() : null
                    const d = runDecision(v, c.hits ?? [], c.unknown ? (c.unreadable ?? []) : null)
                    if (d === 'local') send(c.run ?? c.submit ?? '\r')
                    else if (d === 'send') sendAll(c.run ?? c.submit ?? '\r')
                    else if (v?.kind === 'rule') applyRule(v.rule, v.cmd, c.run, v.hits, c.recheck, false, c.submit)
                    else if (v && v.kind !== 'ok') setCmdConfirm({ cmd: c.cmd, pattern: '', unknown: true, run: c.run, submit: c.submit, hits: v.hits, recheck: c.recheck, unreadable: v.unreadable, opaque: c.opaque })
                    termRef.current?.focus()
                  }}>
                  {cmdConfirm.unknown && cmdConfirm.recheck ? t('session.runInAllPanes') : t('session.run')}</Button>
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
              <div className="grid h-12 w-12 place-items-center rounded-full bg-ink-800 text-slate-300" aria-hidden="true"><LockIcon size={22} /></div>
              <div id="wt-lock-title" className="text-base font-semibold text-slate-100">{t(lockTextKeys(lockReason).title)}</div>
              <div id="wt-lock-desc" className="text-compact leading-relaxed text-slate-400">
                {t(lockTextKeys(lockReason).desc)}
              </div>
              {lockErr && <div className="text-xs wt-danger">{lockErr}</div>}
              <Button variant="primary" size="lg" ref={unlockBtnRef} onClick={reauth} disabled={unlocking} className="mt-1">
                {unlocking ? t('session.verifying') : <><KeyIcon size={14} /> {t(unlockLabelKey(stepupPrompt(unlockCode || null, props.stepupMethod, props.webauthn ?? true)))}</>}
              </Button>
            </div>
          </div>
        )}
        {tabFocusMode && (
          <div className="wt-accent pointer-events-none absolute right-3 top-3 z-10 rounded-full bg-black/75 px-3 py-1 text-xs">
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
        {/* cortina de PAUZĂ a tastaturii (socket închis, sesiune vie): terminalul rămâne
            lizibil/selectabil (pointer-events-none), dar e vizibil îngheţat; la fiecare tastă
            pierdută chip-ul clipeşte (vezi `send`). Fără asta prompt + cursor arătau normal şi
            `rm -rf build && make` + Enter dispăreau în tăcere până la 80 s. */}
        {inputPaused && (
          <div
            role="status"
            aria-live="assertive"
            className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center bg-black/40"
          >
            <span className={`flex items-center gap-2 rounded-xl bg-ink-900/95 px-3 py-2 text-xs text-amber-200 shadow-lg ring-1 transition-shadow ${
              inputFlash ? 'ring-2 ring-amber-400 shadow-amber-400/40' : 'ring-amber-500/30'}`}>
              <span
                className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-amber-500/30 border-t-amber-400"
                aria-hidden="true"
              />
              {everOpenRef.current ? t('session.reconnecting') : t('session.connecting')} · {t('session.inputPaused')}
            </span>
          </div>
        )}
        {/* după reconectare: câte taste s-au pierdut cât eram deconectaţi */}
        {inputNotice && (
          <div role="status" aria-live="polite"
            className="pointer-events-none absolute bottom-3 left-1/2 z-30 -translate-x-1/2 rounded-xl bg-ink-900/95 px-3 py-1.5 text-xs text-amber-200 ring-1 ring-amber-500/30 shadow-lg">
            <span className="inline-flex items-center gap-1.5"><KeyboardIcon size={12} />{inputNotice}</span>
          </div>
        )}
        {/* feedback de copiere vizibil peste terminal — pe mobil butonul „✓"
            din toolbar e ascuns, deci fără asta copierea pare că nu face nimic */}
        {copied && (
          <div role="status" aria-live="polite"
            className="wt-good pointer-events-none absolute bottom-3 left-1/2 z-10 -translate-x-1/2 rounded-full bg-black/75 px-3 py-1 text-xs">
            <span className="inline-flex items-center gap-1">{t('session.copied')} <CheckIcon size={12} /></span>
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
        <FilePanel key={filesNonce} host={props.host} sessionId={session.id} onClose={() => setShowFiles(false)}
          overlay={narrowPane} revealPath={filesReveal} initialAction={filesAction} />
      )}
      {showGit && props.host && (
        <GitPanel host={props.host} sessionId={session.id} onClose={() => setShowGit(false)} overlay={narrowPane} />
      )}
      {showForwards && props.host && (
        <ForwardsPanel host={props.host} onClose={() => setShowForwards(false)} overlay={narrowPane}
          onOpenSession={(sid) => { setShowForwards(false); props.onOpenSession?.(sid) }} />
      )}
      {showDocker && props.host && (
        <DockerPanel host={props.host} onClose={() => setShowDocker(false)} overlay={narrowPane}
          onOpenContainerShell={(c) => { setShowDocker(false); props.onOpenContainerShell?.(props.host!, c) }}
          onOpenContainerLogs={(c, name) => { setShowDocker(false); props.onOpenContainerLogs?.(props.host!, c, name) }} />
      )}
      {showServices && props.host && (
        <ServicesPanel host={props.host} onClose={() => setShowServices(false)} overlay={narrowPane}
          onJournal={(u) => { setShowServices(false); props.onJournal?.(props.host!, u) }} />
      )}
      {showAi && props.host && (
        <Suspense fallback={null}>
          <AiToolsPanel host={props.host} onClose={() => setShowAi(false)} overlay={narrowPane}
            projectDir={cwd ?? undefined} />
        </Suspense>
      )}
      {showToolbox && props.host && (
        <ToolboxPanel host={props.host} onClose={() => setShowToolbox(false)} overlay={narrowPane}
          onOpen={(h, cid) => { setShowToolbox(false); props.onOpenConnection?.(h, cid) }} />
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
              // clamp mai generos la jos: meniul are acum mai multe rânduri (+ submeniul „Fişiere”)
              left: Math.min(ctxMenu.x, window.innerWidth - 216),
              top: Math.max(8, Math.min(ctxMenu.y, window.innerHeight - 360)),
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
            {isLive && (
              <MoreItem onClick={() => { openPastePicker(); setCtxMenu(null) }}>
                <PasteIcon /> {t('paste.fromHistory')}
              </MoreItem>
            )}
            <MoreItem onClick={() => { termRef.current?.selectAll(); setCtxMenu(null) }}>
              <span className="inline-block w-4" aria-hidden="true" /> {t('session.selectAll')}
            </MoreItem>
            {/* Clear terminal: trimite Ctrl-L (\x0c), NU `term.clear()` local — pe tmux serverul
                rejoacă bufferul la reconectare, deci un clear local reapare; Ctrl-L e ce vrea
                utilizatorul şi e inofensiv la prompt sau într-un editor. */}
            {isLive && (
              <MoreItem onClick={() => { send('\x0c'); termRef.current?.focus(); setCtxMenu(null) }}>
                <span className="inline-block w-4" aria-hidden="true" /> {t('session.clearTerminal')}
              </MoreItem>
            )}
            {/* „Deschide calea": doar când selecţia arată fără echivoc a cale (vezi lib/termpath) */}
            {(() => {
              const sel = termRef.current?.hasSelection() ? (termRef.current.getSelection() || '').trim() : ''
              return sel && looksLikePath(sel) ? (
                <MoreItem onClick={() => { void openSelectedPath(sel); setCtxMenu(null) }}>
                  <FilesIcon /> {t('session.openPathInFiles')}
                </MoreItem>
              ) : null
            })()}
            {props.host && (
              <FilesSubmenu
                subtitle={cwd ? t('session.ctxFilesInDir', { dir: cwd }) : t('session.ctxFilesHomeFallback')}
                onOpenChange={(o) => { submenuOpenRef.current = o }}
                onCloseMenu={() => setCtxMenu(null)}
                items={[
                  { key: 'open', icon: <FilesIcon />, label: t('session.ctxFilesOpenHere'), onClick: () => revealFiles() },
                  { key: 'upload', icon: <UploadIcon />, label: t('session.ctxFilesUpload'), onClick: () => uploadInputRef.current?.click() },
                  { key: 'download', icon: <DownloadIcon />, label: t('session.ctxFilesDownload'), onClick: () => { void (async () => revealFiles(await filesAnchorDir()))() } },
                  { key: 'newfile', icon: <FileIcon />, label: t('session.ctxFilesNewFile'), onClick: () => { void (async () => revealFiles(await filesAnchorDir(), 'newFile'))() } },
                  { key: 'newfolder', icon: <FolderIcon />, label: t('session.ctxFilesNewFolder'), onClick: () => { void (async () => revealFiles(await filesAnchorDir(), 'newFolder'))() } },
                ]}
              />
            )}
            {/* AI tools: CLAUDE.md / sub-agenţi / skill-uri pentru proiectul din cwd (OSC 7) —
                acelaşi user de OS ca harness-ul care le citeşte. Doar prin agent (API-ul fs). */}
            {props.host && (props.host.connection_type ?? 'agent') === 'agent' && (
              <MoreItem onClick={() => { closeOthers('ai'); setShowAi(true); setCtxMenu(null) }}>
                <span className="grid h-4 w-4 place-items-center" aria-hidden="true"><SparkleIcon /></span> {t('session.ctxAiTools')}
              </MoreItem>
            )}
            <MoreItem onClick={() => { setShowSearch(true); setCtxMenu(null) }}>
              <SearchIcon /> {t('session.searchScrollbackMenu')}
            </MoreItem>
            <MoreItem onClick={() => { openLinks(); setCtxMenu(null) }}>
              <ExternalLinkIcon /> {t('session.links')}
            </MoreItem>
            {props.onSplitView && (
              <MoreItem onClick={() => { props.onSplitView!(); setCtxMenu(null) }}>
                <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor"
                  strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
                  <rect x="1.5" y="2.5" width="13" height="11" rx="1.5" /><path d="M8 2.5v11" />
                </svg> {t('session.addSplit')}
              </MoreItem>
            )}
          </div>
        </>
      )}

      {/* input ascuns pentru „Încarcă aici…": stă la rădăcină (nu în meniu) ca să supravieţuiască
          închiderii meniului — altfel dialogul de fişiere al sistemului s-ar pierde când se demontează */}
      {isLive && props.host && (
        <input ref={uploadInputRef} type="file" multiple className="hidden" data-testid="wt-ctx-upload"
          onChange={(e) => { if (e.target.files?.length) void uploadHere(Array.from(e.target.files)); e.target.value = '' }} />
      )}
      {/* cale-fişier selectată → editor Monaco (aceeaşi componentă ca-n panou, deci siguranţa la
          fişiere mari + salvarea atomică vin gratis) */}
      {editorFile && props.host && (
        <Suspense fallback={null}>
          <FileEditor hostId={props.host.id} path={editorFile.path} name={editorFile.name}
            canWrite={canOn(perms, props.host.id, 'files.write')}
            onClose={() => setEditorFile(null)} onSaved={() => { /* fişier salvat pe host; nimic de reîmprospătat aici */ }} />
        </Suspense>
      )}

      <StatusBar session={session} host={props.host} rtt={isLive ? rtt : null} cwd={cwd} />
      {isLive && <MobileKeybar onKeys={(k) => userInput(k)} onPaste={paste} backend={props.host?.backend} />}
    </div>
  )
}

/** Lista de URL-uri din scrollback. Componentă separată pentru focus-trap: înainte, Escape
    mergea doar dacă focusul ajunsese în dialog — dar focusul rămânea în xterm, unde Escape se
    ducea în shell, iar Tab circula prin pagina de sub scrim. */
function LinksDialog(props: { links: string[]; onClose: () => void; onCopy: (u: string) => void }) {
  const { t } = useI18n()
  const ref = useRef<HTMLDivElement>(null)
  useFocusTrap(ref, props.onClose)
  return (
    <div role="presentation" className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
         onClick={(e) => { if (e.target === e.currentTarget) props.onClose() }}>
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby="wt-links-title"
           className="glass flex max-h-[80vh] w-full max-w-lg flex-col overflow-hidden rounded-2xl">
        <div className="flex items-center justify-between border-b border-ink-800 px-4 py-3">
          <h2 id="wt-links-title" className="text-sm font-semibold">{t('session.links')}{props.links.length ? ` (${props.links.length})` : ''}</h2>
          <button onClick={props.onClose} aria-label={t('common.close')}
                  className="rounded-md px-2 py-1 text-slate-400 hover:bg-ink-800"><CloseIcon size={14} /></button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto p-2">
          {props.links.length === 0
            ? <p className="px-2 py-6 text-center text-sm text-slate-500">{t('session.linksEmpty')}</p>
            : <ul className="space-y-1">
                {props.links.map((u, i) => (
                  <li key={i} className="flex items-center gap-1">
                    <a href={u} target="_blank" rel="noopener noreferrer" title={u}
                       className="wt-link min-w-0 flex-1 truncate rounded-md px-2 py-1.5 text-sm hover:bg-ink-800">
                      {u}
                    </a>
                    <button title={t('session.copyLink')} aria-label={t('session.copyLink')}
                            onClick={() => props.onCopy(u)}
                            className="shrink-0 rounded-md px-2 py-1.5 text-slate-400 hover:bg-ink-800">
                      <CopyIcon />
                    </button>
                  </li>
                ))}
              </ul>}
        </div>
      </div>
    </div>
  )
}

const ToolButton = forwardRef<HTMLButtonElement, {
  title: string
  /** numele accesibil, când butonul are text VIZIBIL (ex. „A−"): WCAG 2.5.3 (label in name) cere ca
      numele să CONŢINĂ textul vizibil — altfel cine dă comenzi vocale („click A minus") nu-l găseşte.
      Implicit = `title`. `title` rămâne tooltip-ul. */
  name?: string
  active?: boolean
  /** comutator (panou deschis/închis): `aria-pressed` = `active` */
  toggle?: boolean
  /** permisiune lipsă pe ACEST host (FL-09): dezactivat, cu motivul în `title` */
  disabled?: boolean
  onClick: () => void
  children: React.ReactNode
} & Pick<React.ButtonHTMLAttributes<HTMLButtonElement>, 'aria-expanded' | 'aria-controls' | 'aria-haspopup'>>(
  function ToolButton({ title, name, active, toggle, disabled, onClick, children, ...aria }, ref) {
    // IconButton-ul design system-ului (label = aria-label + title); starea „activ" = varianta
    // `active` a primitivei (3.6.3, U24), nu clase de culoare suprapuse peste ghost
    return (
      <IconButton
        ref={ref}
        type="button"
        label={name ?? title}
        title={title}
        active={!!active}
        aria-pressed={toggle ? !!active : undefined}
        disabled={disabled}
        {...aria}
        onMouseDown={(e) => e.preventDefault()} // păstrează focusul (și selecția) în terminal
        onClick={onClick}
      >
        {children}
      </IconButton>
    )
  })

/** Un rând din dezvăluirea „Mai multe" (3.6.3, U23): buton SIMPLU — nu `menuitem`. Panoul e un
    disclosure (trigger cu aria-expanded/aria-controls, Tab între butoane, Escape închide şi întoarce
    focusul pe trigger), deci n-are voie să promită comportamentul de meniu ARIA (săgeţi, roving).
    `wt-touch`: 44px sub pointer grosier — pe telefon panoul e o foaie cu acţiuni etichetate. */
function MoreItem(props: { onClick: () => void; disabled?: boolean; title?: string; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onMouseDown={(e) => e.preventDefault()}
      onClick={props.onClick}
      disabled={props.disabled}
      title={props.title}
      className="wt-touch flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-sm text-slate-300 hover:bg-ink-800 disabled:cursor-default disabled:opacity-40 disabled:hover:bg-transparent"
    >
      {props.children}
    </button>
  )
}

/** Submeniul „Fişiere ▸" din meniul contextual al terminalului: un flyout cu acţiuni de fişiere.
    Flip la stânga lângă marginea din dreapta; tastatură (→/Enter deschide, ↑/↓ între iteme,
    ←/Esc închide), roving focus, închidere la mouse-leave. role=menu/menuitem, ţinte ≥24px. */
function FilesSubmenu(props: {
  subtitle: string
  items: { key: string; icon?: React.ReactNode; label: string; onClick: () => void }[]
  onCloseMenu: () => void
  onOpenChange?: (open: boolean) => void
}) {
  const { t } = useI18n()
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)       // roving focus (tastatură)
  const [flip, setFlip] = useState(false)       // deschide spre stânga lângă marginea din dreapta
  const btnRef = useRef<HTMLButtonElement>(null)
  const itemRefs = useRef<(HTMLButtonElement | null)[]>([])
  const closeTimer = useRef<ReturnType<typeof setTimeout> | 0>(0)
  // raportăm starea sus printr-un ref (fără să re-rulăm efectul la fiecare render al părintelui)
  const onOpenChangeRef = useRef(props.onOpenChange)
  onOpenChangeRef.current = props.onOpenChange
  useEffect(() => { onOpenChangeRef.current?.(open); return () => onOpenChangeRef.current?.(false) }, [open])

  // la deschidere: decide flip după spaţiul din dreapta + focus pe primul item (roving)
  useEffect(() => {
    if (!open) return
    const r = btnRef.current?.getBoundingClientRect()
    if (r) setFlip(r.right + 212 > window.innerWidth)
    setActive(0)
    const id = requestAnimationFrame(() => itemRefs.current[0]?.focus())
    return () => cancelAnimationFrame(id)
  }, [open])
  useEffect(() => { if (open) itemRefs.current[active]?.focus() }, [active, open])

  const show = () => { clearTimeout(closeTimer.current); setOpen(true) }
  const hideSoon = () => { closeTimer.current = setTimeout(() => setOpen(false), 180) }  // gap mic între ancoră şi flyout
  const choose = (fn: () => void) => { setOpen(false); fn(); props.onCloseMenu() }

  const onKey = (e: React.KeyboardEvent) => {
    if (!open) {
      if (e.key === 'ArrowRight' || e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setOpen(true) }
      return
    }
    const n = props.items.length
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => (a + 1) % n) }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => (a - 1 + n) % n) }
    else if (e.key === 'ArrowLeft' || e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); setOpen(false); btnRef.current?.focus() }
    else if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); choose(props.items[active].onClick) }
  }

  // Handlerele stau pe BUTOANE (native-interactive) şi pe flyout-ul cu role=menu — nu pe un div
  // „gol", ca să nu declanşăm avertismentele jsx-a11y de element static interactiv.
  return (
    <div className="relative">
      <button
        ref={btnRef}
        role="menuitem"
        aria-haspopup="menu"
        aria-expanded={open}
        onMouseEnter={show}
        onMouseLeave={hideSoon}
        onMouseDown={(e) => e.preventDefault()}
        // deschide (nu comută): hover-ul l-a putut deschide deja, iar un click care l-ar închide
        // la loc e şi derutant, şi face flyout-ul imposibil de acţionat cu mouse-ul (hover→click)
        onClick={() => show()}
        onKeyDown={onKey}
        className="flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-sm text-slate-300 hover:bg-ink-800"
      >
        <FilesIcon /> <span className="flex-1">{t('session.ctxFilesMenu')}</span>
        <span aria-hidden="true" className="text-slate-500"><ChevronIcon size={12} /></span>
      </button>
      {open && (
        <div
          role="menu"
          aria-label={t('session.ctxFilesMenu')}
          tabIndex={-1}
          onMouseEnter={show}
          onMouseLeave={hideSoon}
          className={`absolute top-0 z-50 w-52 rounded-xl border border-ink-700 bg-ink-900 p-1 shadow-2xl outline-none ${flip ? 'right-full mr-1' : 'left-full ml-1'}`}
        >
          <div className="truncate px-2.5 py-1 text-2xs text-slate-500" title={props.subtitle}>{props.subtitle}</div>
          {props.items.map((it, i) => (
            <button
              key={it.key}
              ref={(el) => { itemRefs.current[i] = el }}
              role="menuitem"
              tabIndex={-1}
              onMouseEnter={() => setActive(i)}
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => choose(it.onClick)}
              onKeyDown={onKey}
              className="flex w-full items-center gap-2 rounded-md px-2.5 py-2 text-left text-sm text-slate-300 hover:bg-ink-800"
            >
              {it.icon ?? <span className="inline-block w-4" aria-hidden="true" />} {it.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
