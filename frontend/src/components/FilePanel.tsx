import { lsGet, lsSet } from '../lib/storage'
import { lazy, Suspense, useCallback, useEffect, useId, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import { errText, api, Host } from '../lib/api'
import { copyText, readText } from '../lib/clipboard'
import { getCwd } from '../lib/cwd'
import { useI18n } from '../lib/i18n'
import { SHEET_CLS, useMediaQuery } from '../lib/sheet'
import { useDrawer } from '../lib/useDrawer'
import SheetBar from './SheetBar'
import { cancelUpload, dismissUpload, isUploadBusy, startUpload as engineStart, takeFilesDir } from '../lib/uploads'
import { BulkItem, startArchiveDownload, startDownload, startDownloads } from '../lib/downloads'
import { isActive, sizeKnown, uploadStore } from '../lib/uploadStore'
import { fmtBytes } from '../lib/uploads'
import { uiLocale } from '../lib/tz'
import {
  EMPTY_SELECTION, Selection, allState, isListKeyTarget, keyTargetOf, previewNames, prune, rangeTo, toggleAll, toggleKey, visibleSelected,
} from '../lib/selection'
import { ArrowLeftIcon, ArrowRightIcon, ArrowsLeftRightIcon, CheckIcon, ChevronIcon, LockIcon, ChevronDownIcon, ChevronUpIcon, CloseIcon, CopyIcon, DownloadIcon, FileIcon, FilePlusIcon, FolderIcon, LevelUpIcon, LinkIcon, MoreIcon, PencilIcon, PlusIcon, RefreshIcon, RenameIcon, TerminalPromptIcon, TrashIcon, UploadIcon } from './Icons'
import CopyToHostDialog, { CopyItem } from './CopyToHostDialog'
import WriteDeniedBanner, { PendingFile } from './WriteDeniedBanner'
import FileMenu, { MenuItem } from './FileMenu'
import { clearDenied, deniedStore, errIsWriteDenied, isDenied, isWriteDenied, markDenied } from '../lib/rootmove'
import { resolveHome, typeIntoOutcome } from '../lib/transfers'
import { startCopy } from '../lib/copyjobs'
import { notifyToast } from '../lib/notify'
import { fmt, matchFilesShortcut } from '../lib/shortcuts'
import {
  EMPTY_HISTORY, NavHistory, TYPE_JUMP_MS, baseName, canBack, canForward, cdCommand, completePath, crumbs, filesGate,
  gateMenuItems, histPush, histStep, mkdirRefusal, parentOf, physicalPathHint, splitForCompletion, targetPath, typeJump,
  underRefused,
} from '../lib/filesNav'
import { usePerms } from '../lib/perms'
import { Button, IconButton } from './ui'

// CodeMirror e greu → lazy: intră doar când deschizi un fișier
const FileEditor = lazy(() => import('./FileEditor'))

interface Entry {
  name: string
  dir: boolean
  link: boolean
  size: number
  mtime: number
  mode: number
}
interface Listing {
  path: string
  parent: string
  entries: Entry[]
  truncated: boolean
}

type SortKey = 'name' | 'size' | 'mtime'

// sortarea aleasă se ţine minte (3.6.14): `name:1`, `mtime:0`… — orice altceva = implicit
const SORT_KEY = 'wt_files_sort'
function loadSort(): { key: SortKey; asc: boolean } {
  const m = /^(name|size|mtime):([01])$/.exec(lsGet(SORT_KEY) ?? '')
  return m ? { key: m[1] as SortKey, asc: m[2] === '1' } : { key: 'name', asc: true }
}
// lăţimea coloanei de pe desktop (3.6.14): trasă de marginea stângă, persistată pe dispozitiv
const WIDTH_KEY = 'wt_files_w'
const W_MIN = 260, W_DEF = 320, W_MAX = 900
const clampW = (w: number) => Math.round(Math.max(W_MIN, Math.min(W_MAX,
  typeof window !== 'undefined' ? Math.max(W_MIN, window.innerWidth - 360) : W_MAX, w)))
function loadWidth(): number {
  const v = Number(lsGet(WIDTH_KEY))
  return v >= W_MIN && v <= W_MAX ? v : W_DEF
}
/** câmp de text (acolo tastele şi focusul sunt ale lui, nu ale listei) */
const isTextField = (el: Element | null) =>
  !!el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || (el as HTMLElement).isContentEditable)

/** ţinta unui meniu: un rând, zona goală a listei (directorul curent) sau butonul flotant „+" */
/** `dir` = directorul LISTAT când s-a deschis meniul: toate acţiunile pornesc de la el (review
    3.6.15, M2), nu de la `listing.path` din clipa click-ului — follow-cwd îl poate fi schimbat. */
type MenuState =
  | { kind: 'row'; entry: Entry; dir: string; x: number; y: number; sheet: boolean }
  | { kind: 'dir'; dir: string; x: number; y: number; sheet: boolean }
  | { kind: 'new'; dir: string; x: number; y: number; sheet: boolean }
/** un rând + directorul în care a fost ales (confirmarea de ştergere, redenumirea) */
type Target = Entry & { at: string }

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(0)}K`
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)}M`
  return `${(n / 1024 ** 3).toFixed(1)}G`
}
// mode octal → rwxr-xr-x (ajută la „de ce n-am voie să scriu aici")
function fmtMode(m: number): string {
  const t = ['---', '--x', '-w-', '-wx', 'r--', 'r-x', 'rw-', 'rwx']
  return t[(m >> 6) & 7] + t[(m >> 3) & 7] + t[m & 7]
}
function fmtMtime(s: number): string {
  const d = new Date(s * 1000)
  const diff = Date.now() - d.getTime()
  if (diff >= 0 && diff < 86400000)
    return d.toLocaleTimeString(uiLocale(), { hour: '2-digit', minute: '2-digit' })
  return d.toLocaleDateString(uiLocale(), { day: '2-digit', month: 'short' })
}
function join(dir: string, name: string): string {
  return `${dir.replace(/\/$/, '')}/${name}`
}

// fișier de încărcat + calea relativă la directorul curent (pentru foldere:
// „sub/dir/fisier.txt”; pentru fișiere simple, doar numele)
interface UpItem { file: File; rel: string }

// Motorul de upload (felii, resync, CRC, watchdog, reluare) stă în lib/uploads.ts — aici doar
// alegem ce şi unde urcăm şi arătăm rândurile acestui host din uploadStore.
// Traversează un FileSystemEntry (dintr-un drop) și adună fișierele cu calea lor
// relativă — așa merge drag&drop pe FOLDERE, nu doar pe fișiere izolate.
async function readEntry(entry: any, prefix: string, out: UpItem[]): Promise<void> {
  if (entry.isFile) {
    const file: File = await new Promise((res, rej) => entry.file(res, rej))
    out.push({ file, rel: prefix + entry.name })
  } else if (entry.isDirectory) {
    const reader = entry.createReader()
    const all: any[] = []
    await new Promise<void>((res) => {
      const step = () => reader.readEntries((batch: any[]) => {
        if (!batch.length) return res()
        all.push(...batch); step()
      }, () => res())
      step()
    })
    for (const e of all) await readEntry(e, prefix + entry.name + '/', out)
  }
}

export default function FilePanel(props: {
  host: Host; sessionId: string; onClose: () => void; overlay?: boolean; embed?: boolean
  /** cale la care panoul navighează la MONTARE, oprind follow-ul (din meniul contextual al
      terminalului: „Deschide calea" pe un director, „Descarcă…", „Fişier/Dosar nou” ancorate pe cwd).
      Absent → comportament normal (urmăreşte cwd-ul sesiunii). */
  revealPath?: string
  /** după ce s-a încărcat directorul, declanşează modul inline existent de fişier/dosar nou —
      refolosim UI-ul + `doNewFile`/`doMkdir`, fără să duplicăm nimic. */
  initialAction?: 'newFile' | 'newFolder'
}) {
  const { t } = useI18n()
  const isAgent = !props.host.connection_type || props.host.connection_type === 'agent'
  const asideRef = useRef<HTMLElement>(null)
  // FL-09 (audit 2026-10-17): gating COSMETIC pe permisiuni — serverul refuză oricum (403
  // authz.denied), dar un Viewer nu trebuie să afle ABIA după gest. Dezactivat cu motivul când are
  // permisiunea pe alt host, ascuns când n-o are nicăieri (docs/design/DESIGN-SYSTEM.md „Hide vs
  // disable"); drop-ul, foaia de pe telefon şi tastele (Ctrl+U, F2, F7, Alt+N, Delete) trec prin
  // ACELEAŞI porţi: refuz cu toast, înainte de orice cerere.
  const perms = usePerms()
  const gate = useMemo(() => filesGate(perms, props.host.id), [perms, props.host.id])
  const mayWrite = gate.write === 'ok', mayDelete = gate.del === 'ok'
  const needsWrite = t('files.needsWrite'), needsDelete = t('files.needsDelete')
  // id-uri per instanţă: două panouri pe aceeaşi pagină (host + sesiune, split) nu au voie să-şi
  // dubleze id-urile pentru aria-describedby (axe duplicate-id-aria)
  const reasonId = useId()
  const needsWriteId = `${reasonId}-needs-write`, needsDeleteId = `${reasonId}-needs-delete`
  /** poarta unei acţiuni de scriere / ştergere: false + toast dacă rolul n-o permite pe hostul ăsta */
  const writeAllowed = () => { if (mayWrite) return true; notifyToast(needsWrite, 'warn'); return false }
  const deleteAllowed = () => { if (mayDelete) return true; notifyToast(needsDelete, 'warn'); return false }
  // Back-ul de Android în foaie (3.6.14): întâi înapoi prin directoarele vizitate, abia la capăt
  // închide panoul. Prin ref: funcţia vede istoricul curent, iar useDrawer o cheamă din popstate.
  const backRef = useRef<() => boolean>(() => false)
  const drawer = useDrawer(asideRef, props.onClose, !props.embed, () => backRef.current())
  // touch fără hover (telefon / tabletă): „⋯" de 44px pe rând în loc de cele patru pictograme de 24px,
  // meniul ca foaie de jos, butonul flotant „+"
  const touchUI = useMediaQuery('(hover: none)')
  // `embed`: panoul umple un tab din pagina hostului (full-width, fără drawer/scrim/close).
  // Altfel: pe pane-uri înguste (split pe iPad) e DRAWER peste terminal, nu coloană statică —
  // o coloană de 320px într-un pane de 240px strivește terminalul la ~0px.
  // Coloana statică de lângă terminal (desktop) se poate lăţi trăgând de marginea stângă (3.6.14).
  const columnMode = !drawer.sheet && !props.embed && !props.overlay
  const [colW, setColW] = useState(loadWidth)
  const asideCls = drawer.sheet ? SHEET_CLS : props.embed
    ? 'flex h-full w-full min-h-0 flex-col bg-ink-900'
    : 'fixed inset-y-0 right-0 z-40 flex w-[90vw] max-w-sm flex-col border-l border-ink-800 bg-ink-900 shadow-2xl outline-none'
    + (props.overlay ? '' : ' sm:relative sm:inset-auto sm:z-auto sm:w-80 sm:max-w-none sm:shrink-0 sm:shadow-none')
  // pe rânduri: dimensiunea şi data sub nume (foaie / drawer îngust), nu în dreapta
  const compact = drawer.sheet || !!props.overlay
  const scrimCls = props.embed ? 'hidden' : 'fixed inset-0 z-30 bg-black/60' + (props.overlay ? '' : ' sm:hidden')
  const [listing, setListing] = useState<Listing | null>(null)
  const [path, setPath] = useState('~')
  const [error, setError] = useState('')
  const [failedPath, setFailedPath] = useState<string | null>(null)   // listarea a picat → Retry
  const [busy, setBusy] = useState(false)
  // starea upload-urilor stă în uploadStore (nivel de modul), NU în componentă: transferul
  // supravieţuieşte închiderii panoului, iar redeschiderea îl arată în mers, cu cancel funcţional
  const uploadsAll = useSyncExternalStore(uploadStore.subscribe, uploadStore.snapshot)
  // doar job-urile acestui host; orfanii (după reload, fără File) trăiesc numai în bara globală
  const uploads = useMemo(
    () => [...uploadsAll.values()].filter((j) => j.hostId === props.host.id && j.state !== 'orphan'),
    [uploadsAll, props.host.id])
  const [overwrite, setOverwrite] = useState<{ items: UpItem[]; count: number } | null>(null)
  // 3.6.9: o scriere refuzată (userul agentului nu poate scrie aici) → bannerul cu cele trei ieşiri
  const [denied, setDenied] = useState<{ dir: string; message: string; pending: PendingFile[] } | null>(null)
  useSyncExternalStore(deniedStore.subscribe, deniedStore.snapshot)
  const [drag, setDrag] = useState(false)
  // drop ţintit pe un RÂND de director: fişierele intră acolo, nu în directorul afişat
  const [dropRow, setDropRow] = useState<string | null>(null)
  const [editing, setEditing] = useState<{ path: string; name: string } | null>(null)
  // urmărește cwd-ul din terminal (OSC 7). Navigarea manuală îl oprește, ca să
  // poți explora în altă parte fără să fii „tras” înapoi la fiecare comandă.
  const [follow, setFollow] = useState(true)
  const [filter, setFilter] = useState('')
  // persistat (audit 3.6.3): cine lucrează cu dotfile-uri nu mai reapasă „.*" la fiecare deschidere
  const [showHidden, setShowHiddenRaw] = useState(() => lsGet('wt_files_hidden') === '1')
  const setShowHidden = (f: (v: boolean) => boolean) => setShowHiddenRaw((v) => { const n = f(v); lsSet('wt_files_hidden', n ? '1' : '0'); return n })
  const [sort, setSortRaw] = useState<{ key: SortKey; asc: boolean }>(loadSort)
  const setSort = (f: (s: { key: SortKey; asc: boolean }) => { key: SortKey; asc: boolean }) =>
    setSortRaw((s) => { const n = f(s); lsSet(SORT_KEY, `${n.key}:${n.asc ? 1 : 0}`); return n })
  // istoricul înapoi / înainte AL ACESTUI panou (lib/filesNav.ts); `histMoveRef` = pasul cerut de
  // ‹ / › / Back, aplicat abia când listarea ţintei reuşeşte
  const [hist, setHist] = useState<NavHistory>(EMPTY_HISTORY)
  const histRef = useRef(hist)
  histRef.current = hist
  const histMoveRef = useRef<NavHistory | null>(null)
  // câmpul de cale apare doar la editare (click pe ultimul segment / ✎ / Ctrl+L); altfel firimituri
  const [editPath, setEditPath] = useState(false)
  const [pathDraft, setPathDraft] = useState('')
  const [completion, setCompletion] = useState<{ candidates: string[]; more: number; none: boolean } | null>(null)
  const completeCache = useRef(new Map<string, string[]>())
  const completeSeq = useRef(0)
  const noProgressRef = useRef<string | null>(null)
  const [menu, setMenu] = useState<MenuState | null>(null)
  // focusul cerut după o acţiune: pe listă, cu rândul `name` (sau indexul `idx`) selectat — aplicat
  // după listarea cu numărul `seq` (0 = imediat). Vezi efectul de după `view`.
  const wantFocusRef = useRef<{ name?: string; idx?: number; seq: number } | null>(null)
  const doneSeqRef = useRef(0)
  const [focusTick, setFocusTick] = useState(0)
  const typeBufRef = useRef<{ s: string; t: number }>({ s: '', t: 0 })
  // dublu-click / dublu-tap făcut de noi (click-uri pe acelaşi rând în <450 ms): merge identic cu
  // mouse şi deget. `navGuardRef`: după ce un click a intrat într-un director, al doilea click al
  // unui dublu-click nu mai are voie să deschidă rândul care a apărut sub cursor în listarea nouă.
  const lastClickRef = useRef<{ name: string; t: number } | null>(null)
  const navGuardRef = useRef(0)
  // duplicate în zbor (rowId-ul copierii → numele + directorul), pentru toast + re-listare la final
  const dupRef = useRef(new Map<string, { name: string; dir: string }>())
  const filterRef = useRef<HTMLInputElement>(null)
  const pathInputRef = useRef<HTMLInputElement>(null)
  const crumbsRef = useRef<HTMLDivElement>(null)
  const firstFocusRef = useRef(!props.embed && !props.initialAction)
  const sessionPanel = !props.embed && !!props.sessionId
  const [sel, setSel] = useState(0)                 // index selectat (tastatură)
  const [listFocused, setListFocused] = useState(false)   // anunţul rândului curent (U10)
  const [renaming, setRenaming] = useState<string | null>(null)
  const [newFolder, setNewFolder] = useState<string | null>(null)
  const [newFile, setNewFile] = useState<string | null>(null)
  const [newFileErr, setNewFileErr] = useState('')
  const [confirmDel, setConfirmDel] = useState<Target | null>(null)
  // directorul în care a început redenumirea inline (refuzată dacă panoul a plecat între timp)
  const renameAtRef = useRef('')
  // Selecţie multiplă (3.5.5): bife pe rânduri, Shift/Ctrl+click, Space / Shift+săgeţi, long-press
  // pe touch. Modelul e pur (lib/selection.ts); cheile = numele din listarea curentă.
  const [selection, setSelection] = useState<Selection>(EMPTY_SELECTION)
  const [confirmBulk, setConfirmBulk] = useState<Entry[] | null>(null)
  const [copyItems, setCopyItems] = useState<CopyItem[] | null>(null)
  const pathRef = useRef<string | null>(null)
  // long-press (touch): porneşte selecţia; click-ul care urmează ridicării degetului e înghiţit
  const pressRef = useRef<{ timer: number; x: number; y: number } | null>(null)
  const suppressClickRef = useRef(false)
  const lastPointerRef = useRef<string>('mouse')
  const fileInput = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)
  const loadSeq = useRef(0)

  /** `focus`: după listare, focusul pe listă cu rândul acela selectat (navigare / redenumire / dosar
      nou / ştergere). Fără el (follow pe cwd, reload) focusul nu se mută. */
  const load = useCallback(async (p: string, focus?: { name?: string; idx?: number }) => {
    // generație monotonă: dacă navighezi rapid (sau un event OSC 7 întârziat
    // sosește după un click manual), doar răspunsul CEL MAI RECENT se aplică —
    // altfel un director lent ar suprascrie unul mai nou și operațiile
    // ulterioare (upload/delete) ar ținti calea greșită.
    const my = ++loadSeq.current
    if (focus) wantFocusRef.current = { ...focus, seq: my }
    setError('')
    setFailedPath(null)
    try {
      const l = await api<Listing>(`/api/hosts/${props.host.id}/fs?path=${encodeURIComponent(p)}`)
      if (my !== loadSeq.current) return          // un load mai nou a pornit între timp
      doneSeqRef.current = my
      // alt director → filtrul se goleşte (3.6.14): un „log" tastat în /var nu mai ascunde, tăcut,
      // tot conţinutul directorului următor
      if (pathRef.current !== l.path) { setFilter(''); setMenu(null) }
      // istoricul: pasul ‹ / › cerut (dacă a ajuns chiar acolo) sau un director nou vizitat
      const mv = histMoveRef.current
      histMoveRef.current = null
      setHist((h) => (mv && mv.stack[mv.idx] === l.path ? mv : histPush(h, l.path)))
      setListing(l)
      setPath(l.path)
      // alt director → selecţia se goleşte; acelaşi (reload după ştergere/rename) → doar ce mai există
      setSelection((s) => (pathRef.current === l.path ? prune(s, l.entries.map((e) => e.name)) : EMPTY_SELECTION))
      pathRef.current = l.path
      setConfirmBulk(null)
      setSel(0)
      setConfirmDel(null)
      setRenaming(null)
    } catch (e) {
      if (my !== loadSeq.current) return
      doneSeqRef.current = my
      histMoveRef.current = null
      setMenu(null)
      setError(errText(e, t) || t('files.genericErr'))
      setFailedPath(p)   // „Reîncearcă" lângă eroare (audit 3.6.3)
      // Listarea VECHE rămânea afişată sub eroare, iar calea din input devenea deja cea
      // nouă: vizual, fişierele din /root păreau să fie în directorul inexistent, iar
      // „Upload to:" arăta încă directorul anterior — deci un upload ar fi plecat altundeva
      // decât credeai. Golim listarea: eroarea rămâne singurul lucru de citit.
      setListing(null)
      setSel(0)
      setConfirmDel(null)
      setRenaming(null)
      setSelection(EMPTY_SELECTION)
      setConfirmBulk(null)
      pathRef.current = null
    }
  }, [props.host.id, t])

  // cwd-ul sesiunii: OSC 7 (dacă e activ shell integration) altfel îl cerem
  // agentului (tmux pane_current_path / /proc) → panoul se deschide unde ești,
  // nu în ~. Pe agenți vechi fără op-ul ăsta, .catch cade curat pe ~.
  const loadSessionCwd = useCallback(() => {
    const known = getCwd(props.sessionId)
    if (known) { load(known); return }
    api<{ cwd: string }>(`/api/hosts/${props.host.id}/fs/cwd?sid=${encodeURIComponent(props.sessionId)}`)
      .then((r) => load(r.cwd || '~'))
      .catch(() => load('~'))
  }, [props.host.id, props.sessionId, load])

  // pornire: deschide în directorul curent al terminalului — sau în directorul cerut de bara de
  // transferuri („deschide aici" pe un upload orfan), care are prioritate şi opreşte follow-ul
  useEffect(() => {
    if (!isAgent) return
    // `revealPath` (meniul contextual al terminalului) are prioritate şi opreşte follow-ul — vrem
    // panoul FIX la calea cerută, nu tras înapoi la cwd de primul `cd`.
    if (props.revealPath) { setFollow(false); load(props.revealPath); return }
    const wanted = takeFilesDir(props.host.id)
    if (wanted) { setFollow(false); load(wanted) } else loadSessionCwd()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAgent])
  // `initialAction` („Fişier/Dosar nou" din submeniul terminalului): odată ce directorul s-a
  // încărcat, intrăm în modul inline EXISTENT (`newFile`/`newFolder`) — aceeaşi cale ca butoanele
  // din bară, deci `doNewFile`/`doMkdir` rămân singura implementare. O SINGURĂ dată per montare.
  const didInitActionRef = useRef(false)
  useEffect(() => {
    if (!props.initialAction || didInitActionRef.current || !listing) return
    didInitActionRef.current = true
    if (props.initialAction === 'newFolder') { setNewFile(null); setNewFolder('') }
    else { setNewFolder(null); setNewFileErr(''); setNewFile('') }
  }, [listing, props.initialAction])
  // acelaşi buton apăsat cât panoul e DEJA deschis pe host: navigăm direct
  useEffect(() => {
    const onOpen = (e: Event) => {
      const d = (e as CustomEvent<{ hostId: number; dir: string }>).detail
      if (d.hostId !== props.host.id) return
      takeFilesDir(props.host.id)
      setFollow(false)
      load(d.dir)
    }
    window.addEventListener('wt-open-files', onOpen)
    return () => window.removeEventListener('wt-open-files', onOpen)
  }, [props.host.id, load])

  // Un drop RATAT (lângă panou, peste terminal) navighează altfel pagina la fişierul local:
  // browserul îl deschide şi SPA-ul moare cu tot cu sesiunile deschise. Panoul invită la
  // drag&drop, deci cât e montat neutralizăm dragover/drop la nivel de fereastră — zona
  // proprie de drop nu e afectată (handler-ele ei rulează înaintea celui de pe window).
  useEffect(() => {
    const block = (e: DragEvent) => e.preventDefault()
    window.addEventListener('dragover', block)
    window.addEventListener('drop', block)
    return () => {
      window.removeEventListener('dragover', block)
      window.removeEventListener('drop', block)
    }
  }, [])

  // follow: la fiecare `cd` din terminal (OSC 7), sari acolo
  useEffect(() => {
    if (!isAgent) return
    const onCwd = (e: Event) => {
      const d = (e as CustomEvent<{ sid: string; cwd: string }>).detail
      if (follow && d.sid === props.sessionId) load(d.cwd)
    }
    window.addEventListener('wt-cwd', onCwd)
    return () => window.removeEventListener('wt-cwd', onCwd)
  }, [follow, isAgent, props.sessionId, load])

  // navigare manuală = oprește follow (altfel te trage înapoi la cwd)
  // `select`: rândul de selectat după listare (la „sus": directorul din care ai venit)
  const navigate = (p: string, select?: string) => {
    setFollow(false); setEditPath(false); setConfirmDel(null)
    void load(p, { name: select })
  }
  const goUp = () => {
    if (!listing || listing.path === '/') return
    navigate(listing.parent || parentOf(listing.path), baseName(listing.path))
  }
  /** ‹ / › (şi Mod+[ / Mod+], butoanele 4/5 ale mouse-ului, Back pe telefon). false = capătul istoricului. */
  const goHist = (d: -1 | 1): boolean => {
    const st = histStep(histRef.current, d)
    if (!st) return false
    const from = listing?.path ?? ''
    histMoveRef.current = st.hist
    setFollow(false)
    setEditPath(false)
    setConfirmDel(null)
    // înapoi într-un părinte: rândul selectat e directorul din care ai venit
    void load(st.path, { name: from && parentOf(from) === st.path ? baseName(from) : undefined })
    return true
  }
  backRef.current = () => goHist(-1)
  /** focusul înapoi pe listă (după un dialog / meniu închis), cu rândul `name` selectat */
  const refocus = (name?: string) => {
    wantFocusRef.current = { name, seq: 0 }
    setFocusTick((n) => n + 1)
  }
  const enableFollow = () => {
    setFollow(true)
    loadSessionCwd()
  }

  const view = useMemo(() => {
    const es = (listing?.entries ?? [])
      .filter((e) => showHidden || !e.name.startsWith('.'))
      .filter((e) => !filter || e.name.toLowerCase().includes(filter.toLowerCase()))
    const dir = sort.asc ? 1 : -1
    es.sort((a, b) => {
      if (a.dir !== b.dir) return a.dir ? -1 : 1   // directoarele mereu primele
      if (sort.key === 'size') return (a.size - b.size) * dir
      if (sort.key === 'mtime') return (a.mtime - b.mtime) * dir
      return a.name.localeCompare(b.name) * dir
    })
    return es
  }, [listing, filter, showHidden, sort])
  // ordinea VIZIBILĂ (filtru + sortare): intervalele şi „Selectează tot" lucrează pe ea
  const order = useMemo(() => view.map((e) => e.name), [view])
  const picked = useMemo(() => {
    const byName = new Map(view.map((e) => [e.name, e]))
    return visibleSelected(selection, order).map((n) => byName.get(n)!)
  }, [selection, order, view])
  const allSel = allState(selection, order)
  const selAllRef = useRef<HTMLInputElement>(null)
  useEffect(() => { if (selAllRef.current) selAllRef.current.indeterminate = allSel === 'some' }, [allSel])

  // ── roving focus (3.6.14) ──
  // Lista (containerul) ţine focusul: la deschidere, după navigare / redenumire / dosar nou / ştergere,
  // după editor, dialoguri şi meniu. Înainte focusul stătea pe butonul numelui — care dispărea la
  // navigare, deci ajungea pe <body> şi tastatura era moartă după aproape orice acţiune cu mouse-ul.
  // Nu furăm focusul: doar dacă e pe <body>, pe panou, sau pe un control al panoului care nu e câmp
  // de text (un câmp de redenumire cu autoFocus, terminalul sau editorul rămân neatinse).
  const focusListIfFree = useCallback(() => {
    const a = document.activeElement
    const aside = asideRef.current
    if (!a || a === document.body || (aside && aside.contains(a) && !isTextField(a)
      && !a.closest('[role="dialog"],[role="alertdialog"]'))) {
      listRef.current?.focus({ preventScroll: true })
    }
  }, [])
  useEffect(() => {
    if (firstFocusRef.current && listing) {
      firstFocusRef.current = false
      focusListIfFree()
    }
    const w = wantFocusRef.current
    if (!w || w.seq > doneSeqRef.current) return
    wantFocusRef.current = null
    let idx = w.name != null ? view.findIndex((e) => e.name === w.name) : -1
    if (idx < 0 && w.idx != null) idx = Math.min(w.idx, view.length - 1)
    if (idx >= 0) setSel(idx)
    focusListIfFree()
  }, [view, listing, focusTick, focusListIfFree])

  async function download(e: Entry, dir = listing!.path) {
    // Prin MOTORUL de transfer (phase 2): progres, retry, pauză şi reluare, vizibile în chip/bară —
    // nu mai e un `<a download>` oarbă care, pe un fişier de 40 GB picat la 90%, reîncepe de la zero.
    // `startDownload` cheamă selectorul de fişier (File System Access) ÎNTÂI, cât încă avem gestul
    // click-ului; fişierele mari curg pe disc, cele mici cad pe Blob. Fişier prea mare fără FS
    // Access → eroare clară (o prindem aici).
    try {
      await startDownload({ hostId: props.host.id, hostName: props.host.name,
                            path: join(dir, e.name), name: e.name, size: e.size })
    } catch (err) {
      setError(errText(err, t) || t('files.genericErr'))
    }
  }

  // director → tar.gz făcut pe host, acum prin MOTORUL de transfer (3.5.5): rând în Transferuri cu
  // „se pregăteşte arhiva…" cât rulează tar-ul (până la 5 min), octeţii primiţi, Cancel şi eroarea
  // serverului. Nu e resumabil (arhivă generată din mers) — Retry o reporneşte.
  async function downloadArchive(e: Entry, dir = listing!.path) {
    try {
      await startArchiveDownload({ hostId: props.host.id, hostName: props.host.name,
                                   path: join(dir, e.name), name: `${e.name}.tgz` })
    } catch (err) {
      setError(errText(err, t) || t('files.genericErr'))
    }
  }

  // ── acţiuni în BLOC pe selecţie ──
  function bulkDownload() {
    if (!listing || !picked.length) return
    const items: BulkItem[] = picked.map((e) => ({ hostId: props.host.id, hostName: props.host.name,
      path: join(listing.path, e.name), name: e.name, size: e.size, dir: e.dir }))
    // startDownloads cere selectorul de folder PRIMUL (gestul click-ului); job-urile rulează mai departe
    void startDownloads(items).then((errs) => {
      if (errs && errs.length) setError(t('files.bulkDownloadFailed', { count: errs.length }) + ' ' + errs.slice(0, 3).join('; '))
    })
  }

  async function doBulkDelete(items: Entry[]) {
    setConfirmBulk(null)
    if (!listing) return
    const dir = listing.path
    setBusy(true)
    const failed: string[] = []
    const failedNames: string[] = []
    for (const e of items) {
      try {
        // aceeaşi regulă ca ştergerea simplă: folderele recursiv (confirmarea a spus-o explicit)
        await api(`/api/hosts/${props.host.id}/fs/delete`, {
          method: 'POST', body: JSON.stringify({ path: join(dir, e.name), recursive: e.dir }),
        })
      } catch (err) {
        failed.push(`${e.name}: ${errText(err, t) || t('files.genericErr')}`)
        failedNames.push(e.name)
      }
    }
    setBusy(false)
    const firstIdx = view.findIndex((e) => e.name === items[0]?.name)
    await load(dir, { idx: Math.max(0, firstIdx) })
    // ce a eşuat rămâne selectat (poţi reîncerca / vedea ce a rămas); restul a dispărut din listare
    setSelection({ keys: new Set(failedNames), anchor: null })
    const deleted = items.length - failed.length
    if (deleted > 0) notifyToast(deleted === 1 && items.length === 1 ? t('files.toastDeleted', { name: items[0].name })
      : t('files.toastDeletedN', { count: deleted }))
    if (failed.length) setError(t('files.bulkDeleteFailed', { count: failed.length, total: items.length }) + ' ' + failed.slice(0, 3).join('; '))
  }

  // ── acţiunile unui RÂND (meniul contextual, tastele, „⋯") ──
  /** rândul + directorul listat acum (pentru confirmarea de ştergere) */
  const tgt = (e: Entry): Target => ({ ...e, at: listing?.path ?? '' })
  /** directorul ales (meniu / confirmare) încă e cel listat? Altfel acţiunea e refuzată cu un mesaj. */
  const stillHere = (dir: string): boolean => {
    if (listing && listing.path === dir) return true
    setError(t('files.staleTarget', { dir })); return false
  }
  /** deschide: director → intră; fişier → editorul */
  function openEntry(e: Entry, dir = listing?.path ?? '') {
    if (!listing || !stillHere(dir)) return
    if (e.dir) navigate(join(dir, e.name)); else edit(e, dir)
  }
  function startRename(name: string, dir = listing?.path ?? '') {
    if (!writeAllowed() || !stillHere(dir)) return
    renameAtRef.current = dir
    setNewFolder(null); setNewFile(null); setConfirmDel(null); setRenaming(name)
  }
  function startNewFolder() {
    if (!listing || !writeAllowed()) return
    setNewFile(null); setNewFileErr(''); setRenaming(null); setConfirmDel(null); setNewFolder('')
  }
  function startNewFile() {
    if (!listing || !writeAllowed()) return
    setNewFileErr(''); setNewFolder(null); setRenaming(null); setConfirmDel(null); setNewFile('')
  }
  function pickUpload() {
    if (!listing || busy || !writeAllowed()) return
    fileInput.current?.click()
  }
  /** Duplicat pe ACELAŞI host, în acelaşi director: `/api/fs/copy` cu src == dst (permis explicit pe
      server) şi `on_conflict: rename` → „nume (1).ext" / folder „nume (1)", primul liber (fscopy.py).
      Copierea rulează pe gateway (rând în Transferuri); la final: toast + re-listare. */
  async function duplicate(e: Entry, dir = listing?.path ?? '') {
    if (!listing || !writeAllowed() || !stillHere(dir)) return
    try {
      const rowId = await startCopy({ srcHost: props.host.id, srcName: props.host.name, dstHost: props.host.id,
        dstName: props.host.name, paths: [join(dir, e.name)], dstDir: dir, onConflict: 'rename' })
      dupRef.current.set(rowId, { name: e.name, dir })
    } catch (err) { writeFailed(err, dir) }
  }
  /** Copiază numele (sau, cu o selecţie, numele selectate, câte unul pe rând) / calea completă. */
  function copyNames(e: Entry | undefined, full: boolean) {
    if (!listing) return
    const list = picked.length > 1 ? picked : e ? [e] : []
    if (!list.length) return
    void copyToClip(list.map((x) => (full ? join(listing.path, x.name) : x.name)).join('\n'))
  }
  /** „cd aici" în terminalul sesiunii: tastat prin drumul existent typed-not-run (doar la un prompt,
      fără Enter — ca „Insert path"); refuzat cu un toast altfel. Directorul unui fişier = cel listat. */
  function cdHere(dir: string) {
    if (!sessionPanel) return
    const cmd = cdCommand(dir)
    if (!cmd) { notifyToast(t('files.cdUnsafe'), 'warn'); return }
    const r = typeIntoOutcome(props.sessionId, cmd)
    if (r === 'typed') {
      notifyToast(t('files.cdTyped', { cmd }))
      if (drawer.sheet) props.onClose()          // pe telefon foaia acoperă terminalul
    } else if (r === 'notPrompt') notifyToast(t('files.cdNotPrompt'), 'warn')
    else notifyToast(t('files.cdNoTarget'), 'warn')
  }

  // duplicatele terminate: toast + re-listare (dacă suntem încă în acel director); eşecul → linia roşie
  useEffect(() => {
    for (const [id, d] of [...dupRef.current]) {
      const j = uploadsAll.get(id)
      if (!j) { dupRef.current.delete(id); continue }
      if (j.state === 'done') {
        dupRef.current.delete(id)
        notifyToast(t('files.toastDuplicated', { name: d.name }))
        if (pathRef.current === d.dir) void load(d.dir)
      } else if (j.state === 'err' || j.state === 'cancelled') {
        dupRef.current.delete(id)
        if (j.error) setError(`${d.name}: ${j.error}`)
      }
    }
  }, [uploadsAll, load, t])

  // ── meniul ──
  function openRowMenu(e: Entry, x: number, y: number, sheet = touchUI) {
    if (!listing) return
    setMenu({ kind: 'row', entry: e, dir: listing.path, x, y, sheet })
  }
  /** Shift+F10 / tasta Menu: meniul rândului curent, sub el */
  function openRowMenuAtSel() {
    const e = view[sel]
    if (!e) return
    const r = listRef.current?.querySelector(`[data-idx="${sel}"]`)?.getBoundingClientRect()
    openRowMenu(e, (r?.left ?? 0) + 32, r?.bottom ?? 0, false)
  }
  function closeMenu() {
    const m = menu
    setMenu(null)
    refocus(m?.kind === 'row' ? m.entry.name : undefined)
  }
  function menuItems(m: MenuState): MenuItem[] {
    return gateMenuItems(rawMenuItems(m), gate, { write: needsWrite, del: needsDelete })
  }
  function rawMenuItems(m: MenuState): MenuItem[] {
    const dirItems = (): MenuItem[] => [
      { key: 'newfile', label: t('files.newFile'), icon: <FilePlusIcon />, onSelect: startNewFile, hint: fmt('Alt+N') },
      { key: 'newfolder', label: t('files.newDir'), icon: <PlusIcon />, onSelect: startNewFolder, hint: 'F7' },
      { key: 'upload', label: t('files.uploadHere'), icon: <UploadIcon />, onSelect: pickUpload, disabled: busy, hint: fmt('Mod+U') },
    ]
    if (m.kind === 'new') return dirItems()
    if (m.kind === 'dir') {
      const here = m.dir
      return [
        ...dirItems(),
        { key: 'reload', label: t('files.reload'), icon: <RefreshIcon />, onSelect: () => void load(here), hint: 'F5', sep: true },
        { key: 'copypath', label: t('files.copyPath'), icon: <CopyIcon />, onSelect: () => void copyToClip(here) },
        ...(sessionPanel ? [{ key: 'cd', label: t('files.cdHere'), icon: <TerminalPromptIcon />, onSelect: () => cdHere(here) }] : []),
      ]
    }
    const e = m.entry
    const dir = m.dir
    return [
      e.dir
        ? { key: 'open', label: t('files.open'), icon: <FolderIcon />, onSelect: () => openEntry(e, dir), hint: 'Enter' }
        : { key: 'edit', label: t('files.edit'), icon: <PencilIcon />, onSelect: () => { if (stillHere(dir)) edit(e, dir) }, hint: 'Enter' },
      { key: 'download', label: e.dir ? t('files.downloadTgz') : t('files.download'), icon: <DownloadIcon />,
        onSelect: () => { if (stillHere(dir)) void (e.dir ? downloadArchive(e, dir) : download(e, dir)) } },
      { key: 'rename', label: t('files.rename'), icon: <RenameIcon />, onSelect: () => startRename(e.name, dir), hint: 'F2', sep: true },
      { key: 'duplicate', label: t('files.duplicate'), icon: <CopyIcon />, onSelect: () => void duplicate(e, dir) },
      { key: 'copyname', label: t('files.copyName'), icon: <CopyIcon />, onSelect: () => void copyToClip(e.name), hint: fmt('Mod+C'), sep: true },
      { key: 'copypath', label: t('files.copyPath'), icon: <CopyIcon />, onSelect: () => void copyToClip(join(dir, e.name)), hint: fmt('Mod+Shift+C') },
      { key: 'copyhost', label: t('copy.open'), icon: <ArrowsLeftRightIcon />,
        onSelect: () => setCopyItems([{ name: e.name, path: join(dir, e.name), dir: e.dir, mode: e.mode }]) },
      ...(sessionPanel ? [{ key: 'cd', label: t('files.cdHere'), icon: <TerminalPromptIcon />,
        onSelect: () => cdHere(e.dir ? join(dir, e.name) : dir), sep: true }] : []),
      { key: 'delete', label: t('files.delete'), icon: <TrashIcon />, danger: true, sep: !sessionPanel,
        onSelect: () => { if (!deleteAllowed() || !stillHere(dir)) return; setConfirmBulk(null); setConfirmDel({ ...e, at: dir }) }, hint: 'Del' },
    ]
  }

  function openCopy() {
    if (!listing || !picked.length) return
    setCopyItems(picked.map((e) => ({ name: e.name, path: join(listing.path, e.name), dir: e.dir, mode: e.mode })))
  }

  // modificatori pe rând: Shift = interval de la ancoră, Ctrl/Cmd = comută; întoarce true dacă a
  // fost un click de SELECŢIE (atunci butonul numelui nu navighează / nu copiază)
  function selectClick(ev: React.MouseEvent, e: Entry, i: number): boolean {
    if (ev.shiftKey) {
      setSelection((s) => rangeTo(s, order, e.name, ev.ctrlKey || ev.metaKey))
      setSel(i)
      return true
    }
    if (ev.ctrlKey || ev.metaKey) {
      setSelection((s) => toggleKey(s, e.name))
      setSel(i)
      return true
    }
    return false
  }

  // long-press pe touch (500 ms, fără să mişti degetul): comută rândul → modul de selecţie; cât
  // există o selecţie, un tap pe rând COMUTĂ în loc să navigheze (ca în galeriile de pe telefon)
  function pressStart(ev: React.PointerEvent, e: Entry, i: number) {
    lastPointerRef.current = ev.pointerType
    if (ev.pointerType !== 'touch') return
    pressCancel()
    const timer = window.setTimeout(() => {
      pressRef.current = null
      suppressClickRef.current = true
      setSelection((s) => toggleKey(s, e.name))
      setSel(i)
      try { navigator.vibrate?.(15) } catch { /* fără vibraţie */ }
    }, 500)
    pressRef.current = { timer, x: ev.clientX, y: ev.clientY }
  }
  function pressMove(ev: React.PointerEvent) {
    const p = pressRef.current
    if (p && (Math.abs(ev.clientX - p.x) > 10 || Math.abs(ev.clientY - p.y) > 10)) pressCancel()
  }
  function pressCancel() {
    if (pressRef.current) { window.clearTimeout(pressRef.current.timer); pressRef.current = null }
  }

  // FileEditor încarcă singur conținutul (preview cu partial-read) și decide
  // editabil / view-only / binar — aici doar deschidem modalul.
  function edit(e: Entry, dir = listing!.path) {
    setError('')
    setEditing({ path: join(dir, e.name), name: e.name })
  }

  // Un fişier → motorul din lib/uploads.ts (acelaşi protocol ca înainte, acum cu watchdog,
  // reluare şi persistenţă). Promisiunea se rezolvă la finalul primei treceri; un Retry
  // ulterior (din bara globală) nu mai trece pe aici.
  const uploadOne = (dest: string, rel: string, file: File) =>
    engineStart({ hostId: props.host.id, hostName: props.host.name, dest, name: rel, file })

  // ✕ pe rând: cât transferul e viu îl anulează (temp-ul de pe host dispare, nu mai e resumabil);
  // pe ✓/✗ doar curăţă rândul din listă (store-ul e global, altfel erorile ar rămâne pe ecran)
  function cancelOrDismiss(id: string, live: boolean) {
    if (live) cancelUpload(id); else dismissUpload(id)
  }

  // fişierele dintr-un drop (foldere incluse). webkitGetAsEntry TREBUIE apelat sincron —
  // `items` se golesc după handler — de aceea întâi culegem intrările, apoi le parcurgem.
  async function collectDrop(e: React.DragEvent): Promise<UpItem[]> {
    const entries = Array.from(e.dataTransfer.items || [])
      .map((it) => (it.webkitGetAsEntry ? it.webkitGetAsEntry() : null))
      .filter(Boolean)
    const out: UpItem[] = []
    if (entries.length) {
      for (const en of entries) await readEntry(en, '', out)
    } else {
      for (const f of Array.from(e.dataTransfer.files)) out.push({ file: f, rel: f.name })
    }
    return out
  }

  // punct de intrare: cere confirmare dacă suprascrie fișiere top-level existente. `baseDir`
  // (drop pe un rând de director) ţinteşte un subdirector pe care nu l-am listat — acolo nu
  // putem vedea coliziunile, deci urcăm direct (motorul suprascrie atomic la commit).
  function startUpload(items: UpItem[], baseDir?: string) {
    if (!listing) return
    // fără files.write pe host: refuz cu motiv ÎNAINTE de orice cerere (drop, selector, drop pe rând)
    if (!writeAllowed()) return
    const base = baseDir ?? listing.path
    // re-drop-ul unui fişier DEJA în zbor pornea un al doilea uploadOne pe acelaşi upload_id:
    // cele două bucle îşi suprascriau reciproc ctl-ul (cancel-ul rămânea mort) şi îşi
    // furau offset-ul prin resync-uri 409 — îl ignorăm, transferul existent continuă singur
    items = items.filter((it) => !isUploadBusy(props.host.id, join(base, it.rel)))
    if (!items.length) return
    if (base !== listing.path) { void reallyUpload(items, base); return }
    const existing = new Set(listing.entries.map((e) => e.name))
    const collides = items.filter((it) => !it.rel.includes('/') && existing.has(it.rel))
    if (collides.length) setOverwrite({ items, count: collides.length })
    else reallyUpload(items)
  }

  async function reallyUpload(items: UpItem[], baseDir?: string) {
    setOverwrite(null)
    if (!listing) return
    const base = baseDir ?? listing.path
    setBusy(true)
    // creează întâi subdirectoarele (upload de folder), idempotent
    const dirs = new Set<string>()
    for (const it of items) {
      const slash = it.rel.lastIndexOf('/')
      if (slash > 0) dirs.add(it.rel.slice(0, slash))
    }
    // FS-04 (audit 2026-10-17): un mkdir REFUZAT (userul agentului nu poate scrie acolo) nu mai trece
    // drept „există deja": tot subarborele lui e refuzat dintr-o dată — altfel fiecare fişier ar cere
    // `fs_write` într-un dosar inexistent şi ar raporta „the folder does not exist" (adevărat literal,
    // fals ca explicaţie), fără banner, fără lacăt, fără oferta „move as root". Listarea curentă spune
    // dacă prima componentă exista (atunci EA e nescriibilă) sau nu (atunci dosarul listat).
    const existing = new Set(base === listing.path ? listing.entries.map((e) => e.name) : [])
    const refusedPrefixes: string[] = []
    let refusedDir: { dir: string; message: string } | null = null
    for (const d of [...dirs].sort()) {
      if (underRefused(d, refusedPrefixes)) continue
      try { await api(`/api/hosts/${props.host.id}/fs/mkdir`, { method: 'POST', body: JSON.stringify({ path: join(base, d), parents: true }) }) }
      catch (e) {
        const r = mkdirRefusal(e, base, d, existing)
        if (!r) continue                              // există deja (altă eroare: o va spune upload-ul)
        refusedPrefixes.push(r.prefix)
        refusedDir ??= { dir: r.at, message: errText(e, t) }
        if (r.prefix === '') break                    // dosarul listat nu e scriibil: niciun subdosar nu va merge
      }
    }
    const refused: PendingFile[] = []
    let refusedMsg = '', otherErr = '', anyOk = false, skipped = 0
    for (const it of items) {
      // sub un dosar refuzat nu mai încercăm fişierele unul câte unul (fiecare ar primi „dirMissing")
      if (underRefused(it.rel, refusedPrefixes)) { skipped++; continue }
      const id = await uploadOne(join(base, it.rel), it.rel, it.file)
      const j = uploadStore.get(id)
      if (j?.state === 'done') anyOk = true
      else if (j?.state === 'err' && isWriteDenied(j.errorCode) && !it.rel.includes('/')) {
        refused.push({ file: it.file, name: it.rel })
        refusedMsg ||= j.error ?? ''
      } else if (j?.state === 'err' && j.error) otherErr ||= `${it.rel}: ${j.error}`
    }

    setBusy(false)
    if (refused.length || refusedDir) {
      // fişiere simple refuzate → dosarul listat (ele intră în oferta „move as root"); doar un
      // subdosar refuzat → dosarul nescriibil (lacăt + banner acolo; aici linia de eroare de mai jos)
      const dir = refused.length ? base : refusedDir!.dir
      markDenied(props.host.id, dir)
      setDenied({ dir, message: refusedMsg || refusedDir?.message || '', pending: refused })
    } else if (anyOk) clearDenied(props.host.id, base)
    await load(listing.path)
    // 3.6.9: eroarea unui upload apărea DOAR în widgetul de transferuri; o arătăm şi aici — DUPĂ
    // re-listare, care goleşte linia de eroare
    if (skipped) otherErr = t('files.subtreeRefused', { count: skipped, dir: refusedDir?.dir ?? base }) + (otherErr ? ' ' + otherErr : '')
    if (otherErr) setError(otherErr)
  }

  /** O operaţie de scriere refuzată în dosarul curent → bannerul (în loc de linia roşie scurtă). */
  function writeFailed(e: unknown, dir: string): void {
    if (errIsWriteDenied(e)) {
      markDenied(props.host.id, dir)
      setDenied({ dir, message: errText(e, t), pending: [] })
    } else setError(errText(e, t) || t('files.genericErr'))
  }

  async function uploadHome(files: PendingFile[]) {
    let home: string
    try { home = await resolveHome(props.host.id) } catch (e) { setError(errText(e, t) || t('files.genericErr')); return }
    setDenied(null)
    if (files.length) await reallyUpload(files.map((f) => ({ file: f.file, rel: f.name })), home)
    navigate(home)
  }

  function pickFiles(files: FileList | File[]) {
    startUpload(Array.from(files).map((f) => ({ file: f, rel: f.name })))
  }

  async function doMkdir(name: string) {
    const n = name.trim()
    setNewFolder(null)
    if (!n || !listing) { refocus(); return }
    try {
      await api(`/api/hosts/${props.host.id}/fs/mkdir`, { method: 'POST', body: JSON.stringify({ path: join(listing.path, n) }) })
      notifyToast(t('files.toastMkdir', { name: n }))
      void load(listing.path, { name: n })
    } catch (e) { writeFailed(e, listing.path); refocus() }
  }

  // fişier nou: îl creăm pe host printr-un upload one-shot — corp gol ("empty") sau conţinutul din
  // clipboard ("clipboard") — apoi deschidem editorul pe el (acolo mai editezi şi salvezi). Refoloseşte
  // editorul + salvarea atomică existente. Citirea clipboard-ului cere HTTPS + gest de utilizator (clickul
  // pe buton) — dacă browserul o refuză (ex. Firefox), lăsăm modalul deschis cu "empty" ca alternativă.
  async function doNewFile(name: string, mode: 'empty' | 'clipboard') {
    const n = name.trim()
    if (!n || !listing) return
    // doar un NUME, nu o cale: cu `/` fişierul ar ateriza în alt director decât cel afişat
    // (join-ul concatenează, verificarea de duplicat nu l-ar vedea) — derutant, nu-l permitem
    if (/[/\\]/.test(n) || n === '.' || n === '..') { setNewFileErr(t('files.badName')); return }
    let body = new Uint8Array(0)
    if (mode === 'clipboard') {
      const txt = await readText()                      // null = refuzat/indisponibil (ex. Firefox, HTTP)
      if (txt === null) { setNewFileErr(t('files.clipboardDenied')); return }
      body = new TextEncoder().encode(txt)
    }
    // upload-ul suprascrie necondiţionat, iar listing-ul poate fi vechi (un `vim n.txt` în terminal
    // după ultima listare) — re-listăm chiar înainte de creare, ca duplicatul să fie văzut ACUM,
    // nu la ultimul load. Fereastra de cursă rămâne teoretic, dar nu mai e „de la ultima navigare".
    const dir = listing.path
    try {
      const fresh = await api<Listing>(`/api/hosts/${props.host.id}/fs?path=${encodeURIComponent(dir)}`)
      if (fresh.entries.some((e) => e.name === n)) { setNewFileErr(t('files.newFileExists')); return }
    } catch (e) { setNewFileErr(errText(e, t) || t('files.genericErr')); return }
    setNewFile(null); setNewFileErr('')
    const path = join(dir, n)
    try {
      await api(`/api/hosts/${props.host.id}/fs/upload?path=${encodeURIComponent(path)}`,
        { method: 'POST', body })
      await load(dir)
      setEditing({ path, name: n })                     // deschide editorul pe fişierul nou
    } catch (e) { writeFailed(e, dir) }
  }

  // copierea numelui / căii (meniul rândului, Ctrl+C / Ctrl+Shift+C — până în 3.6.13 dublu- /
  // triplu-click, care acum DESCHID). Prin `copyText` (nu navigator.clipboard direct): are rezerva
  // execCommand pentru instalările fără TLS şi toast-ul standard de „copiat" — acelaşi feedback ca peste tot.
  async function copyToClip(text: string) {
    if (!(await copyText(text))) setError(t('files.copyFailed'))
  }

  async function doRename(e: Entry, name: string) {
    const n = name.trim()
    setRenaming(null)
    if (!n || n === e.name || !listing) { refocus(e.name); return }
    const from = targetPath(renameAtRef.current, listing.path, e.name)
    const to = targetPath(renameAtRef.current, listing.path, n)
    if (!from || !to) { setError(t('files.staleTarget', { dir: renameAtRef.current })); return }
    try {
      await api(`/api/hosts/${props.host.id}/fs/rename`, {
        method: 'POST', body: JSON.stringify({ path: from, to }),
      })
      notifyToast(t('files.toastRenamed', { from: e.name, to: n }))
      void load(listing.path, { name: n })
    } catch (err) { writeFailed(err, listing.path); refocus(e.name) }
  }

  async function doDelete(e: Target) {
    setConfirmDel(null)
    if (!listing) return
    // ţinta e legată de directorul în care a fost aleasă: dacă panoul a plecat între timp (follow cwd),
    // NU ştergem `<directorul nou>/<acelaşi nume>` (review 3.6.15, M2)
    const path = targetPath(e.at, listing.path, e.name)
    if (!path) { setError(t('files.staleTarget', { dir: e.at })); return }
    const idx = view.findIndex((x) => x.name === e.name)
    try {
      await api(`/api/hosts/${props.host.id}/fs/delete`, {
        method: 'POST', body: JSON.stringify({ path, recursive: e.dir }),
      })
      notifyToast(t('files.toastDeleted', { name: e.name }))
      // focusul rămâne pe aceeaşi poziţie (rândul de după cel şters)
      void load(listing.path, { idx: Math.max(0, idx) })
    } catch (err) { writeFailed(err, listing.path); refocus(e.name) }
  }
  function cancelDelete() {
    const name = confirmDel?.name
    setConfirmDel(null); setConfirmBulk(null)
    refocus(name)
  }

  /** câte rânduri încap în listă (PgUp / PgDn) */
  const pageRows = () => {
    const l = listRef.current
    const row = l?.querySelector<HTMLElement>('[data-idx]')
    return l && row && row.offsetHeight ? Math.max(1, Math.floor(l.clientHeight / row.offsetHeight) - 1) : 10
  }

  function onKeyDown(ev: React.KeyboardEvent<HTMLDivElement>) {
    // Escape cu confirmarea de ştergere deschisă = anulează confirmarea, nu închide panoul
    if (ev.key === 'Escape' && (confirmDel || confirmBulk)) {
      ev.preventDefault(); ev.stopPropagation(); cancelDelete(); return
    }
    // Escape cu o selecţie = goleşte selecţia (al doilea Escape închide panoul, ca înainte)
    if (ev.key === 'Escape' && selection.keys.size) { ev.preventDefault(); ev.stopPropagation(); setSelection(EMPTY_SELECTION); return }
    if (editing || renaming || newFolder !== null || newFile !== null || confirmBulk || menu) return
    // tastele listei: de pe container sau de pe un descendent care nu e câmp de text; Enter/Space pe
    // un buton real îl activează pe el (lib/selection.ts, U09 + roving focus 3.6.14)
    if (!isListKeyTarget(keyTargetOf(ev.target, ev.currentTarget), ev.key)) return
    // confirmarea simplă deschisă şi focusul înapoi în listă (review 3.6.15, M1): Enter NU confirmă —
    // userul care a dat click pe alt rând şi apasă Enter vrea să-l deschidă, nu să şteargă (recursiv)
    // dosarul de dinainte. Orice tastă din listă închide confirmarea; Enter nu face nimic.
    // (modificatorii singuri — Shift/Ctrl/Alt/Meta apăsate înaintea altei taste — nu o închid, review R3)
    if (confirmDel && !['Shift', 'Control', 'Alt', 'Meta', 'AltGraph', 'CapsLock'].includes(ev.key)) {
      setConfirmDel(null)
      if (ev.key === 'Enter') { ev.preventDefault(); return }
    }
    const cur = view[sel]
    const now = Date.now()
    // tastează ca să sari: literele (cu Shift = majuscule), spaţiul doar ÎN MIJLOCUL unui nume tastat
    const buf = typeBufRef.current
    const live = !!buf.s && now - buf.t < TYPE_JUMP_MS
    if (ev.key.length === 1 && !ev.ctrlKey && !ev.metaKey && !ev.altKey && ev.key !== '/' && (ev.key !== ' ' || live)) {
      ev.preventDefault()
      const s = (live ? buf.s : '') + ev.key
      typeBufRef.current = { s, t: now }
      const i = typeJump(view.map((e) => e.name), s, sel)
      if (i >= 0) setSel(i)
      return
    }
    const id = matchFilesShortcut(ev.nativeEvent)
    const stop = () => { ev.preventDefault(); ev.stopPropagation() }
    // auto-repeat (tastă ţinută apăsată) nu declanşează acţiuni distructive / deschideri în lanţ
    if (ev.repeat && (id === 'filesDelete' || id === 'filesOpen' || id === 'filesMenu' || id === 'filesRename')) { ev.preventDefault(); return }
    // Delete / F2 de pe un control din rând (butoanele de la hover) nu ţintesc `view[sel]` (review L1)
    if ((id === 'filesDelete' || id === 'filesRename') && ev.target !== ev.currentTarget) return
    switch (id) {
      case 'filesOpen': if (cur) { stop(); openEntry(cur) } return
      case 'filesUp': stop(); goUp(); return
      case 'filesBack': stop(); goHist(-1); return
      case 'filesForward': stop(); goHist(1); return
      case 'filesRename': if (cur) { stop(); startRename(cur.name) } return
      case 'filesNewFolder': stop(); startNewFolder(); return
      case 'filesNewFile': stop(); startNewFile(); return
      // Ctrl+U (view-source) / F5 / Ctrl+R (reload) / Ctrl+L (bara de adrese): preventDefault DOAR
      // aici, cu focusul în listă — în rest tastele rămân ale browserului
      case 'filesUpload': stop(); pickUpload(); return
      case 'filesReload': stop(); if (listing) void load(listing.path); return
      case 'filesFocusPath': stop(); startEditPath(); return
      case 'filesFilter': stop(); filterRef.current?.focus(); return
      case 'filesCopyPath': if (cur) { stop(); copyNames(cur, true) } return
      case 'filesCopyName':
        // un text selectat cu mouse-ul (ex. din mesajul de eroare) se copiază normal
        if (window.getSelection()?.toString()) return
        if (cur) { stop(); copyNames(cur, false) }
        return
      case 'filesMenu': if (cur) { stop(); openRowMenuAtSel() } return
      case 'filesSelectAll': stop(); setSelection((s) => toggleAll(s, order)); return
      case 'filesToggleSel': if (cur) { ev.preventDefault(); setSelection((s) => toggleKey(s, cur.name)) } return
      case 'filesExtendSel': {
        // Shift+săgeţi: extinde selecţia de la ancoră (sau de la rândul curent, dacă nu e ancoră)
        ev.preventDefault()
        if (!view.length) return
        const next = ev.key === 'ArrowDown' ? Math.min(view.length - 1, sel + 1) : Math.max(0, sel - 1)
        const from = cur?.name ?? view[0].name
        setSelection((s) => rangeTo(s.anchor != null && order.includes(s.anchor) ? s : { ...s, anchor: from }, order, view[next].name))
        setSel(next)
        return
      }
      case 'filesEdges': {
        ev.preventDefault()
        if (!view.length) return
        const last = view.length - 1
        const n = ev.key === 'Home' ? 0 : ev.key === 'End' ? last
          : ev.key === 'PageUp' ? Math.max(0, sel - pageRows()) : Math.min(last, sel + pageRows())
        setSel(n)
        return
      }
      case 'filesDelete':
        // fără files.delete pe host: toast cu motivul, nimic deschis (aceeaşi poartă ca butoanele)
        if (!deleteAllowed()) { ev.preventDefault(); return }
        // cu o selecţie: ştergerea în bloc (o singură confirmare); altfel rândul curent
        if (picked.length) { ev.preventDefault(); setConfirmDel(null); setConfirmBulk(picked); return }
        if (cur) { ev.preventDefault(); setConfirmDel(tgt(cur)) }
        return
    }
    if (ev.key === 'ArrowDown' && !ev.altKey && !ev.ctrlKey && !ev.metaKey) { ev.preventDefault(); setSel((s) => Math.min(view.length - 1, s + 1)) }
    else if (ev.key === 'ArrowUp' && !ev.altKey && !ev.ctrlKey && !ev.metaKey) { ev.preventDefault(); setSel((s) => Math.max(0, s - 1)) }
  }

  // ── câmpul de cale: firimituri ↔ input editabil, cu completare pe Tab ──
  function startEditPath() {
    setPathDraft(listing?.path ?? path)
    setCompletion(null)
    noProgressRef.current = null
    completeCache.current.clear()
    setEditPath(true)
  }
  function endEditPath(focusList = true) {
    setEditPath(false)
    setCompletion(null)
    if (focusList) refocus()
  }
  /** Tab: completează ultimul segment din subdirectoarele directorului lui (listarea părintelui,
      prin acelaşi API, memorată cât e deschis câmpul). Fără progres a doua oară → Tab-ul pleacă mai
      departe (nu prindem tastatura în câmp). */
  async function completeTab(ev: React.KeyboardEvent<HTMLInputElement>) {
    const input = pathDraft
    const base = listing?.path ?? path
    const { dir, prefix } = splitForCompletion(input, base)
    if (!prefix && !input.endsWith('/') && input !== '~') return     // nimic de completat: Tab normal
    if (noProgressRef.current === input) { noProgressRef.current = null; return }
    ev.preventDefault()
    const my = ++completeSeq.current
    let dirs = completeCache.current.get(dir)
    if (!dirs) {
      try {
        const l = await api<Listing>(`/api/hosts/${props.host.id}/fs?path=${encodeURIComponent(dir)}`)
        dirs = l.entries.filter((e) => e.dir || e.link).map((e) => e.name)
        if (completeCache.current.size > 20) completeCache.current.clear()
        completeCache.current.set(dir, dirs)
      } catch { dirs = [] }
    }
    if (my !== completeSeq.current) return           // între timp alt Tab / altă tastare
    const r = completePath(input, base, dirs)
    if (r.value !== input) { setPathDraft(r.value); noProgressRef.current = null }
    else noProgressRef.current = input
    setCompletion(r.candidates.length || r.value === input ? { candidates: r.candidates, more: r.more, none: !r.candidates.length } : null)
  }

  // menține selecția vizibilă la navigarea din tastatură
  useEffect(() => {
    const el = listRef.current?.querySelector(`[data-idx="${sel}"]`)
    el?.scrollIntoView({ block: 'nearest' })
  }, [sel])

  const deniedHere = !!listing && isDenied(props.host.id, listing.path)
  const deniedView = !listing ? null
    : denied && denied.dir === listing.path ? denied
    : deniedHere ? { dir: listing.path, pending: [] as PendingFile[],
                     message: t('files.denied.explain', { user: props.host.agent_user || '?', dir: listing.path }) }
    : null

  // firimiturile lungi derulează pe orizontală: arătăm capătul (directorul curent), nu rădăcina
  useEffect(() => {
    const el = crumbsRef.current
    if (el) el.scrollLeft = el.scrollWidth
  }, [listing?.path, editPath])

  // ── lăţimea coloanei (desktop): mânerul din marginea stângă, ca splitter-ul sidebar-ului ──
  const dragCleanup = useRef<(() => void) | null>(null)
  useEffect(() => () => dragCleanup.current?.(), [])
  const saveW = (w: number) => lsSet(WIDTH_KEY, String(w))
  const dragWidth = (e: React.PointerEvent) => {
    e.preventDefault()
    const x0 = e.clientX
    const w0 = asideRef.current?.getBoundingClientRect().width ?? colW
    // panoul e lipit de dreapta: tras spre stânga = mai lat
    const at = (ev: PointerEvent) => clampW(w0 + (x0 - ev.clientX))
    const move = (ev: PointerEvent) => setColW(at(ev))
    const detach = () => {
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
      dragCleanup.current = null
    }
    const up = (ev: PointerEvent) => { detach(); saveW(at(ev)) }
    dragCleanup.current = detach
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
  }

  const header = props.embed ? null : (
    <header className="flex items-center gap-2 border-b border-ink-800 px-3 py-2">
      <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">{t('files.title')}</span>
      <IconButton onClick={props.onClose} label={t('files.closeAria')} className="ml-auto"><CloseIcon size={14} /></IconButton>
    </header>
  )

  if (!isAgent) {
    return (
      <>
        <div className={scrimCls} onClick={props.onClose} aria-hidden="true" />
        {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- Escape pe regiunea drawer-ului (vezi useDrawer): intenţionat pe <aside>, nu pe document */}
        <aside ref={asideRef} aria-label={t('files.sessionAria')} className={asideCls} onKeyDown={drawer.onKeyDown}>
          {drawer.sheet && <SheetBar title={t('session.files')} onBack={props.onClose} />}
          {!drawer.sheet && header}
          <div className="flex flex-1 flex-col items-center justify-center gap-3 p-4 text-center">
            <p className="text-xs leading-relaxed text-slate-500">
              {t('files.noAgent', { type: props.host.connection_type?.toUpperCase() ?? '' })}
            </p>
          </div>
        </aside>
      </>
    )
  }

  const crumbList = crumbs(listing?.path ?? path)
  const rowMenuLabel = (name: string) => t('files.menuAria', { name })

  return (
    <>
      <div className={scrimCls} onClick={props.onClose} aria-hidden="true" />
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- Escape pe regiunea drawer-ului (vezi useDrawer); butoanele 4/5 ale mouse-ului = înapoi / înainte în panou */}
      <aside
        ref={asideRef}
        aria-label={t('files.sessionAria')}
        className={asideCls}
        style={columnMode ? { width: clampW(colW) } : undefined}
        onKeyDown={drawer.onKeyDown}
        // butoanele laterale ale mouse-ului (4 = înapoi, 5 = înainte): istoricul PANOULUI, nu al paginii
        // (care ar schimba ruta `#/s/…` şi ar ieşi din sesiune)
        onMouseDown={(e) => { if (e.button === 3 || e.button === 4) e.preventDefault() }}
        onMouseUp={(e) => {
          if (e.button !== 3 && e.button !== 4) return
          e.preventDefault()
          goHist(e.button === 3 ? -1 : 1)
        }}
        onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
        onDragLeave={() => { setDrag(false); setDropRow(null) }}
        onDrop={async (e) => {
          e.preventDefault(); setDrag(false); setDropRow(null)
          if (!listing) return
          startUpload(await collectDrop(e))
        }}
      >
        {/* mâner de lăţime (doar coloana de pe desktop): tras cu mouse-ul, ←/→ de la tastatură,
            dublu-click = lăţimea implicită — tiparul „window splitter" al sidebar-ului */}
        {columnMode && (
          <div role="separator" aria-orientation="vertical" tabIndex={0}
            aria-label={t('files.resizeAria')} title={t('files.resizeAria')}
            aria-valuenow={colW} aria-valuemin={W_MIN} aria-valuemax={W_MAX}
            data-testid="wt-files-resize"
            onPointerDown={dragWidth}
            onDoubleClick={() => { setColW(W_DEF); saveW(W_DEF) }}
            onKeyDown={(e) => {
              const d = e.key === 'ArrowLeft' ? 16 : e.key === 'ArrowRight' ? -16 : 0
              if (!d) return
              e.preventDefault()
              const w = clampW(colW + d)
              setColW(w); saveW(w)
            }}
            className="absolute inset-y-0 -left-1 z-10 w-2 cursor-col-resize rounded-md hover:bg-sky-500/30 focus:outline-none focus-visible:bg-sky-500/50" />
        )}
        {drawer.sheet && <SheetBar title={t('session.files')} onBack={props.onClose} />}
        {!drawer.sheet && header}

        {/* agent în urmă: mkdir/rename/delete/salvarea atomică cer agentul nou */}
        {props.host.update_pending && (
          <div className="border-b border-ink-800 bg-amber-950/40 px-3 py-1.5 text-2xs wt-warn">
            {t('files.oldAgent')}
          </div>
        )}

        {/* navigare: ‹ › ↑ + firimituri (click pe ultimul segment / ✎ / Ctrl+L = câmp editabil) */}
        <div className="flex items-center gap-1 border-b border-ink-800 px-2 py-1.5">
          <IconButton onClick={() => goHist(-1)} disabled={!canBack(hist)} label={t('files.back')}
            title={`${t('files.back')} (${fmt('Mod+[')})`} data-testid="wt-files-back"><ArrowLeftIcon size={13} /></IconButton>
          <IconButton onClick={() => goHist(1)} disabled={!canForward(hist)} label={t('files.forward')}
            title={`${t('files.forward')} (${fmt('Mod+]')})`} data-testid="wt-files-forward"><ArrowRightIcon size={13} /></IconButton>
          <IconButton onClick={goUp} disabled={!listing || listing.path === '/'}
            label={t('files.upLevel')}><LevelUpIcon size={14} /></IconButton>
          {editPath ? (
            <div className="relative min-w-0 flex-1">
              <input
                ref={pathInputRef}
                autoFocus
                value={pathDraft}
                aria-label={t('files.pathAria')}
                aria-describedby={completion ? 'wt-files-complete' : undefined}
                // o completare încă în zbor nu mai are voie să suprascrie ce tastezi (review L3)
                onChange={(e) => { completeSeq.current++; setPathDraft(e.target.value); setCompletion(null); noProgressRef.current = null }}
                onFocus={(e) => e.target.select()}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') { e.preventDefault(); navigate(pathDraft.trim() || '/') }
                  else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); endEditPath() }
                  else if (e.key === 'Tab' && !e.shiftKey && !e.altKey && !e.ctrlKey && !e.metaKey) void completeTab(e)
                }}
                onBlur={() => { if (editPath) endEditPath(false) }}
                spellCheck={false}
                autoCapitalize="off"
                autoCorrect="off"
                className="w-full rounded-md bg-ink-800 px-2 py-1 font-mono text-2xs text-slate-300 ring-1 ring-ink-700 focus:ring-sky-500"
                title={t('files.pathHint')}
              />
              {completion && (
                <div id="wt-files-complete" role="status" data-testid="wt-files-complete"
                  className="absolute inset-x-0 top-full z-30 mt-1 rounded-md border border-ink-700 bg-ink-900 px-2 py-1 font-mono text-2xs text-slate-400 shadow-xl">
                  {completion.none ? t('files.completeNone')
                    : completion.candidates.join('  ') + (completion.more ? ` ${t('files.andMore', { count: completion.more })}` : '')}
                </div>
              )}
            </div>
          ) : (
            <nav aria-label={t('files.crumbsAria')} className="flex min-w-0 flex-1">
              <div ref={crumbsRef} className="flex min-w-0 flex-1 items-center overflow-x-auto whitespace-nowrap [scrollbar-width:none]">
                <ol className="flex items-center">
                  {crumbList.map((c, i) => {
                    const last = i === crumbList.length - 1
                    return (
                      <li key={c.path} className="flex items-center">
                        {/* după rădăcina „/" fără separator (arată ca o cale: /tmp › x) */}
                        {(i > 1 || (i === 1 && crumbList[0].label !== '/')) && <span className="text-slate-600" aria-hidden="true"><ChevronIcon size={10} /></span>}
                        <button type="button" data-crumb={c.path}
                          aria-current={last ? 'location' : undefined}
                          // ultimul segment (directorul curent) → câmpul editabil; restul navighează
                          onClick={() => (last ? startEditPath() : navigate(c.path))}
                          title={last ? t('files.pathHint') : c.path}
                          className={`min-h-[24px] min-w-[24px] shrink-0 rounded-md px-1 py-0.5 font-mono text-2xs hover:bg-ink-800 [@media(pointer:coarse)]:min-h-11 [@media(pointer:coarse)]:min-w-11 ${
                            last ? 'font-semibold text-slate-100' : 'text-slate-400 hover:text-slate-200'}`}>
                          {c.label}
                        </button>
                      </li>
                    )
                  })}
                </ol>
              </div>
            </nav>
          )}
          {!editPath && (
            <IconButton onClick={startEditPath} label={t('files.editPath')} title={`${t('files.editPath')} (${fmt('Mod+L')})`}
              data-testid="wt-files-editpath"><PencilIcon size={13} /></IconButton>
          )}
          {deniedHere && (
            <span className="shrink-0 wt-warn" title={t('files.denied.badge', { user: props.host.agent_user || '?' })}
              data-testid="wt-files-lock">
              <LockIcon size={13} /><span className="sr-only">{t('files.denied.badge', { user: props.host.agent_user || '?' })}</span>
            </span>
          )}
        </div>

        {/* filtru + follow + hidden + acţiuni pe director (pe touch: „+"-ul flotant le ţine pe ultimele trei) */}
        <div className="flex items-center gap-1 border-b border-ink-800 px-2 py-1 text-2xs">
          <input
            ref={filterRef}
            value={filter}
            aria-label={t('files.filterAria')}
            onChange={(e) => { setFilter(e.target.value); setSel(0) }}
            // ↓ / Enter / Escape: înapoi în listă (Escape goleşte întâi filtrul)
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown' || e.key === 'Enter') { e.preventDefault(); listRef.current?.focus() }
              else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); if (filter) setFilter(''); else listRef.current?.focus() }
            }}
            placeholder={t('files.filterPh')}
            className="min-h-[28px] min-w-0 flex-1 rounded-md bg-ink-800/60 px-2 py-0.5 text-slate-300 ring-1 ring-ink-700 focus:ring-sky-500"
          />
          {/* „follow cwd" are sens doar legat de o sesiune; în embed (tab-ul hostului) nu avem una */}
          {!props.embed && (
            <button onClick={follow ? () => setFollow(false) : enableFollow} aria-pressed={follow}
              className={`inline-flex min-h-[28px] min-w-[28px] shrink-0 items-center gap-1 rounded-md px-1.5 py-0.5 ${follow ? 'wt-good ring-1 ring-emerald-600/40' : 'text-slate-500 hover:bg-ink-800'}`}
              title={t('files.followCwd')} aria-label={t('files.followCwd')}><ArrowsLeftRightIcon size={12} /> cwd</button>
          )}
          <button onClick={() => setShowHidden((v) => !v)} aria-pressed={showHidden}
            className={`min-h-[28px] min-w-[28px] shrink-0 rounded-md px-1.5 py-0.5 ${showHidden ? 'wt-link' : 'text-slate-500 hover:bg-ink-800'}`}
            title={t('files.showHidden')} aria-label={t('files.showHidden')}>.*</button>
          <IconButton onClick={() => load(listing?.path ?? path)} label={t('files.reload')} aria-keyshortcuts="F5"
            data-testid="wt-files-reload"><RefreshIcon /></IconButton>
          {/* deschiderea unuia închide restul: toolbar-ul rămâne interactiv deasupra modalului,
              iar un input montat SUB overlay i-ar fura focusul (tastezi într-un câmp invizibil) */}
          {/* motivele dezactivării (FL-09), referite prin aria-describedby de butoanele gri */}
          <span id={needsWriteId} className="sr-only">{needsWrite}</span>
          <span id={needsDeleteId} className="sr-only">{needsDelete}</span>
          {gate.write !== 'hidden' && (
            <>
              <IconButton onClick={startNewFile} disabled={!listing || !mayWrite} label={t('files.newFile')}
                title={mayWrite ? undefined : needsWrite} aria-describedby={mayWrite ? undefined : needsWriteId}
                aria-keyshortcuts="Alt+N" className="[@media(hover:none)]:hidden"><FilePlusIcon /></IconButton>
              <IconButton onClick={startNewFolder} disabled={!listing || !mayWrite} label={t('files.newDir')}
                title={mayWrite ? undefined : needsWrite} aria-describedby={mayWrite ? undefined : needsWriteId}
                aria-keyshortcuts="F7" className="[@media(hover:none)]:hidden"><PlusIcon /></IconButton>
              <IconButton onClick={pickUpload} disabled={busy || !listing || !mayWrite} label={t('files.uploadHere')}
                title={!mayWrite ? needsWrite : deniedHere ? t('files.denied.uploadHint', { user: props.host.agent_user || '?' }) : undefined}
                aria-describedby={mayWrite ? undefined : needsWriteId} aria-keyshortcuts="Control+U"
                variant="link" className="[@media(hover:none)]:hidden"><UploadIcon /></IconButton>
            </>
          )}
          <input ref={fileInput} type="file" multiple className="hidden" onChange={(e) => { if (e.target.files) pickFiles(e.target.files); e.target.value = ''; refocus() }} />
        </div>
        {/* sortare: ţinte de ≥24px (erau text de 10px fără padding) + direcţia anunţată, nu doar ▲/▼ */}
        <div className="flex items-center gap-1 border-b border-ink-800 px-2 text-2xs uppercase tracking-wide text-slate-600">
          {/* „Selectează tot" = ce se VEDE (filtrul şi .* respectate); tri-state */}
          <label className="grid h-6 w-6 shrink-0 cursor-pointer place-items-center [@media(pointer:coarse)]:h-9 [@media(pointer:coarse)]:w-9" title={t('files.selectAll')}>
            <input ref={selAllRef} type="checkbox" checked={allSel === 'all'} disabled={!view.length}
              aria-label={t('files.selectAll')} data-testid="wt-files-select-all"
              onChange={() => setSelection((s) => toggleAll(s, order))}
              className="h-3.5 w-3.5 cursor-pointer accent-sky-500 [@media(pointer:coarse)]:h-6 [@media(pointer:coarse)]:w-6" />
          </label>
          {(['name', 'size', 'mtime'] as SortKey[]).map((k) => (
            <button key={k} onClick={() => setSort((s) => ({ key: k, asc: s.key === k ? !s.asc : true }))}
              aria-pressed={sort.key === k}
              className={`inline-flex min-h-[24px] items-center gap-0.5 rounded-md px-1.5 py-1 hover:text-slate-400 ${sort.key === k ? 'text-slate-400' : ''}`}>
              {k === 'name' ? t('files.sortName') : k === 'size' ? t('files.sortSize') : t('files.sortDate')}{sort.key === k ? (sort.asc ? <ChevronUpIcon size={10} /> : <ChevronDownIcon size={10} />) : ''}
              {/* direcţia rămâne în numele accesibil (era ▲/▼ în text) */}
              {sort.key === k && <span className="sr-only"> {sort.asc ? t('files.sortAsc') : t('files.sortDesc')}</span>}
            </button>
          ))}
        </div>

        {deniedView && (
          <>
            <WriteDeniedBanner host={props.host} dir={deniedView.dir} message={deniedView.message}
              sessionId={props.sessionId} pending={deniedView.pending}
              onUploadHome={(fs) => void uploadHome(fs)}
              onDismiss={() => { clearDenied(props.host.id, deniedView.dir); setDenied(null) }}
              onMoved={() => uploads.filter((u) => u.state === 'err' && isWriteDenied(u.errorCode)
                && u.dest.slice(0, u.dest.lastIndexOf('/')) === deniedView.dir).forEach((u) => dismissUpload(u.id))} />
            {/* FS-02 (audit 2026-10-17): sub merged-usr calea LOGICĂ (/lib/firmware) pică verificarea
                `pwd -P` a comenzii de mutare ca root („is not the physical path of that folder"); până
                la realpath prin agent (v59), spunem calea fizică probabilă */}
            {physicalPathHint(deniedView.dir) && (
              <div className="border-b border-ink-800 bg-amber-950/30 px-3 py-1.5 text-2xs wt-warn" data-testid="wt-files-symlink-hint">
                {t('files.denied.symlinkHint', { real: physicalPathHint(deniedView.dir)! })}
              </div>
            )}
          </>
        )}
        {error && <div role="alert" className="border-b border-ink-800 bg-ink-800 px-3 py-1.5 text-2xs wt-danger">{error}
          {failedPath !== null && <button type="button" onClick={() => load(failedPath)} className="wt-link ml-2 min-h-6 hover:underline">{t('common.retry')}</button>}</div>}

        {/* rândul curent, anunţat cât lista are focusul (U10): săgeţile mutau doar un fundal —
            cititorul de ecran nu spunea nimic. Rândurile conţin butoane şi bife, deci nu pot fi
            `option`-uri într-un listbox; anunţul live e tiparul corect aici. */}
        <span className="sr-only" aria-live="polite" data-testid="wt-files-current">
          {listFocused && view[sel] ? t('files.rowAnnounce', {
            name: view[sel].name + (view[sel].dir ? '/' : ''), k: sel + 1, n: view.length,
          }) + (selection.keys.has(view[sel].name) ? ` · ${t('files.rowSelected')}` : '') : ''}
        </span>
        <div className="relative flex min-h-0 flex-1 flex-col">
        {/* `data-path` = directorul LISTAT (ţinta upload-urilor), nu textul din câmpul de cale —
            acela se schimbă la tastare, înainte ca listarea să se întoarcă.
            `data-files-list`: handler-ul global din App lasă `?` şi `/` listei (tastează-ca-să-sari / filtru). */}
        {/* eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex -- lista e ţinta roving focus-ului (role=group cu tastatura ei, vezi onKeyDown) */}
        <div ref={listRef} tabIndex={0} onKeyDown={onKeyDown} role="group" aria-label={t('files.listAria')}
          aria-keyshortcuts="Enter F2 F7 Delete Shift+F10"
          data-path={listing?.path ?? ''} data-files-list=""
          onFocus={(ev) => { if (ev.target === ev.currentTarget) setListFocused(true) }}
          onBlur={(ev) => { if (ev.target === ev.currentTarget) setListFocused(false) }}
          // click dreapta pe zona GOALĂ a listei: meniul directorului curent (nou / încarcă / cd aici)
          onContextMenu={(ev) => {
            if ((ev.target as HTMLElement).closest('[data-idx]') || lastPointerRef.current === 'touch' || !listing) return
            ev.preventDefault()
            setMenu({ kind: 'dir', dir: listing.path, x: ev.clientX, y: ev.clientY, sheet: false })
          }}
          className={`relative min-h-0 flex-1 overflow-y-auto outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[rgb(var(--focus))] ${drag ? 'ring-2 ring-inset ring-sky-500' : ''}`}>
          {/* peste un rând de director nu întunecăm lista (inelul rândului trebuie să se vadă);
              spunem jos, într-o linie, unde va ateriza */}
          {drag && !dropRow && (
            <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center bg-black/60 text-xs text-sky-200">
              {t('files.dropHere')}
            </div>
          )}
          {drag && dropRow && (
            <div className="pointer-events-none absolute inset-x-0 bottom-0 z-10 bg-ink-900/95 px-3 py-1 text-center font-mono text-2xs wt-accent">
              {t('transfers.dropIntoFolder', { name: dropRow })}
            </div>
          )}
          {newFolder !== null && (
            <div className="flex items-center gap-2 border-b border-ink-800/60 px-3 py-1">
              <FolderIcon />
              <input autoFocus value={newFolder} onChange={(e) => setNewFolder(e.target.value)} aria-label={t('files.newDir')}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') doMkdir(newFolder)
                  if (e.key === 'Escape') { e.stopPropagation(); setNewFolder(null); refocus() }
                }}
                onBlur={() => doMkdir(newFolder)} placeholder={t('files.newDirPh')}
                className="min-w-0 flex-1 rounded-md bg-ink-800 px-1.5 py-0.5 font-mono text-2xs text-slate-200 ring-1 ring-sky-500" />
            </div>
          )}
          {newFile !== null && (
            <div className="absolute inset-0 z-20 flex items-center justify-center bg-black/60 p-4"
              onClick={() => { setNewFile(null); refocus() }}>
              <div className="w-full max-w-xs rounded-xl bg-ink-900 p-3 shadow-xl ring-1 ring-ink-700"
                role="dialog" aria-labelledby="wt-files-newfile-title"
                onClick={(e) => e.stopPropagation()}>
                <div id="wt-files-newfile-title" className="mb-2 flex items-center gap-2 text-xs text-slate-300">
                  <FileIcon />{t('files.newFile')}
                </div>
                <input autoFocus value={newFile} aria-label={t('files.newFilePh')}
                  onChange={(e) => { setNewFile(e.target.value); if (newFileErr) setNewFileErr('') }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') doNewFile(newFile, 'empty')
                    if (e.key === 'Escape') { e.stopPropagation(); setNewFile(null); refocus() }
                  }}
                  placeholder={t('files.newFilePh')}
                  className="w-full rounded-md bg-ink-800 px-2 py-1 font-mono text-xs text-slate-200 outline-none ring-1 ring-sky-500" />
                {newFileErr && <div className="mt-1.5 text-2xs wt-danger">{newFileErr}</div>}
                <div className="mt-2.5 flex justify-end gap-2 text-xs">
                  <Button variant="ghost" size="sm" onClick={() => { setNewFile(null); refocus() }}>{t('files.cancel')}</Button>
                  <Button variant="secondary" size="sm" onClick={() => doNewFile(newFile, 'clipboard')} disabled={!newFile.trim()}>{t('files.newFromClip')}</Button>
                  <Button variant="primary" size="sm" onClick={() => doNewFile(newFile, 'empty')} disabled={!newFile.trim()}>{t('files.newEmpty')}</Button>
                </div>
              </div>
            </div>
          )}
          {view.map((e, i) => {
            const checked = selection.keys.has(e.name)
            const meta = `${e.dir ? '' : fmtSize(e.size) + ' · '}${fmtMtime(e.mtime)}`
            return (
            <div key={e.name} data-idx={i} data-selected={checked || undefined} data-row={e.name}
              className={`group flex items-center gap-2 py-1 pl-1 pr-3 text-xs [@media(pointer:coarse)]:select-none ${i === sel ? 'bg-ink-800' : checked ? 'bg-sky-500/10' : 'hover:bg-ink-800/60'} ${dropRow === e.name ? 'bg-sky-500/10 ring-2 ring-inset ring-sky-400' : ''}`}
              onClick={(ev) => {
                if (suppressClickRef.current) { suppressClickRef.current = false; return }   // capătul unui long-press
                // un click pe alt rând închide confirmarea de ştergere deschisă (review M1)
                if (confirmDel) setConfirmDel(null)
                // roving focus: un click pe rând lasă focusul pe LISTĂ (tastele merg imediat)
                if (!(ev.target as HTMLElement).closest('input,textarea')) listRef.current?.focus({ preventScroll: true })
                if (selectClick(ev, e, i)) return
                // touch, în modul selecţie: un tap oriunde pe rând îl comută
                if (lastPointerRef.current === 'touch' && selection.keys.size) { setSelection((s) => toggleKey(s, e.name)); setSel(i); return }
                setSel(i)
                // dublu-click / dublu-tap = deschide (director: intră; fişier: editor)
                const now = Date.now()
                if (now < navGuardRef.current) return
                const lc = lastClickRef.current
                if (lc && lc.name === e.name && now - lc.t < 450) { lastClickRef.current = null; navGuardRef.current = now + 450; openEntry(e); return }
                lastClickRef.current = { name: e.name, t: now }
              }}
              // Shift+click nu trebuie să selecteze TEXT între rânduri; nici dublu-click-ul (deschide)
              onMouseDown={(ev) => { if (ev.shiftKey || ev.detail > 1) ev.preventDefault() }}
              onPointerDown={(ev) => pressStart(ev, e, i)}
              onPointerMove={pressMove}
              onPointerUp={pressCancel}
              onPointerCancel={pressCancel}
              onPointerLeave={pressCancel}
              // long-press pe Android deschide altfel meniul de sistem (copiere text / link); cu mouse-ul:
              // meniul rândului (3.6.14) în locul celui al browserului
              onContextMenu={(ev) => {
                ev.preventDefault()
                if (lastPointerRef.current === 'touch') return
                setSel(i)
                openRowMenu(e, ev.clientX, ev.clientY, false)
              }}
              // drop pe un rând de DIRECTOR → upload în el (nu în directorul afişat). stopPropagation:
              // altfel handler-ul <aside> ar urca aceleaşi fişiere încă o dată în directorul curent.
              // `aria-dropeffect` e deprecat — indiciul pentru cititoare e un text ascuns vizual.
              onDragOver={e.dir ? (ev) => { ev.preventDefault(); ev.stopPropagation(); setDrag(true); setDropRow(e.name) } : undefined}
              onDragLeave={e.dir ? () => setDropRow((r) => (r === e.name ? null : r)) : undefined}
              onDrop={e.dir ? async (ev) => {
                ev.preventDefault(); ev.stopPropagation(); setDrag(false); setDropRow(null)
                if (!listing) return
                startUpload(await collectDrop(ev), join(listing.path, e.name))
              } : undefined}>
              {/* bifa: click-ul ei NU ajunge la rând (fără navigare / deschidere); Shift = interval */}
              <label className="grid h-6 w-6 shrink-0 cursor-pointer place-items-center [@media(pointer:coarse)]:h-9 [@media(pointer:coarse)]:w-9"
                onClick={(ev) => ev.stopPropagation()} onPointerDown={(ev) => ev.stopPropagation()}>
                <input type="checkbox" checked={checked} aria-label={t('files.selectRow', { name: e.name })}
                  tabIndex={-1}
                  onChange={() => { /* decide onClick, care vede Shift/Ctrl */ }}
                  onClick={(ev) => {
                    ev.stopPropagation()
                    setSelection((s) => (ev.shiftKey ? rangeTo(s, order, e.name, ev.ctrlKey || ev.metaKey) : toggleKey(s, e.name)))
                    setSel(i)
                  }}
                  className="h-3.5 w-3.5 cursor-pointer accent-sky-500 [@media(pointer:coarse)]:h-6 [@media(pointer:coarse)]:w-6" />
              </label>
              <span className={`shrink-0 ${e.dir ? 'wt-link' : e.link ? 'text-slate-400' : 'text-slate-500'}`}>
                {e.dir ? <FolderIcon /> : e.link ? <LinkIcon /> : <FileIcon />}
              </span>
              {e.dir && <span className="sr-only">{t('transfers.dropFolderHint')}</span>}
              {renaming === e.name ? (
                <input autoFocus defaultValue={e.name} aria-label={t('files.renameAria', { name: e.name })}
                  // numele fără extensie selectat (ca în orice manager de fişiere): tastezi direct noul nume
                  onFocus={(ev) => { const d = e.dir ? -1 : e.name.lastIndexOf('.'); ev.target.setSelectionRange(0, d > 0 ? d : e.name.length) }}
                  onKeyDown={(ev) => { if (ev.key === 'Enter') doRename(e, (ev.target as HTMLInputElement).value); if (ev.key === 'Escape') { ev.stopPropagation(); setRenaming(null); refocus(e.name) } }}
                  onBlur={(ev) => doRename(e, ev.target.value)}
                  className="min-w-0 flex-1 rounded-md bg-ink-800 px-1 py-0.5 font-mono text-2xs text-slate-100 ring-1 ring-sky-500" />
              ) : (
                // tabIndex=-1: tastatura stă pe listă (roving focus) — numele nu mai e o oprire de Tab
                <button type="button" tabIndex={-1} data-fname={e.name} onClick={(ev) => {
                    // un click simplu pe un DIRECTOR intră în el (ca un link); al doilea click al unui
                    // dublu-click nu mai deschide nimic din listarea nouă (navGuard). Fişier: rândul
                    // decide (selectează; dublu-click = editorul).
                    if (!e.dir || ev.shiftKey || ev.ctrlKey || ev.metaKey || suppressClickRef.current) return
                    if (lastPointerRef.current === 'touch' && selection.keys.size) return
                    ev.stopPropagation()
                    // al doilea click al unui dublu-click nu coboară încă un nivel (review L2)
                    if (Date.now() < navGuardRef.current) return
                    listRef.current?.focus({ preventScroll: true })
                    navGuardRef.current = Date.now() + 450
                    lastClickRef.current = null
                    navigate(join(listing!.path, e.name))
                  }}
                  // pe deget: rândul are măcar 36px (era 18px, sub pragul WCAG 2.5.8 de 24px); cu mouse rămâne compact
                  className={`flex min-w-0 flex-1 select-none flex-col items-start text-left font-mono [@media(pointer:coarse)]:min-h-[36px] [@media(pointer:coarse)]:justify-center ${e.dir ? 'wt-link' : 'text-slate-200'}`}
                  title={e.name}>
                  <span className="w-full truncate">{e.name}{e.dir ? '/' : ''}</span>
                  {/* foaie / drawer îngust: dimensiunea şi data SUB nume (în dreapta n-ar încăpea) */}
                  <span className={`w-full truncate text-2xs tabular-nums text-slate-500 ${compact ? '' : 'sm:hidden'}`}>{meta}</span>
                </button>
              )}
              {/* meta pe UN rând: mode · dim · data (ascunse când apar acțiunile) */}
              <span className={`shrink-0 items-center gap-2 font-mono text-2xs tabular-nums text-slate-600 ${compact ? 'hidden' : 'hidden sm:flex group-hover:sm:hidden group-focus-within:sm:hidden'}`}>
                <span>{fmtMode(e.mode)}</span>
                {!e.dir && <span className="w-10 text-right text-slate-500">{fmtSize(e.size)}</span>}
                <span className="min-w-[3rem] whitespace-nowrap text-right">{fmtMtime(e.mtime)}</span>
              </span>
              {/* acțiuni la hover (mouse) / la focus în rând (tastatură). Ţinte de 24px, fiecare cu
                  etichetă care numeşte intrarea; „⋯" = meniul complet (acelaşi ca la click dreapta).
                  Pe touch (fără hover): doar „⋯" de 44px, care deschide foaia de acţiuni. */}
              {/* stopPropagation: o acţiune pe rând (ex. Şterge) nu e şi un tap de selecţie pe touch */}
              {/* eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions -- doar opreşte bubbling-ul spre rând; butoanele din el au tastatura lor */}
              <div onClick={(ev) => { ev.stopPropagation(); setSel(i) }} className="hidden shrink-0 items-center gap-0.5 group-hover:flex group-focus-within:flex [@media(hover:none)]:!hidden">
                {!e.dir && (
                  <IconButton touch={false} onClick={() => edit(e)} title={t('files.edit')} label={`${t('files.edit')} ${e.name}`}><PencilIcon /></IconButton>
                )}
                {!e.dir && (
                  <IconButton touch={false} onClick={() => download(e)} title={t('files.download')} label={`${t('files.download')} ${e.name}`}><DownloadIcon /></IconButton>
                )}
                {/* directoarele nu au download simplu — dar au arhivă (tar.gz pe host) */}
                {e.dir && (
                  <button onClick={() => downloadArchive(e)} className="grid h-6 w-6 place-items-center rounded-md text-slate-500 hover:bg-ink-700 hover:text-slate-200"
                    title={t('files.downloadArchive')} aria-label={t('files.downloadArchiveAria', { name: e.name })}><DownloadIcon /></button>
                )}
                {gate.write !== 'hidden' && (
                  <IconButton touch={false} onClick={() => startRename(e.name)} disabled={!mayWrite}
                    title={mayWrite ? t('files.rename') : needsWrite} aria-describedby={mayWrite ? undefined : needsWriteId}
                    label={t('files.renameAria', { name: e.name })}><RenameIcon /></IconButton>
                )}
                {gate.del !== 'hidden' && (
                  <IconButton touch={false} variant="danger" disabled={!mayDelete}
                    onClick={() => { if (listing && deleteAllowed()) setConfirmDel({ ...e, at: listing.path }) }}
                    title={mayDelete ? t('files.delete') : needsDelete} aria-describedby={mayDelete ? undefined : needsDeleteId}
                    label={`${t('files.delete')} ${e.name}`}><TrashIcon /></IconButton>
                )}
                <IconButton touch={false} aria-haspopup="menu" data-testid="wt-files-more"
                  onClick={(ev) => { const r = (ev.currentTarget as HTMLElement).getBoundingClientRect(); setSel(i); openRowMenu(e, r.right - 224, r.bottom, false) }}
                  title={t('files.moreActions')} label={t('files.more', { name: e.name })}><MoreIcon size={14} /></IconButton>
              </div>
              {/* touch: un singur „⋯" de 44px (în locul celor patru pictograme de 24px) */}
              <button type="button" aria-haspopup="menu" aria-label={t('files.more', { name: e.name })}
                data-testid="wt-files-more-touch"
                onClick={(ev) => { ev.stopPropagation(); setSel(i); openRowMenu(e, 0, 0, true) }}
                onPointerDown={(ev) => ev.stopPropagation()}
                className="hidden h-11 w-11 shrink-0 place-items-center rounded-md text-slate-400 hover:bg-ink-800 [@media(hover:none)]:grid">
                <MoreIcon size={18} />
              </button>
            </div>
            )
          })}
          {listing && view.length === 0 && (
            <div className="px-3 py-6 text-center text-2xs text-slate-500">
              {filter ? t('files.emptyFilter') : t('files.emptyDir')}
              {/* indiciu de upload DOAR în starea goală — nu o zonă punctată permanentă */}
              {!filter && <div className="wt-muted mt-1 text-2xs">{t('transfers.emptyHint')}</div>}
            </div>
          )}
          {listing?.truncated && (
            <div className="px-3 py-2 text-center text-2xs wt-warn">{t('files.truncated')}</div>
          )}
          {/* loc sub ultimul rând, ca butonul flotant „+" să nu-l acopere (touch) */}
          <div className="hidden h-16 [@media(hover:none)]:block" aria-hidden="true" />
        </div>
        {/* „+" flotant (touch): fişier nou / dosar nou / încarcă — înlocuieşte cele trei pictograme din bară */}
        {listing && !picked.length && gate.write !== 'hidden' && (
          <button type="button" aria-haspopup="menu" aria-label={t('files.fabAria')} data-testid="wt-files-fab"
            onClick={(ev) => { const r = (ev.currentTarget as HTMLElement).getBoundingClientRect(); if (listing) setMenu({ kind: 'new', dir: listing.path, x: r.left, y: r.top, sheet: true }) }}
            className="absolute bottom-3 right-3 z-10 hidden h-12 w-12 place-items-center rounded-full bg-sky-600 text-white shadow-xl hover:bg-sky-500 [@media(hover:none)]:grid">
            <PlusIcon size={20} />
          </button>
        )}
        </div>

        {/* bara de selecţie: „N selectate · Descarcă · Şterge · Copiază pe host… · Renunţă" — lipită
            jos (pe telefon: deasupra barei de gesturi, prin safe-area-ul foii) */}
        {picked.length > 0 && (
          <div role="toolbar" aria-label={t('files.selBarAria')} data-testid="wt-files-selbar"
            className="sticky bottom-0 z-10 flex flex-wrap items-center gap-1 border-t border-ink-800 bg-ink-800/95 px-2 py-1 text-2xs [@media(hover:none)]:py-1.5">
            <span className="mr-1 font-medium text-slate-200" aria-live="polite">{t('files.selCount', { count: picked.length })}</span>
            <Button variant="ghost" size="sm" onClick={bulkDownload} className="wt-touch">
              <DownloadIcon />{t('files.download')}</Button>
            {gate.del !== 'hidden' && (
              <Button variant="ghost" size="sm" onClick={() => { if (deleteAllowed()) { setConfirmDel(null); setConfirmBulk(picked) } }}
                disabled={busy || !mayDelete} title={mayDelete ? undefined : needsDelete}
                aria-describedby={mayDelete ? undefined : needsDeleteId} className="wt-touch">
                <TrashIcon />{t('files.delete')}</Button>
            )}
            <Button variant="ghost" size="sm" onClick={openCopy} title={t('copy.open')} className="wt-touch">
              <CopyIcon />{t('copy.open')}</Button>
            <Button variant="ghost" size="sm" onClick={() => setSelection(EMPTY_SELECTION)} className="wt-touch ml-auto">
              {t('files.selClear')}</Button>
          </div>
        )}

        {confirmBulk && (() => {
          const pv = previewNames(confirmBulk.map((e) => e.name))
          const nDirs = confirmBulk.filter((e) => e.dir).length
          return (
            // eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- Escape anulează confirmarea (nu închide panoul)
            <div className="border-t border-ink-800 bg-ink-800/80 px-3 py-2 text-2xs" role="alertdialog" aria-label={t('files.bulkDeleteTitle')}
              onKeyDownCapture={(e) => { if (e.repeat && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); e.stopPropagation() } }}
              onKeyDown={(e) => { if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); cancelDelete() } }}>
              <p className="text-slate-300">{t('files.bulkDeleteConfirm', { count: confirmBulk.length })}</p>
              <p className="mt-0.5 break-all font-mono wt-danger">
                {pv.shown.join(', ')}{pv.more ? ` ${t('files.andMore', { count: pv.more })}` : ''}
              </p>
              {nDirs > 0 && <p className="mt-0.5 wt-warn">{t('files.bulkDeleteDirs', { count: nDirs })}</p>}
              <div className="mt-1.5 flex gap-2">
                <Button variant="ghost" size="sm" autoFocus onClick={cancelDelete}>{t('files.cancel')}</Button>
                <Button variant="danger" size="sm" onClick={() => void doBulkDelete(confirmBulk)}>
                  {t('files.bulkDeleteGo', { count: confirmBulk.length })}</Button>
              </div>
            </div>
          )
        })()}

        {/* confirmare ștergere (inline, nu window.confirm): „Şterge" are focusul — Enter confirmă,
            Escape anulează; focusul se întoarce pe listă */}
        {confirmDel && (
          // eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- Escape anulează confirmarea (nu închide panoul)
          <div className="border-t border-ink-800 bg-ink-800/80 px-3 py-2 text-2xs" role="alertdialog"
            aria-labelledby="wt-files-del-q" data-testid="wt-files-confirm-delete"
            // tasta ţinută apăsată (auto-repeat) nu activează butoanele de aici (review M1)
            onKeyDownCapture={(e) => { if (e.repeat && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); e.stopPropagation() } }}
            onKeyDown={(e) => { if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); cancelDelete() } }}>
            <p id="wt-files-del-q" className="mb-1.5 text-slate-300">
              {t('files.deletePrefix')} <span className="break-all font-mono wt-danger">{join(confirmDel.at, confirmDel.name)}</span>
              {confirmDel.dir ? t('files.deleteSuffixDir') : '?'}
            </p>
            <div className="flex gap-2">
              {/* focusul pe Anulează (ca la ştergerea în bloc): un Enter rătăcit nu şterge nimic */}
              <Button variant="ghost" size="sm" autoFocus onClick={cancelDelete}>{t('files.cancel')}</Button>
              <Button variant="danger" size="sm" onClick={() => doDelete(confirmDel)}>{t('files.delete')}</Button>
            </div>
          </div>
        )}

        {/* confirmare overwrite (pe coliziuni de fișiere existente) */}
        {overwrite && (
          <div className="border-t border-ink-800 bg-ink-800/80 px-3 py-2 text-2xs">
            <p className="mb-1.5 text-slate-300">{t('files.overwrite', { count: overwrite.count })}</p>
            <div className="flex gap-2">
              <button onClick={() => reallyUpload(overwrite.items)} className="rounded-md bg-amber-600 px-2 py-0.5 font-medium text-white hover:bg-amber-700">{t('files.overwrite')}</button>
              <Button variant="ghost" size="sm" onClick={() => setOverwrite(null)}>{t('files.cancel')}</Button>
            </div>
          </div>
        )}

        {uploads.length > 0 && (
          <div className="max-h-28 overflow-y-auto border-t border-ink-800 px-3 py-1 text-2xs">
            {uploads.map((u) => {
              const live = isActive(u)
              const label = live ? t('files.cancelUpload') : t('files.dismissUpload')
              return (
                <div key={u.id} className="py-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-slate-400" title={u.dest}>{u.name}</span>
                    <span className={`ml-auto tabular-nums ${u.state === 'done' ? 'wt-good' : u.state === 'err' ? 'wt-danger'
                      : u.state === 'stalled' || u.state === 'retrying' ? 'wt-warn' : 'wt-link'}`}>
                      {u.state === 'done' ? <CheckIcon size={12} /> : u.state === 'err' ? <CloseIcon size={12} />
                        : u.state === 'stalled' ? t('jobs.stateStalled')
                        : u.state === 'retrying' ? t('jobs.stateRetrying', { n: u.attempts, max: 8 })
                        : sizeKnown(u) ? `${u.pct}%` : fmtBytes(u.pos)}
                    </span>
                    <IconButton touch={false} variant="danger" onClick={() => cancelOrDismiss(u.id, live)}
                      title={label} label={`${label} ${u.name}`}><CloseIcon size={14} /></IconButton>
                  </div>
                  {/* bară de progres: se umple pe octeți (XHR onprogress), colorată după stare */}
                  <div className="mt-0.5 h-1 w-full overflow-hidden rounded-full bg-ink-800">
                    <div
                      className={`h-full rounded-full transition-[width] duration-200 ease-out motion-reduce:transition-none ${
                        u.state === 'err' ? 'bg-rose-500' : u.state === 'done' ? 'bg-emerald-500'
                        : u.state === 'stalled' || u.state === 'retrying' ? 'bg-amber-500' : 'bg-sky-500'}`}
                      style={{ width: `${u.state === 'err' ? 100 : u.pct}%` }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </aside>

      {menu && (
        <FileMenu items={menuItems(menu)} at={{ x: menu.x, y: menu.y }} sheet={menu.sheet}
          title={menu.kind === 'row' ? menu.entry.name + (menu.entry.dir ? '/' : '') : undefined}
          label={menu.kind === 'row' ? rowMenuLabel(menu.entry.name) : menu.kind === 'new' ? t('files.fabAria') : t('files.dirMenuAria')}
          anchor={listRef.current} onClose={closeMenu} />
      )}

      {copyItems && (
        <CopyToHostDialog srcHost={props.host} items={copyItems} onClose={() => { setCopyItems(null); refocus() }}
          onStarted={() => setSelection(EMPTY_SELECTION)} />
      )}

      {/* editor CodeMirror (lazy) — highlight, fișiere mari view-only, conflict */}
      {editing && (
        <Suspense fallback={<div className="wt-editor fixed inset-0 z-[60] flex items-center justify-center bg-black/60 text-sm text-slate-400">{t('files.loadingEditor')}</div>}>
          <FileEditor
            hostId={props.host.id}
            path={editing.path}
            name={editing.name}
            onClose={() => {
              // la închidere focusul revine pe LISTĂ, cu rândul fişierului selectat (roving focus) —
              // înainte cădea pe butonul „Edit" al rândului, ascuns fără hover, deci pe <body>
              const name = editing.name
              setEditing(null)
              refocus(name)
            }}
            onSaved={() => load(listing!.path)}
          />
        </Suspense>
      )}
    </>
  )
}
