import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react'
import { errText, api, Host } from '../lib/api'
import { copyText, readText } from '../lib/clipboard'
import { getCwd } from '../lib/cwd'
import { useI18n } from '../lib/i18n'
import { SHEET_CLS } from '../lib/sheet'
import { useDrawer } from '../lib/useDrawer'
import SheetBar from './SheetBar'
import { cancelUpload, dismissUpload, isUploadBusy, startUpload as engineStart, takeFilesDir } from '../lib/uploads'
import { BulkItem, startArchiveDownload, startDownload, startDownloads } from '../lib/downloads'
import { isActive, sizeKnown, uploadStore } from '../lib/uploadStore'
import { fmtBytes } from '../lib/uploads'
import { uiLocale } from '../lib/tz'
import {
  EMPTY_SELECTION, Selection, allState, previewNames, prune, rangeTo, toggleAll, toggleKey, visibleSelected,
} from '../lib/selection'
import { ArrowsLeftRightIcon, CheckIcon, ChevronDownIcon, ChevronUpIcon, CloseIcon, CopyIcon, DownloadIcon, FileIcon, FilePlusIcon, FolderIcon, LevelUpIcon, LinkIcon, PencilIcon, PlusIcon, RefreshIcon, RenameIcon, TrashIcon, UploadIcon } from './Icons'
import CopyToHostDialog, { CopyItem } from './CopyToHostDialog'
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
  const drawer = useDrawer(asideRef, props.onClose, !props.embed)
  // `embed`: panoul umple un tab din pagina hostului (full-width, fără drawer/scrim/close).
  // Altfel: pe pane-uri înguste (split pe iPad) e DRAWER peste terminal, nu coloană statică —
  // o coloană de 320px într-un pane de 240px strivește terminalul la ~0px.
  const asideCls = drawer.sheet ? SHEET_CLS : props.embed
    ? 'flex h-full w-full min-h-0 flex-col bg-ink-900'
    : 'fixed inset-y-0 right-0 z-40 flex w-[90vw] max-w-sm flex-col border-l border-ink-800 bg-ink-900 shadow-2xl outline-none'
    + (props.overlay ? '' : ' sm:static sm:z-auto sm:w-80 sm:max-w-none sm:shrink-0 sm:shadow-none')
  const scrimCls = props.embed ? 'hidden' : 'fixed inset-0 z-30 bg-black/60' + (props.overlay ? '' : ' sm:hidden')
  const [listing, setListing] = useState<Listing | null>(null)
  const [path, setPath] = useState('~')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  // starea upload-urilor stă în uploadStore (nivel de modul), NU în componentă: transferul
  // supravieţuieşte închiderii panoului, iar redeschiderea îl arată în mers, cu cancel funcţional
  const uploadsAll = useSyncExternalStore(uploadStore.subscribe, uploadStore.snapshot)
  // doar job-urile acestui host; orfanii (după reload, fără File) trăiesc numai în bara globală
  const uploads = useMemo(
    () => [...uploadsAll.values()].filter((j) => j.hostId === props.host.id && j.state !== 'orphan'),
    [uploadsAll, props.host.id])
  const [overwrite, setOverwrite] = useState<{ items: UpItem[]; count: number } | null>(null)
  const [drag, setDrag] = useState(false)
  // drop ţintit pe un RÂND de director: fişierele intră acolo, nu în directorul afişat
  const [dropRow, setDropRow] = useState<string | null>(null)
  const [editing, setEditing] = useState<{ path: string; name: string } | null>(null)
  // urmărește cwd-ul din terminal (OSC 7). Navigarea manuală îl oprește, ca să
  // poți explora în altă parte fără să fii „tras” înapoi la fiecare comandă.
  const [follow, setFollow] = useState(true)
  const [filter, setFilter] = useState('')
  const [showHidden, setShowHidden] = useState(false)
  const [sort, setSort] = useState<{ key: SortKey; asc: boolean }>({ key: 'name', asc: true })
  const [sel, setSel] = useState(0)                 // index selectat (tastatură)
  const [renaming, setRenaming] = useState<string | null>(null)
  const [newFolder, setNewFolder] = useState<string | null>(null)
  const [newFile, setNewFile] = useState<string | null>(null)
  const [newFileErr, setNewFileErr] = useState('')
  const [confirmDel, setConfirmDel] = useState<Entry | null>(null)
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

  const load = useCallback(async (p: string) => {
    // generație monotonă: dacă navighezi rapid (sau un event OSC 7 întârziat
    // sosește după un click manual), doar răspunsul CEL MAI RECENT se aplică —
    // altfel un director lent ar suprascrie unul mai nou și operațiile
    // ulterioare (upload/delete) ar ținti calea greșită.
    const my = ++loadSeq.current
    setError('')
    try {
      const l = await api<Listing>(`/api/hosts/${props.host.id}/fs?path=${encodeURIComponent(p)}`)
      if (my !== loadSeq.current) return          // un load mai nou a pornit între timp
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
      setError(errText(e, t) || t('files.genericErr'))
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
  const navigate = (p: string) => { setFollow(false); load(p) }
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

  async function download(e: Entry) {
    // Prin MOTORUL de transfer (phase 2): progres, retry, pauză şi reluare, vizibile în chip/bară —
    // nu mai e un `<a download>` oarbă care, pe un fişier de 40 GB picat la 90%, reîncepe de la zero.
    // `startDownload` cheamă selectorul de fişier (File System Access) ÎNTÂI, cât încă avem gestul
    // click-ului; fişierele mari curg pe disc, cele mici cad pe Blob. Fişier prea mare fără FS
    // Access → eroare clară (o prindem aici).
    try {
      await startDownload({ hostId: props.host.id, hostName: props.host.name,
                            path: join(listing!.path, e.name), name: e.name, size: e.size })
    } catch (err) {
      setError(errText(err, t) || t('files.genericErr'))
    }
  }

  // director → tar.gz făcut pe host, acum prin MOTORUL de transfer (3.5.5): rând în Transferuri cu
  // „se pregăteşte arhiva…" cât rulează tar-ul (până la 5 min), octeţii primiţi, Cancel şi eroarea
  // serverului. Nu e resumabil (arhivă generată din mers) — Retry o reporneşte.
  async function downloadArchive(e: Entry) {
    try {
      await startArchiveDownload({ hostId: props.host.id, hostName: props.host.name,
                                   path: join(listing!.path, e.name), name: `${e.name}.tgz` })
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
    await load(dir)
    // ce a eşuat rămâne selectat (poţi reîncerca / vedea ce a rămas); restul a dispărut din listare
    setSelection({ keys: new Set(failedNames), anchor: null })
    if (failed.length) setError(t('files.bulkDeleteFailed', { count: failed.length, total: items.length }) + ' ' + failed.slice(0, 3).join('; '))
  }

  function openCopy() {
    if (!listing || !picked.some((e) => !e.dir)) return
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
  function edit(e: Entry) {
    setError('')
    setEditing({ path: join(listing!.path, e.name), name: e.name })
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
    for (const d of [...dirs].sort()) {
      try { await api(`/api/hosts/${props.host.id}/fs/mkdir`, { method: 'POST', body: JSON.stringify({ path: join(base, d), parents: true }) }) } catch { /* există deja */ }
    }
    for (const it of items) await uploadOne(join(base, it.rel), it.rel, it.file)
    setBusy(false)
    load(listing.path)
  }

  function pickFiles(files: FileList | File[]) {
    startUpload(Array.from(files).map((f) => ({ file: f, rel: f.name })))
  }

  async function doMkdir(name: string) {
    const n = name.trim()
    setNewFolder(null)
    if (!n || !listing) return
    try {
      await api(`/api/hosts/${props.host.id}/fs/mkdir`, { method: 'POST', body: JSON.stringify({ path: join(listing.path, n) }) })
      load(listing.path)
    } catch (e) { setError(errText(e, t) || t('files.genericErr')) }
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
    } catch (e) { setError(errText(e, t) || t('files.genericErr')) }
  }

  // dublu-click pe un fişier copiază numele, triplu-click copiază calea completă (ca-n terminal:
  // cuvânt vs. linie). Prin `copyText` (nu navigator.clipboard direct): are rezerva execCommand
  // pentru instalările fără TLS şi toast-ul standard de „copiat" — acelaşi feedback ca peste tot.
  async function copyToClip(text: string) {
    if (!(await copyText(text))) setError(t('files.copyFailed'))
  }

  async function doRename(e: Entry, name: string) {
    const n = name.trim()
    setRenaming(null)
    if (!n || n === e.name || !listing) return
    try {
      await api(`/api/hosts/${props.host.id}/fs/rename`, {
        method: 'POST', body: JSON.stringify({ path: join(listing.path, e.name), to: join(listing.path, n) }),
      })
      load(listing.path)
    } catch (err) { setError(errText(err, t) || t('files.genericErr')) }
  }

  async function doDelete(e: Entry) {
    setConfirmDel(null)
    if (!listing) return
    try {
      await api(`/api/hosts/${props.host.id}/fs/delete`, {
        method: 'POST', body: JSON.stringify({ path: join(listing.path, e.name), recursive: e.dir }),
      })
      load(listing.path)
    } catch (err) { setError(errText(err, t) || t('files.genericErr')) }
  }

  function onKeyDown(ev: React.KeyboardEvent) {
    // Escape cu confirmarea de ştergere deschisă = anulează confirmarea, nu închide panoul
    if (ev.key === 'Escape' && (confirmDel || confirmBulk)) {
      ev.preventDefault(); ev.stopPropagation(); setConfirmDel(null); setConfirmBulk(null); return
    }
    // Escape cu o selecţie = goleşte selecţia (al doilea Escape închide panoul, ca înainte)
    if (ev.key === 'Escape' && selection.keys.size) { ev.preventDefault(); ev.stopPropagation(); setSelection(EMPTY_SELECTION); return }
    if (editing || renaming || newFolder !== null || newFile !== null || confirmDel || confirmBulk) return
    // Shift+săgeţi: extinde selecţia de la ancoră (sau de la rândul curent, dacă nu e ancoră)
    if (ev.shiftKey && (ev.key === 'ArrowDown' || ev.key === 'ArrowUp')) {
      ev.preventDefault()
      if (!view.length) return
      const next = ev.key === 'ArrowDown' ? Math.min(view.length - 1, sel + 1) : Math.max(0, sel - 1)
      const cur = view[sel]?.name ?? view[0].name
      setSelection((s) => rangeTo(s.anchor != null && order.includes(s.anchor) ? s : { ...s, anchor: cur }, order, view[next].name))
      setSel(next)
      return
    }
    if (ev.key === ' ') {                 // Space: comută rândul focalizat
      const e = view[sel]; if (!e) return
      ev.preventDefault()
      setSelection((s) => toggleKey(s, e.name))
      return
    }
    if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'a') {   // Ctrl/Cmd+A: tot ce se vede
      ev.preventDefault()
      setSelection((s) => toggleAll(s, order))
      return
    }
    if (ev.key === 'ArrowDown') { ev.preventDefault(); setSel((s) => Math.min(view.length - 1, s + 1)) }
    else if (ev.key === 'ArrowUp') { ev.preventDefault(); setSel((s) => Math.max(0, s - 1)) }
    else if (ev.key === 'Enter') {
      const e = view[sel]; if (!e) return
      ev.preventDefault()
      if (e.dir) navigate(join(listing!.path, e.name)); else edit(e)
    } else if (ev.key === 'Backspace') {
      ev.preventDefault(); if (listing && listing.path !== '/') navigate(listing.parent)
    } else if (ev.key === 'Delete') {
      // cu o selecţie: ştergerea în bloc (o singură confirmare); altfel rândul curent, ca înainte
      if (picked.length) { ev.preventDefault(); setConfirmDel(null); setConfirmBulk(picked); return }
      const e = view[sel]; if (e) { ev.preventDefault(); setConfirmDel(e) }
    }
  }

  // menține selecția vizibilă la navigarea din tastatură
  useEffect(() => {
    const el = listRef.current?.querySelector(`[data-idx="${sel}"]`)
    el?.scrollIntoView({ block: 'nearest' })
  }, [sel])

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

  return (
    <>
      <div className={scrimCls} onClick={props.onClose} aria-hidden="true" />
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- Escape pe regiunea drawer-ului (vezi useDrawer) */}
      <aside
        ref={asideRef}
        aria-label={t('files.sessionAria')}
        className={asideCls}
        onKeyDown={drawer.onKeyDown}
        onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
        onDragLeave={() => { setDrag(false); setDropRow(null) }}
        onDrop={async (e) => {
          e.preventDefault(); setDrag(false); setDropRow(null)
          if (!listing) return
          startUpload(await collectDrop(e))
        }}
      >
        {drawer.sheet && <SheetBar title={t('session.files')} onBack={props.onClose} />}
        {!drawer.sheet && header}

        {/* agent în urmă: mkdir/rename/delete/salvarea atomică cer agentul nou */}
        {props.host.update_pending && (
          <div className="border-b border-ink-800 bg-amber-950/40 px-3 py-1.5 text-2xs wt-warn">
            {t('files.oldAgent')}
          </div>
        )}

        {/* bara de cale + acțiuni pe director */}
        <div className="flex items-center gap-1 border-b border-ink-800 px-2 py-1.5">
          <IconButton onClick={() => listing && navigate(listing.parent)} disabled={!listing || listing.path === '/'}
            label={t('files.upLevel')}><LevelUpIcon size={14} /></IconButton>
          <input
            value={path}
            aria-label={t('files.pathAria')}
            onChange={(e) => setPath(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && navigate(path)}
            spellCheck={false}
            className="min-w-0 flex-1 rounded-md bg-ink-800 px-2 py-1 font-mono text-2xs text-slate-300 ring-1 ring-ink-700 focus:ring-sky-500"
            title={t('files.pathHint')}
          />
          <IconButton onClick={() => load(listing?.path ?? path)} label={t('files.reload')}><RefreshIcon /></IconButton>
          {/* deschiderea unuia închide restul: toolbar-ul rămâne interactiv deasupra modalului,
              iar un input montat SUB overlay i-ar fura focusul (tastezi într-un câmp invizibil) */}
          <IconButton onClick={() => { setNewFileErr(''); setNewFolder(null); setRenaming(null); setConfirmDel(null); setNewFile('') }} disabled={!listing} label={t('files.newFile')}><FilePlusIcon /></IconButton>
          <IconButton onClick={() => { setNewFile(null); setNewFileErr(''); setNewFolder('') }} label={t('files.newDir')}><PlusIcon /></IconButton>
          <IconButton onClick={() => fileInput.current?.click()} disabled={busy || !listing} label={t('files.uploadHere')} className="wt-link"><UploadIcon /></IconButton>
          <input ref={fileInput} type="file" multiple className="hidden" onChange={(e) => { if (e.target.files) pickFiles(e.target.files); e.target.value = '' }} />
        </div>

        {/* filtru + follow + hidden + sort */}
        <div className="flex items-center gap-1 border-b border-ink-800 px-2 py-1 text-2xs">
          <input
            value={filter}
            aria-label={t('files.filterAria')}
            onChange={(e) => { setFilter(e.target.value); setSel(0) }}
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

        {error && <div className="border-b border-ink-800 bg-ink-800 px-3 py-1.5 text-2xs wt-danger">{error}</div>}

        <div ref={listRef} tabIndex={0} onKeyDown={onKeyDown}
          className={`relative min-h-0 flex-1 overflow-y-auto outline-none ${drag ? 'ring-2 ring-inset ring-sky-500' : ''}`}>
          {/* peste un rând de director nu întunecăm lista (inelul rândului trebuie să se vadă);
              spunem jos, într-o linie, unde va ateriza */}
          {drag && !dropRow && (
            <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center bg-black/60 text-xs text-sky-200">
              {t('files.dropHere')}
            </div>
          )}
          {drag && dropRow && (
            <div className="pointer-events-none absolute inset-x-0 bottom-0 z-10 bg-ink-900/95 px-3 py-1 text-center font-mono text-2xs text-sky-200">
              {t('transfers.dropIntoFolder', { name: dropRow })}
            </div>
          )}
          {newFolder !== null && (
            <div className="flex items-center gap-2 border-b border-ink-800/60 px-3 py-1">
              <FolderIcon />
              <input autoFocus value={newFolder} onChange={(e) => setNewFolder(e.target.value)} aria-label={t('files.newDir')}
                onKeyDown={(e) => { if (e.key === 'Enter') doMkdir(newFolder); if (e.key === 'Escape') { e.stopPropagation(); setNewFolder(null) } }}
                onBlur={() => doMkdir(newFolder)} placeholder={t('files.newDirPh')}
                className="min-w-0 flex-1 rounded-md bg-ink-800 px-1.5 py-0.5 font-mono text-2xs text-slate-200 ring-1 ring-sky-500" />
            </div>
          )}
          {newFile !== null && (
            <div className="absolute inset-0 z-20 flex items-center justify-center bg-black/60 p-4"
              onClick={() => setNewFile(null)}>
              <div className="w-full max-w-xs rounded-xl bg-ink-900 p-3 shadow-xl ring-1 ring-ink-700"
                role="dialog" aria-labelledby="wt-files-newfile-title"
                onClick={(e) => e.stopPropagation()}>
                <div id="wt-files-newfile-title" className="mb-2 flex items-center gap-2 text-xs text-slate-300">
                  <FileIcon />{t('files.newFile')}
                </div>
                <input autoFocus value={newFile} aria-label={t('files.newFilePh')}
                  onChange={(e) => { setNewFile(e.target.value); if (newFileErr) setNewFileErr('') }}
                  onKeyDown={(e) => { if (e.key === 'Enter') doNewFile(newFile, 'empty'); if (e.key === 'Escape') { e.stopPropagation(); setNewFile(null) } }}
                  placeholder={t('files.newFilePh')}
                  className="w-full rounded-md bg-ink-800 px-2 py-1 font-mono text-xs text-slate-200 outline-none ring-1 ring-sky-500" />
                {newFileErr && <div className="mt-1.5 text-2xs wt-danger">{newFileErr}</div>}
                <div className="mt-2.5 flex justify-end gap-2 text-xs">
                  <Button variant="ghost" size="sm" onClick={() => setNewFile(null)}>{t('files.cancel')}</Button>
                  <Button variant="secondary" size="sm" onClick={() => doNewFile(newFile, 'clipboard')} disabled={!newFile.trim()}>{t('files.newFromClip')}</Button>
                  <Button variant="primary" size="sm" onClick={() => doNewFile(newFile, 'empty')} disabled={!newFile.trim()}>{t('files.newEmpty')}</Button>
                </div>
              </div>
            </div>
          )}
          {view.map((e, i) => {
            const checked = selection.keys.has(e.name)
            return (
            <div key={e.name} data-idx={i} data-selected={checked || undefined}
              className={`group flex items-center gap-2 py-1 pl-1 pr-3 text-xs [@media(pointer:coarse)]:select-none ${i === sel ? 'bg-ink-800' : checked ? 'bg-sky-500/10' : 'hover:bg-ink-800/60'} ${dropRow === e.name ? 'bg-sky-500/10 ring-2 ring-inset ring-sky-400' : ''}`}
              onClick={(ev) => {
                if (suppressClickRef.current) { suppressClickRef.current = false; return }   // capătul unui long-press
                if (selectClick(ev, e, i)) return
                // touch, în modul selecţie: un tap oriunde pe rând îl comută
                if (lastPointerRef.current === 'touch' && selection.keys.size) setSelection((s) => toggleKey(s, e.name))
                setSel(i)
              }}
              // Shift+click nu trebuie să selecteze TEXT între rânduri
              onMouseDown={(ev) => { if (ev.shiftKey) ev.preventDefault() }}
              onPointerDown={(ev) => pressStart(ev, e, i)}
              onPointerMove={pressMove}
              onPointerUp={pressCancel}
              onPointerCancel={pressCancel}
              onPointerLeave={pressCancel}
              // long-press pe Android deschide altfel meniul de sistem (copiere text / link)
              onContextMenu={(ev) => { if (lastPointerRef.current === 'touch') ev.preventDefault() }}
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
              {/* bifa: click-ul ei NU ajunge la rând (fără navigare / copiere de nume); Shift = interval */}
              <label className="grid h-6 w-6 shrink-0 cursor-pointer place-items-center [@media(pointer:coarse)]:h-9 [@media(pointer:coarse)]:w-9"
                onClick={(ev) => ev.stopPropagation()} onPointerDown={(ev) => ev.stopPropagation()}>
                <input type="checkbox" checked={checked} aria-label={t('files.selectRow', { name: e.name })}
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
                  onKeyDown={(ev) => { if (ev.key === 'Enter') doRename(e, (ev.target as HTMLInputElement).value); if (ev.key === 'Escape') { ev.stopPropagation(); setRenaming(null) } }}
                  onBlur={(ev) => doRename(e, ev.target.value)}
                  className="min-w-0 flex-1 rounded-md bg-ink-800 px-1 py-0.5 font-mono text-2xs text-slate-100 ring-1 ring-sky-500" />
              ) : (
                <button onClick={(ev) => {
                    // click de selecţie (modificator / după long-press / tap în modul selecţie pe touch):
                    // rândul l-a tratat deja — nu navigăm, nu copiem numele
                    if (ev.shiftKey || ev.ctrlKey || ev.metaKey) return
                    if (suppressClickRef.current) { suppressClickRef.current = false; ev.stopPropagation(); return }
                    if (lastPointerRef.current === 'touch' && selection.keys.size) {
                      ev.stopPropagation(); setSelection((s) => toggleKey(s, e.name)); setSel(i); return
                    }
                    if (e.dir) { navigate(join(listing!.path, e.name)); return }
                    if (ev.detail >= 3) copyToClip(join(listing!.path, e.name))
                    else if (ev.detail === 2) copyToClip(e.name)
                  }}
                  // pe deget: rândul are măcar 36px (era 18px, sub pragul WCAG 2.5.8 de 24px); cu mouse rămâne compact
                  className={`min-w-0 flex-1 truncate text-left font-mono [@media(pointer:coarse)]:min-h-[36px] ${e.dir ? 'wt-link' : 'text-slate-200'} ${e.dir ? '' : 'select-none'}`}
                  title={e.dir ? e.name : t('files.copyHint', { name: e.name })}>{e.name}{e.dir ? '/' : ''}</button>
              )}
              {/* meta pe UN rând: mode · dim · data (ascunse când apar acțiunile) */}
              <span className="shrink-0 items-center gap-2 font-mono text-2xs tabular-nums text-slate-600 hidden sm:flex group-hover:sm:hidden group-focus-within:sm:hidden">
                <span>{fmtMode(e.mode)}</span>
                {!e.dir && <span className="w-10 text-right text-slate-500">{fmtSize(e.size)}</span>}
                <span className="w-12 text-right">{fmtMtime(e.mtime)}</span>
              </span>
              {/* acțiuni la hover (mouse), la focus în rând (tastatură — `hidden` le scotea din
                  fluxul de Tab, deci de la tastatură NU puteai şterge/redenumi) / mereu (touch).
                  Ţinte de 24px, fiecare cu etichetă care numeşte intrarea. */}
              {/* stopPropagation: o acţiune pe rând (ex. Şterge) nu e şi un tap de selecţie pe touch */}
              {/* eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions -- doar opreşte bubbling-ul spre rând; butoanele din el au tastatura lor */}
              <div onClick={(ev) => ev.stopPropagation()} className="hidden shrink-0 items-center gap-0.5 group-hover:flex group-focus-within:flex [@media(hover:none)]:flex">
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
                <IconButton touch={false} onClick={() => setRenaming(e.name)} title={t('files.rename')} label={t('files.renameAria', { name: e.name })}><RenameIcon /></IconButton>
                <IconButton touch={false} variant="danger" onClick={() => setConfirmDel(e)} title={t('files.delete')} label={`${t('files.delete')} ${e.name}`}><TrashIcon /></IconButton>
              </div>
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
        </div>

        {/* bara de selecţie: „N selectate · Descarcă · Şterge · Copiază pe host… · Renunţă" */}
        {picked.length > 0 && (
          <div role="toolbar" aria-label={t('files.selBarAria')} data-testid="wt-files-selbar"
            className="flex flex-wrap items-center gap-1 border-t border-ink-800 bg-ink-800/70 px-2 py-1 text-2xs">
            <span className="mr-1 font-medium text-slate-200" aria-live="polite">{t('files.selCount', { count: picked.length })}</span>
            <Button variant="ghost" size="sm" onClick={bulkDownload} className="wt-touch">
              <DownloadIcon />{t('files.download')}</Button>
            <Button variant="ghost" size="sm" onClick={() => { setConfirmDel(null); setConfirmBulk(picked) }} disabled={busy}
              className="wt-touch">
              <TrashIcon />{t('files.delete')}</Button>
            <Button variant="ghost" size="sm" onClick={openCopy} disabled={!picked.some((e) => !e.dir)}
              title={picked.some((e) => !e.dir) ? t('copy.open') : t('copy.foldersNext')}
              className="wt-touch">
              <CopyIcon />{t('copy.open')}</Button>
            <Button variant="ghost" size="sm" onClick={() => setSelection(EMPTY_SELECTION)} className="wt-touch ml-auto">
              {t('files.selClear')}</Button>
          </div>
        )}

        {confirmBulk && (() => {
          const pv = previewNames(confirmBulk.map((e) => e.name))
          const nDirs = confirmBulk.filter((e) => e.dir).length
          return (
            <div className="border-t border-ink-800 bg-ink-800/80 px-3 py-2 text-2xs" role="alertdialog" aria-label={t('files.bulkDeleteTitle')}>
              <p className="text-slate-300">{t('files.bulkDeleteConfirm', { count: confirmBulk.length })}</p>
              <p className="mt-0.5 break-all font-mono wt-danger">
                {pv.shown.join(', ')}{pv.more ? ` ${t('files.andMore', { count: pv.more })}` : ''}
              </p>
              {nDirs > 0 && <p className="mt-0.5 wt-warn">{t('files.bulkDeleteDirs', { count: nDirs })}</p>}
              <div className="mt-1.5 flex gap-2">
                <Button variant="ghost" size="sm" autoFocus onClick={() => setConfirmBulk(null)}>{t('files.cancel')}</Button>
                <Button variant="danger" size="sm" onClick={() => void doBulkDelete(confirmBulk)}>
                  {t('files.bulkDeleteGo', { count: confirmBulk.length })}</Button>
              </div>
            </div>
          )
        })()}

        {/* confirmare ștergere (inline, nu window.confirm) */}
        {confirmDel && (
          <div className="border-t border-ink-800 bg-ink-800/80 px-3 py-2 text-2xs">
            <p className="mb-1.5 text-slate-300">
              {t('files.deletePrefix')} <span className="font-mono wt-danger">{confirmDel.name}</span>
              {confirmDel.dir ? t('files.deleteSuffixDir') : '?'}
            </p>
            <div className="flex gap-2">
              <Button variant="danger" size="sm" onClick={() => doDelete(confirmDel)}>{t('files.delete')}</Button>
              <Button variant="ghost" size="sm" onClick={() => setConfirmDel(null)}>{t('files.cancel')}</Button>
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

      {copyItems && (
        <CopyToHostDialog srcHost={props.host} items={copyItems} onClose={() => setCopyItems(null)}
          onStarted={() => setSelection(EMPTY_SELECTION)} />
      )}

      {/* editor CodeMirror (lazy) — highlight, fișiere mari view-only, conflict */}
      {editing && (
        <Suspense fallback={<div className="wt-editor fixed inset-0 z-[60] flex items-center justify-center bg-black/60 text-sm text-slate-400">{t('files.loadingEditor')}</div>}>
          <FileEditor
            hostId={props.host.id}
            path={editing.path}
            name={editing.name}
            onClose={() => setEditing(null)}
            onSaved={() => load(listing!.path)}
          />
        </Suspense>
      )}
    </>
  )
}
