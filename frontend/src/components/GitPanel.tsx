import { useCallback, useEffect, useRef, useState } from 'react'
import { errText, api, Host, withGuardConfirm } from '../lib/api'
import { useConfirm } from '../lib/confirm'
import { copyText } from '../lib/clipboard'
import { getCwd } from '../lib/cwd'
import { parseGitStatus, type GitFile, type RepoInfo } from '../lib/gitStatus'
import { useI18n } from '../lib/i18n'
import { notify } from '../lib/notify'
import { typeCommandOutcome } from '../lib/rootmove'
import { SHEET_CLS } from '../lib/sheet'
import { lsGet, lsSet } from '../lib/storage'
import { useDrawer } from '../lib/useDrawer'
import SheetBar from './SheetBar'
import { ArrowDownIcon, ArrowsLeftRightIcon, ArrowUpIcon, CloseIcon, FolderIcon, GitBranchIcon, RefreshIcon } from './Icons'

// Panou git ca lentilă de SUPRAVEGHERE: pune-l pe folderul din terminal (chiar
// după `su`/`sudo su`) sau pe orice cale manual, și vezi live ce se întâmplă în
// repo — status/diff, commit-uri (cu conținut), branch-uri, mișcările HEAD
// (reset/rebase). Rulează tot prin /api/hosts/{id}/git (op-ul `run` al agentului,
// argv shell-quotat server-side) → NICIO schimbare de agent, deci fără re-semnare.
// Observarea e STRICT read-only (log/show/for-each-ref/reflog); scrierea rămâne
// la stage/commit. checkout/merge/rebase/push rămân la CLI.

// When the agent cannot open the directory, the gateway diagnoses why (gitpanel.access_fix):
// a missing path, a path the agent account can't read, or — only for a real user's home — a
// scoped `usermod` grant to offer. `offer` gates whether we show a command at all.
interface GitAccess { reason: 'missing' | 'denied' | 'system'; path: string; offer: boolean; command: string; group?: string; agent?: string }
interface GitResult { exit_code: number; stdout: string; stderr: string; access?: GitAccess | null }

// Field separator for server-formatted commit metadata; subjects may contain it.
const US = '\u001f'

interface Commit { hash: string; short: string; author: string; date: string; subject: string }
interface Branch { name: string; current: boolean; upstream: string; track: string; date: string }
interface ReflogEntry { short: string; selector: string; subject: string }

type Tab = 'changes' | 'commits' | 'branches' | 'activity'

// lăţimea coloanei (desktop) — acelaşi tipar „window splitter" ca la FilePanel,
// cu cheie proprie în localStorage. Diff-urile/`git show` au nevoie de lăţime.
const WIDTH_KEY = 'wt_git_w'
const W_MIN = 260, W_DEF = 320, W_MAX = 900
const clampW = (w: number) => Math.round(Math.max(W_MIN, Math.min(W_MAX,
  typeof window !== 'undefined' ? Math.max(W_MIN, window.innerWidth - 360) : W_MAX, w)))
function loadWidth(): number {
  const v = Number(lsGet(WIDTH_KEY))
  return v >= W_MIN && v <= W_MAX ? v : W_DEF
}

// litera de status → etichetă scurtă + culoare (wt-* ca în restul UI-ului)
const STATUS: Record<string, { label: string; cls: string }> = {
  M: { label: 'git.status.modified', cls: 'wt-warn' },
  A: { label: 'git.status.added', cls: 'wt-good' },
  D: { label: 'git.status.deleted', cls: 'wt-danger' },
  R: { label: 'git.status.renamed', cls: 'wt-link' },
  C: { label: 'git.status.copied', cls: 'wt-link' },
  U: { label: 'git.status.conflict', cls: 'wt-danger' },
  T: { label: 'git.status.typeChanged', cls: 'wt-warn' },
  '?': { label: 'git.status.new', cls: 'wt-good' },
}
function statusOf(ch: string) { return STATUS[ch] ?? { label: ch, cls: 'text-slate-400' } }

/** `git log --format=%H<US>%h<US>%an<US>%ar<US>%s` → listă de commit-uri. */
function parseLog(out: string): Commit[] {
  const res: Commit[] = []
  for (const line of out.split('\n')) {
    if (!line) continue
    const [hash, short, author, date, ...rest] = line.split(US)
    res.push({ hash, short, author, date, subject: rest.join(US) })
  }
  return res
}

/** `git for-each-ref …refs/heads` → branch-uri (câmp HEAD = „*" pe cel curent). */
function parseBranches(out: string): Branch[] {
  const res: Branch[] = []
  for (const line of out.split('\n')) {
    if (!line) continue
    const [head, name, upstream, track, date] = line.split(US)
    if (!name) continue
    res.push({ name, current: head === '*', upstream: upstream || '', track: track || '', date: date || '' })
  }
  return res
}

/** `git reflog --format=%h<US>%gd<US>%gs` → mișcările recente ale HEAD. */
function parseReflog(out: string): ReflogEntry[] {
  const res: ReflogEntry[] = []
  for (const line of out.split('\n')) {
    if (!line) continue
    const [short, selector, ...rest] = line.split(US)
    res.push({ short, selector, subject: rest.join(US) })
  }
  return res
}

// acțiunea din subiectul reflog → culoare: rescrierile de istorie (reset/rebase/
// amend/gc) ies în evidență — exact ce caută un supervizor la un AI.
function reflogTone(subject: string): string {
  const head = subject.split(':')[0].toLowerCase()
  if (/reset|rebase|filter|gc|prune/.test(head) || /amend/.test(subject)) return 'wt-danger'
  if (/commit|merge|pull/.test(head)) return 'wt-good'
  if (/checkout|branch|clone|switch/.test(head)) return 'wt-link'
  return 'text-slate-400'
}

// marcaj: omul a refuzat confirmarea unei reguli guardrail (nu e eroare, nimic nu s-a rulat)
const GUARD_CANCELLED = new Error('guard-cancelled')
const isStaged = (f: GitFile) => f.index !== ' ' && f.index !== '?'
const isUnstaged = (f: GitFile) => f.work !== ' ' && f.work !== '?' && !f.untracked

/** Diff colorat, ușor (fără CodeMirror) — exact ce cere panoul. */
function DiffView({ text }: { text: string }) {
  const lines = text.split('\n')
  return (
    <pre className="min-h-0 flex-1 overflow-auto px-2 py-1 font-mono text-2xs leading-snug">
      {lines.map((l, i) => {
        let cls = 'text-slate-400'
        if (l.startsWith('@@')) cls = 'wt-link'
        else if (l.startsWith('+++') || l.startsWith('---') || l.startsWith('diff ') || l.startsWith('index ')) cls = 'text-slate-600'
        else if (l.startsWith('commit ') || l.startsWith('Author:') || l.startsWith('Date:') || l.startsWith('Merge:')) cls = 'text-slate-500'
        else if (l.startsWith('+')) cls = 'wt-good bg-emerald-950/30'
        else if (l.startsWith('-')) cls = 'wt-danger bg-rose-950/30'
        return <div key={i} className={`whitespace-pre ${cls}`}>{l || ' '}</div>
      })}
    </pre>
  )
}

export default function GitPanel(props: { host: Host; sessionId: string; onClose: () => void; overlay?: boolean }) {
  const { t } = useI18n()
  const { confirm } = useConfirm()
  const isAgent = !props.host.connection_type || props.host.connection_type === 'agent'
  const asideRef = useRef<HTMLElement>(null)
  const drawer = useDrawer(asideRef, props.onClose)
  const asideCls = drawer.sheet ? SHEET_CLS : 'fixed inset-y-0 right-0 z-40 flex w-[90vw] max-w-sm flex-col border-l border-ink-800 bg-ink-900 shadow-2xl outline-none'
    + (props.overlay ? '' : ' sm:relative sm:inset-auto sm:z-auto sm:w-80 sm:max-w-none sm:shrink-0 sm:shadow-none')
  const scrimCls = 'fixed inset-0 z-30 bg-black/60' + (props.overlay ? '' : ' sm:hidden')
  // coloana statică de pe desktop se poate lăţi trăgând de marginea stângă (ca Files)
  const columnMode = !drawer.sheet && !props.overlay
  const [colW, setColW] = useState(loadWidth)
  const dragCleanup = useRef<(() => void) | null>(null)
  useEffect(() => () => dragCleanup.current?.(), [])
  const saveW = (w: number) => lsSet(WIDTH_KEY, String(w))
  const dragWidth = (e: React.PointerEvent) => {
    e.preventDefault()
    const x0 = e.clientX
    const w0 = asideRef.current?.getBoundingClientRect().width ?? colW
    const at = (ev: PointerEvent) => clampW(w0 + (x0 - ev.clientX))   // lipit de dreapta: spre stânga = mai lat
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

  const [cwd, setCwdState] = useState('')
  const [repoRoot, setRepoRoot] = useState('')
  const [cwdError, setCwdError] = useState('')
  const [following, setFollowing] = useState(true)   // urmărește cwd-ul terminalului; navigarea manuală îl oprește
  const [pathInput, setPathInput] = useState('')
  const [tab, setTab] = useState<Tab>('changes')
  const [live, setLive] = useState(false)

  const [repo, setRepo] = useState<RepoInfo | null>(null)
  const [notRepo, setNotRepo] = useState(false)
  const [repoErr, setRepoErr] = useState('')     // stderr de la rev-parse (ex. permisiuni) — ajută diagnoza
  const [access, setAccess] = useState<GitAccess | null>(null)   // diagnoza structurată de la gateway
  const [grantNote, setGrantNote] = useState('')
  const [files, setFiles] = useState<GitFile[]>([])
  const [commits, setCommits] = useState<Commit[] | null>(null)
  const [branches, setBranches] = useState<Branch[] | null>(null)
  const [reflog, setReflog] = useState<ReflogEntry[] | null>(null)
  const [error, setError] = useState('')
  const [note, setNote] = useState('')   // notă neutră (ex. guardrail anulat) — nu eroare
  // eroare sau anulare de guardrail: fiecare în locul ei
  const fail = useCallback((e: unknown, fallback: string) => {
    if (e === GUARD_CANCELLED) setNote(t('guard.cancelled'))
    else setError(errText(e, t) || fallback)
  }, [t])
  const [busy, setBusy] = useState(false)
  const [sel, setSel] = useState<{ path: string; staged: boolean } | null>(null)
  const [diff, setDiff] = useState('')
  const [commitView, setCommitView] = useState<{ hash: string; subject: string } | null>(null)
  const [showText, setShowText] = useState('')
  const [msg, setMsg] = useState('')
  const loadSeq = useRef(0)
  const cSeq = useRef(0)
  const bSeq = useRef(0)
  const rSeq = useRef(0)
  const detailSeq = useRef(0)
  const invalidateRequests = useCallback(() => {
    loadSeq.current++; cSeq.current++; bSeq.current++; rSeq.current++; detailSeq.current++
  }, [])

  // subcomenzile care scriu (add/reset/restore/commit) trec prin guardrail pe server: la o regulă
  // `confirm` întrebăm aici şi retrimitem; un refuz devine eroarea obişnuită de mai jos
  const gitcmd = useCallback(async (operation: string, params: { path?: string; revision?: string; message?: string; orig?: string } = {}): Promise<GitResult> => {
    const r = await withGuardConfirm((pattern) => confirm({ title: t('guard.confirmTitle'), message: t('guard.confirmMsg', { pattern }), danger: true, confirmLabel: t('guard.confirmRun') }),
      (confirmed) => api<GitResult>(`/api/hosts/${props.host.id}/git`, {
        method: 'POST', body: JSON.stringify({ operation, ...params, cwd, confirmed }),
      }))
    // refuzul omului la o regulă `confirm` NU e o eroare: aruncăm un marcaj recunoscut mai jos
    // şi-l afişăm ca notă neutră („Anulat — nu s-a rulat"), nu cu roşu
    if (r === null) throw GUARD_CANCELLED
    return r
  }, [props.host.id, cwd, confirm, t])

  const refresh = useCallback(async () => {
    if (!cwd) return
    const my = ++loadSeq.current
    setError(''); setNote('')
    try {
      const rp = await gitcmd('root')
      if (my !== loadSeq.current) return
      if (rp.exit_code !== 0) {
        setNotRepo(true); setRepoErr((rp.stderr || '').split('\n')[0] || '')
        setAccess(rp.access ?? null); setGrantNote('')
        setRepo(null); setRepoRoot(''); setFiles([]); setSel(null); return
      }
      setNotRepo(false); setRepoErr(''); setAccess(null)
      setRepoRoot(rp.stdout.replace(/\n$/, ''))
      const st = await gitcmd('status')
      if (my !== loadSeq.current) return
      if (st.exit_code !== 0) {
        setRepo(null); setFiles([]); setSel(null)
        throw new Error(st.stderr || st.stdout || t('git.error.generic'))
      }
      const parsed = parseGitStatus(st.stdout, t)
      setRepo(parsed.repo)
      setFiles(parsed.files)
    } catch (e) {
      if (my !== loadSeq.current) return
      fail(e, t('git.error.generic'))
    }
  }, [cwd, gitcmd, t, fail])

  const loadCommits = useCallback(async () => {
    if (!cwd) return
    const my = ++cSeq.current
    try {
      const r = await gitcmd('commits')
      if (my !== cSeq.current) return
      setCommits(r.exit_code === 0 ? parseLog(r.stdout) : [])
    } catch (e) { if (my === cSeq.current) fail(e, t('git.error.generic')) }
  }, [cwd, gitcmd, t, fail])

  const loadBranches = useCallback(async () => {
    if (!cwd) return
    const my = ++bSeq.current
    try {
      const r = await gitcmd('branches')
      if (my !== bSeq.current) return
      setBranches(r.exit_code === 0 ? parseBranches(r.stdout) : [])
    } catch (e) { if (my === bSeq.current) fail(e, t('git.error.generic')) }
  }, [cwd, gitcmd, t, fail])

  const loadReflog = useCallback(async () => {
    if (!cwd) return
    const my = ++rSeq.current
    try {
      const r = await gitcmd('activity')
      if (my !== rSeq.current) return
      setReflog(r.exit_code === 0 ? parseReflog(r.stdout) : [])
    } catch (e) { if (my === rSeq.current) fail(e, t('git.error.generic')) }
  }, [cwd, gitcmd, t, fail])

  // reîncarcă DOAR datele tab-ului vizibil (+ bara de status), ca Live/refresh să
  // nu ceară degeaba log/branches/reflog pe care nu le vede nimeni.
  const loadTab = useCallback((which: Tab) => {
    if (which === 'commits') loadCommits()
    else if (which === 'branches') loadBranches()
    else if (which === 'activity') loadReflog()
  }, [loadCommits, loadBranches, loadReflog])

  // Agent lookup is best-effort: changing user in the terminal does not change
  // the agent's identity or grant it access to that user's private directories.
  const pullCwd = useCallback(async () => {
    try {
      const r = await api<{ cwd: string }>(`/api/hosts/${props.host.id}/git`, {
        method: 'POST', body: JSON.stringify({ operation: 'cwd', sid: props.sessionId }),
      })
      if (r.cwd?.startsWith('/')) {
        setCwdError('')
        setCwdState((prev) => (prev === r.cwd ? prev : r.cwd))
      } else setCwdError(t('git.cwdUnavailable'))
    } catch (e) { setCwdError(errText(e, t) || t('git.cwdUnavailable')) }
  }, [props.host.id, props.sessionId, t])

  const tick = useCallback(async () => {
    if (following) await pullCwd()
    refresh()
    loadTab(tab)
  }, [following, pullCwd, refresh, loadTab, tab])

  // On mount/session change, show OSC 7 immediately and ask the agent as well.
  useEffect(() => {
    if (!isAgent) return
    const known = getCwd(props.sessionId)
    if (known) setCwdState(known)
    pullCwd()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAgent, props.host.id, props.sessionId])

  // la fiecare `cd` din terminal (OSC 7), urmează-l — DOAR cât urmărim terminalul.
  useEffect(() => {
    if (!isAgent) return
    const onCwd = (e: Event) => {
      const d = (e as CustomEvent<{ sid: string; cwd: string }>).detail
      if (d.sid === props.sessionId && following) setCwdState(d.cwd)
    }
    window.addEventListener('wt-cwd', onCwd)
    return () => window.removeEventListener('wt-cwd', onCwd)
  }, [isAgent, props.sessionId, following])

  // schimbarea cwd-ului resetează tot (alt repo → alte date) și reîncarcă status + tab
  useEffect(() => {
    if (!cwd) return
    setSel(null); setDiff(''); setCommitView(null); setShowText('')
    // caches → null: efectul de mai jos (pe tab) reîncarcă tab-ul activ
    setCommits(null); setBranches(null); setReflog(null)
    refresh()
    return invalidateRequests
  }, [cwd, refresh, invalidateRequests])

  // input-ul de cale urmează cwd-ul (până îl editezi tu)
  useEffect(() => { setPathInput(cwd) }, [cwd])

  // comutarea pe un tab încarcă datele lui dacă nu-s deja (null = neîncărcat)
  useEffect(() => {
    if (!cwd || notRepo) return
    if (tab === 'commits' && commits === null) loadCommits()
    else if (tab === 'branches' && branches === null) loadBranches()
    else if (tab === 'activity' && reflog === null) loadReflog()
  }, [tab, cwd, notRepo, commits, branches, reflog, loadCommits, loadBranches, loadReflog])

  // Live: la ~5s, cât panoul e vizibil și tab-ul browserului e în focus
  useEffect(() => {
    if (!live || !cwd) return
    const id = window.setInterval(() => {
      if (document.visibilityState === 'visible') tick()
    }, 5000)
    return () => window.clearInterval(id)
  }, [live, cwd, tick])

  function applyPath() {
    const p = pathInput.trim()
    if (!p) return
    if (!p.startsWith('/')) { setError(t('err.git.cwdAbsolute')); return }
    setError('')
    setFollowing(false)
    setCwdError('')
    if (p === cwd) { refresh(); loadTab(tab) } else setCwdState(p)
  }

  function backToTerminal() {
    setFollowing(true)
    setError('')
    pullCwd()
  }

  // Grant: type the gateway-built `sudo usermod …` command into THIS session's terminal, at a
  // prompt, as a bracketed paste with no newline — the person reads it and presses Enter (same
  // path as rootmove.ts). We never run it. If the foreground isn't a shell prompt, nothing is
  // typed and we point at Copy instead.
  function grantAccess(cmd: string) {
    const outcome = typeCommandOutcome(props.sessionId, cmd)
    setGrantNote(outcome === 'typed' ? t('git.access.typed') : t('git.access.notPrompt'))
  }
  async function copyGrant(cmd: string) {
    if (await copyText(cmd)) setGrantNote(t('git.access.copied'))
  }

  async function openDiff(f: GitFile, staged: boolean) {
    const my = ++detailSeq.current
    setCommitView(null); setShowText('')
    setSel({ path: f.path, staged })
    setDiff(t('git.loading'))
    try {
      let r: GitResult
      if (f.untracked) {
        // untracked: arată tot fișierul ca adăugat (--no-index iese cu 1, e ok)
        r = await gitcmd('untracked_diff', { path: f.path })
      } else {
        r = await gitcmd(staged ? 'staged_diff' : 'diff', { path: f.path })
      }
      if (my !== detailSeq.current) return
      if (r.exit_code !== 0 && !(f.untracked && r.exit_code === 1)) throw new Error(r.stderr || t('git.error.diff'))
      setDiff(r.stdout || t('git.nothingToShow'))
    } catch (e) {
      if (my !== detailSeq.current) return
      setDiff('')
      fail(e, t('git.error.diff'))
    }
  }

  async function openShow(c: Commit) {
    const my = ++detailSeq.current
    setSel(null); setDiff('')
    setCommitView({ hash: c.hash, subject: c.subject })
    setShowText(t('git.loading'))
    try {
      const r = await gitcmd('show', { revision: c.hash })
      if (my !== detailSeq.current) return
      if (r.exit_code !== 0) throw new Error(r.stderr || t('git.error.diff'))
      setShowText(r.stdout || t('git.nothingToShow'))
    } catch (e) {
      if (my !== detailSeq.current) return
      setShowText('')
      fail(e, t('git.error.diff'))
    }
  }

  async function mutate(operation: string, params: { path: string; orig?: string }) {
    setBusy(true)
    setError(''); setNote('')
    try {
      const r = await gitcmd(operation, params)
      if (r.exit_code !== 0) setError((r.stderr || r.stdout || t('git.error.opFailed')).trim())
    } catch (e) {
      fail(e, t('git.error.generic'))
    } finally {
      setBusy(false)
      setSel(null); setDiff('')
      refresh()
    }
  }

  const stage = (f: GitFile) => mutate('stage', { path: f.path })
  // a staged rename resets BOTH the new path and its original, else the delete stays staged
  const unstage = (f: GitFile) => mutate('unstage', { path: f.path, orig: f.orig })

  async function commit() {
    const m = msg.trim()
    if (!m) return
    setBusy(true)
    setError(''); setNote('')
    try {
      const r = await gitcmd('commit', { message: m })
      if (r.exit_code === 0) {
        setMsg(''); setSel(null); setDiff('')
        notify(t('git.commitDone'), r.stdout.split('\n')[0] || m, 'info')
        refresh()
        if (tab !== 'changes') loadTab(tab)
      } else {
        setError((r.stderr || r.stdout || t('git.error.commitFailed')).trim())
      }
    } catch (e) {
      fail(e, t('git.error.generic'))
    } finally {
      setBusy(false)
    }
  }

  const staged = files.filter(isStaged)
  const modified = files.filter(isUnstaged)
  const untracked = files.filter((f) => f.untracked)

  const header = (
    <header className="flex items-center gap-2 border-b border-ink-800 px-3 py-2">
      <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">{t('git.title')}</span>
      <button onClick={() => setLive((v) => !v)} disabled={!cwd}
        className={`wt-touch ml-auto inline-flex items-center gap-1 rounded-md px-1.5 text-2xs disabled:opacity-30 ${live ? 'wt-good' : 'text-slate-500 hover:bg-ink-800 hover:text-slate-300'}`}
        title={t('git.liveTitle')} aria-pressed={live}>
        <span className={`inline-block h-1.5 w-1.5 rounded-full ${live ? 'animate-pulse bg-emerald-400' : 'bg-slate-600'}`} />{t('git.live')}
      </button>
      <button onClick={() => tick()} disabled={!cwd || busy}
        className="wt-touch rounded-md px-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-300 disabled:opacity-30"
        title={t('git.reloadStatus')} aria-label={t('git.reloadStatus')}><RefreshIcon /></button>
      <button onClick={props.onClose} aria-label={t('git.closeAria')}
        className="wt-touch rounded-md px-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-300"><CloseIcon size={14} /></button>
    </header>
  )

  if (!isAgent) {
    return (
      <>
        <div className={scrimCls} onClick={props.onClose} aria-hidden="true" />
        {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- Escape pe regiunea drawer-ului (vezi useDrawer): intenţionat pe <aside>, nu pe document */}
        <aside ref={asideRef} aria-label={t('git.panelAria')} className={asideCls} onKeyDown={drawer.onKeyDown}>
          {drawer.sheet && <SheetBar title={'Git'} onBack={props.onClose} />}
          {header}
          <div className="flex flex-1 flex-col items-center justify-center gap-3 p-4 text-center">
            <p className="text-xs leading-relaxed text-slate-500">
              {t('git.noAgent', { type: props.host.connection_type?.toUpperCase() ?? '' })}
            </p>
          </div>
        </aside>
      </>
    )
  }

  // bara de director: cale editabilă + „urmează terminalul". Fixarea unei căi
  // oprește urmărirea; butonul ⟲ o repornește și sare la cwd-ul sesiunii.
  const pathBar = (
    <div className="flex items-center gap-1 border-b border-ink-800 px-2 py-1.5">
      <FolderIcon size={14} />
      <input
        value={pathInput}
        onChange={(e) => setPathInput(e.target.value)}
        onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); applyPath() } }}
        spellCheck={false} autoCapitalize="off" autoCorrect="off"
        placeholder={t('git.pathPlaceholder')}
        aria-label={t('git.pathLabel')}
        className="min-w-0 flex-1 rounded-md bg-ink-800 px-2 py-1 font-mono text-2xs text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500"
      />
      <button onClick={applyPath} disabled={!pathInput.trim() || pathInput.trim() === cwd}
        className="wt-touch shrink-0 rounded-md px-1.5 py-1 text-2xs text-slate-400 hover:bg-ink-800 hover:text-slate-200 disabled:opacity-30"
        title={t('git.goPath')}>{t('git.goPath')}</button>
      {/* toggle „urmează cwd-ul terminalului" — ca în FilePanel (verde + ring când e activ);
          iconiță distinctă de refresh-ul din header, ca să nu fie două cercuri la fel */}
      <button onClick={following ? () => setFollowing(false) : backToTerminal} aria-pressed={following}
        className={`wt-touch inline-flex min-h-[28px] shrink-0 items-center gap-1 rounded-md px-1.5 py-0.5 text-2xs ${following ? 'wt-good ring-1 ring-emerald-600/40' : 'text-slate-500 hover:bg-ink-800 hover:text-slate-200'}`}
        title={following ? t('git.followingTitle') : t('git.backToTerminal')} aria-label={t('git.backToTerminal')}><ArrowsLeftRightIcon size={12} /> cwd</button>
    </div>
  )

  const tabs: { id: Tab; label: string }[] = [
    { id: 'changes', label: t('git.tab.changes') },
    { id: 'commits', label: t('git.tab.commits') },
    { id: 'branches', label: t('git.tab.branches') },
    { id: 'activity', label: t('git.tab.activity') },
  ]
  const tabBar = (
    <div role="tablist" className="flex items-stretch border-b border-ink-800 text-2xs">
      {tabs.map((tb) => (
        <button key={tb.id} role="tab" aria-selected={tab === tb.id} onClick={() => setTab(tb.id)}
          className={`wt-touch flex-1 border-b-2 px-2 py-1.5 ${tab === tb.id ? 'border-sky-500 text-slate-200' : 'border-transparent text-slate-500 hover:text-slate-300'}`}>
          {tb.label}
        </button>
      ))}
    </div>
  )

  // rând de fișier: status, cale, buton stage/unstage
  const row = (f: GitFile, group: 'staged' | 'modified' | 'untracked') => {
    const ch = group === 'staged' ? f.index : f.untracked ? '?' : f.work
    const s = statusOf(ch)
    const active = sel?.path === f.path && sel.staged === (group === 'staged')
    return (
      <div key={group + f.path}
        className={`group flex items-center gap-2 px-3 py-1 text-xs ${active ? 'bg-ink-800' : 'hover:bg-ink-800/60'}`}>
        <span className={`w-4 shrink-0 text-center font-mono text-2xs font-bold ${s.cls}`} title={t(s.label)}>{ch === '?' ? '?' : ch}</span>
        <button onClick={() => openDiff(f, group === 'staged')}
          className="min-w-0 flex-1 truncate text-left font-mono text-slate-200" title={f.path}>
          {f.path}
        </button>
        {/* ţinte de 24px + etichetă care numeşte fişierul: „+"/„−" singure nu spun nimic cititorului */}
        {group === 'staged' ? (
          <button onClick={() => unstage(f)} disabled={busy}
            className="grid h-6 w-6 shrink-0 place-items-center rounded-md text-slate-500 hover:bg-ink-700 hover:text-warn disabled:opacity-40"
            title={t('git.unstage')} aria-label={`${t('git.unstage')} ${f.path}`}>−</button>
        ) : (
          <button onClick={() => stage(f)} disabled={busy}
            className="grid h-6 w-6 shrink-0 place-items-center rounded-md text-slate-500 hover:bg-ink-700 hover:text-ok disabled:opacity-40"
            title={t('git.stage')} aria-label={`${t('git.stage')} ${f.path}`}>+</button>
        )}
      </div>
    )
  }

  const groupHead = (label: string, n: number) => (
    <div className="flex items-center gap-2 border-y border-ink-800/60 bg-ink-800/30 px-3 py-0.5 text-2xs uppercase tracking-wide text-slate-500">
      <span>{label}</span><span className="tabular-nums text-slate-600">{n}</span>
    </div>
  )

  const emptyHint = (text: string) => (
    <div className="px-3 py-6 text-center text-2xs text-slate-500">{text}</div>
  )

  // ── conținutul fiecărui tab ────────────────────────────────────────────────
  const changesTab = (
    <>
      <div className={`overflow-y-auto ${sel ? 'max-h-[45%]' : 'flex-1'}`}>
        {staged.length > 0 && groupHead(t('git.groupStaged'), staged.length)}
        {staged.map((f) => row(f, 'staged'))}
        {modified.length > 0 && groupHead(t('git.groupModified'), modified.length)}
        {modified.map((f) => row(f, 'modified'))}
        {untracked.length > 0 && groupHead(t('git.groupUntracked'), untracked.length)}
        {untracked.map((f) => row(f, 'untracked'))}
        {files.length === 0 && emptyHint(t('git.nothingToCommit'))}
      </div>

      {sel && (
        <div className="flex min-h-0 flex-1 flex-col border-t border-ink-800">
          <div className="flex items-center gap-2 border-b border-ink-800 px-3 py-1 text-2xs text-slate-500">
            <span className="truncate font-mono" title={sel.path}>{sel.path}</span>
            <span className="ml-auto shrink-0">{sel.staged ? t('git.diffStaged') : t('git.diffWorktree')}</span>
            <button onClick={() => { setSel(null); setDiff('') }} className="grid h-6 w-6 shrink-0 place-items-center rounded-md hover:bg-ink-800 hover:text-slate-300" title={t('git.closeDiff')} aria-label={t('git.closeDiff')}><CloseIcon size={14} /></button>
          </div>
          <DiffView text={diff} />
        </div>
      )}

      {/* commit — doar ce e în stage */}
      <div className="border-t border-ink-800 p-2">
        <textarea
          value={msg}
          onChange={(e) => setMsg(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) { e.preventDefault(); commit() } }}
          placeholder={staged.length ? t('git.commitPlaceholder') : t('git.commitPlaceholderEmpty')}
          rows={2}
          className="w-full resize-none rounded-md bg-ink-800 px-2 py-1 font-mono text-2xs text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500"
        />
        <div className="mt-1 flex items-center gap-2">
          <span className="text-2xs text-slate-500">{t('git.stagedCount', { n: staged.length })}</span>
          <button
            onClick={commit}
            disabled={busy || !msg.trim() || staged.length === 0}
            className="ml-auto rounded-md bg-emerald-600 px-3 py-1 text-xs font-medium text-white hover:bg-emerald-700 disabled:opacity-40"
          >{t('git.commit')}</button>
        </div>
      </div>
    </>
  )

  const commitsTab = (
    <>
      <div className={`overflow-y-auto ${commitView ? 'max-h-[45%]' : 'flex-1'}`}>
        {commits === null ? emptyHint(t('git.loading'))
          : commits.length === 0 ? emptyHint(t('git.noCommits'))
            : commits.map((c) => (
              <button key={c.hash} onClick={() => openShow(c)}
                className={`flex w-full items-baseline gap-2 px-3 py-1 text-left text-xs hover:bg-ink-800/60 ${commitView?.hash === c.hash ? 'bg-ink-800' : ''}`}>
                <span className="shrink-0 font-mono text-2xs text-amber-400/90">{c.short}</span>
                <span className="min-w-0 flex-1 truncate text-slate-200" title={c.subject}>{c.subject}</span>
                <span className="shrink-0 text-2xs text-slate-500" title={c.author}>{c.date}</span>
              </button>
            ))}
      </div>
      {commitView && (
        <div className="flex min-h-0 flex-1 flex-col border-t border-ink-800">
          <div className="flex items-center gap-2 border-b border-ink-800 px-3 py-1 text-2xs text-slate-500">
            <span className="truncate font-mono" title={commitView.hash}>{commitView.subject}</span>
            <button onClick={() => { setCommitView(null); setShowText('') }} className="ml-auto grid h-6 w-6 shrink-0 place-items-center rounded-md hover:bg-ink-800 hover:text-slate-300" title={t('git.closeDiff')} aria-label={t('git.closeDiff')}><CloseIcon size={14} /></button>
          </div>
          <DiffView text={showText} />
        </div>
      )}
    </>
  )

  const branchesTab = (
    <div className="flex-1 overflow-y-auto">
      {branches === null ? emptyHint(t('git.loading'))
        : branches.length === 0 ? emptyHint(t('git.noBranches'))
          : branches.map((b) => (
            <div key={b.name} className={`flex items-center gap-2 px-3 py-1 text-xs ${b.current ? 'bg-ink-800/50' : ''}`}>
              <span className={`shrink-0 ${b.current ? 'wt-good' : 'text-slate-600'}`}><GitBranchIcon size={12} /></span>
              <span className={`min-w-0 flex-1 truncate font-mono ${b.current ? 'font-medium text-slate-100' : 'text-slate-300'}`} title={b.name}>{b.name}</span>
              {b.track && b.track !== '[gone]' && <span className="shrink-0 text-2xs text-slate-500" title={b.upstream}>{b.track}</span>}
              {b.track === '[gone]' && <span className="shrink-0 text-2xs wt-warn" title={b.upstream}>{t('git.upstreamGone')}</span>}
              <span className="shrink-0 text-2xs text-slate-600">{b.date}</span>
            </div>
          ))}
    </div>
  )

  const activityTab = (
    <div className="flex-1 overflow-y-auto">
      {reflog === null ? emptyHint(t('git.loading'))
        : reflog.length === 0 ? emptyHint(t('git.noActivity'))
          : reflog.map((e, i) => (
            <div key={e.selector + i} className="flex items-baseline gap-2 px-3 py-1 text-xs">
              <span className="shrink-0 font-mono text-2xs text-amber-400/90">{e.short}</span>
              <span className={`min-w-0 flex-1 truncate ${reflogTone(e.subject)}`} title={e.subject}>{e.subject}</span>
              <span className="shrink-0 font-mono text-2xs text-slate-600" title={e.selector}>{e.selector.replace(/^HEAD/, '')}</span>
            </div>
          ))}
    </div>
  )

  return (
    <>
      <div className={scrimCls} onClick={props.onClose} aria-hidden="true" />
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- Escape pe regiunea drawer-ului (vezi useDrawer): intenţionat pe <aside>, nu pe document */}
      <aside ref={asideRef} aria-label={t('git.panelAria')} className={asideCls}
        style={columnMode ? { width: clampW(colW) } : undefined} onKeyDown={drawer.onKeyDown}>
        {/* mâner de lăţime (coloana de pe desktop): drag, ←/→ de la tastatură, dublu-click = reset */}
        {columnMode && (
          <div role="separator" aria-orientation="vertical" tabIndex={0}
            aria-label={t('git.resizeAria')} title={t('git.resizeAria')}
            aria-valuenow={colW} aria-valuemin={W_MIN} aria-valuemax={W_MAX}
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
        {drawer.sheet && <SheetBar title={'Git'} onBack={props.onClose} />}
        {header}
        {pathBar}
        {cwdError && <p role="status" className="border-b border-ink-800 px-3 py-1.5 text-2xs wt-warn">{cwdError}</p>}

        {/* bara de branch */}
        {repo && (
          <div title={repoRoot} className="flex items-center gap-2 border-b border-ink-800 px-3 py-1.5 text-2xs">
            <span className="inline-flex items-center gap-1 font-mono font-medium text-slate-300" title={cwd}><GitBranchIcon size={12} /> {repo.branch}</span>
            {repo.ahead > 0 && <span className="wt-good inline-flex items-center tabular-nums" title={t('git.aheadTitle')}><ArrowUpIcon size={11} />{repo.ahead}</span>}
            {repo.behind > 0 && <span className="wt-warn inline-flex items-center tabular-nums" title={t('git.behindTitle')}><ArrowDownIcon size={11} />{repo.behind}</span>}
            {files.length === 0 && <span className="ml-auto text-slate-600">{t('git.cleanTree')}</span>}
          </div>
        )}

        {error && <div className="border-b border-ink-800 bg-ink-800 px-3 py-1.5 text-2xs wt-danger">{error}</div>}
        {note && !error && <div role="status" className="border-b border-ink-800 bg-ink-800/60 px-3 py-1.5 text-2xs text-slate-400">{note}</div>}

        {notRepo && (
          <div className="flex flex-1 flex-col items-center justify-center gap-2 p-4 text-center">
            {access?.reason === 'missing' ? (
              <>
                <p className="text-xs text-slate-500">{t('git.access.missing')}</p>
                <p className="font-mono text-2xs text-slate-600" title={access.path}>{access.path || cwd || '—'}</p>
                <p className="text-2xs text-slate-600">{t('git.notRepoHint')}</p>
              </>
            ) : access?.reason === 'denied' && access.offer ? (
              <>
                <p className="text-xs text-slate-500">{t('git.access.denied')}</p>
                <p className="font-mono text-2xs text-slate-600" title={access.path}>{access.path}</p>
                <p className="max-w-full text-2xs text-slate-500">{t('git.access.hint', { agent: access.agent || '' })}</p>
                <code className="max-w-full select-all break-all rounded-md bg-ink-900 px-2 py-1 font-mono text-2xs text-slate-300 ring-1 ring-ink-700">{access.command}</code>
                <div className="flex gap-2">
                  <button onClick={() => grantAccess(access.command)}
                    className="wt-touch rounded-md px-2 py-1 text-2xs text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800 hover:text-slate-100">{t('git.access.openInTerminal')}</button>
                  <button onClick={() => copyGrant(access.command)}
                    className="wt-touch rounded-md px-2 py-1 text-2xs text-slate-400 hover:bg-ink-800 hover:text-slate-200">{t('git.access.copy')}</button>
                </div>
                {grantNote && <p role="status" className="text-2xs text-slate-400">{grantNote}</p>}
                <p className="max-w-full text-2xs text-slate-600">{t('git.access.restartNote')}</p>
              </>
            ) : access ? (
              <>
                <p className="text-xs text-slate-500">{t('git.access.system')}</p>
                <p className="font-mono text-2xs text-slate-600" title={access.path}>{access.path || cwd || '—'}</p>
              </>
            ) : (
              <>
                <p className="text-xs text-slate-500">{t(repoErr ? 'git.repoUnavailable' : 'git.notRepo')}</p>
                <p className="font-mono text-2xs text-slate-600" title={cwd}>{cwd || '—'}</p>
                {repoErr && <>
                  <p className="max-w-full break-words font-mono text-2xs text-slate-600">{repoErr}</p>
                  <p className="text-2xs text-slate-500">{t('git.agentPermissions')}</p>
                </>}
                <p className="text-2xs text-slate-600">{t('git.notRepoHint')}</p>
              </>
            )}
          </div>
        )}

        {repo && (
          <>
            {tabBar}
            {tab === 'changes' && changesTab}
            {tab === 'commits' && commitsTab}
            {tab === 'branches' && branchesTab}
            {tab === 'activity' && activityTab}
          </>
        )}
      </aside>
    </>
  )
}
