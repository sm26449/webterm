import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError, Host } from '../lib/api'
import { getCwd } from '../lib/cwd'
import { useI18n } from '../lib/i18n'
import { notify } from '../lib/notify'
import { RefreshIcon } from './Icons'

// Panou git în limbajul panoului de fișiere: status/diff/stage/commit pentru
// repo-ul din directorul curent al sesiunii (OSC 7). Rulează totul prin
// /api/hosts/{id}/git (op-ul `run` al agentului, argv shell-quotat server-side)
// → NICIO schimbare de agent, deci fără re-semnare. Scope conștient restrâns:
// merge/rebase/push/branch rămân la CLI (au prea multe stări-limită pt. un UI).

interface GitResult { exit_code: number; stdout: string; stderr: string }

// XY din `git status --porcelain`: X=stage (index), Y=arbore de lucru.
interface GitFile { path: string; index: string; work: string; untracked: boolean }
interface RepoInfo { branch: string; ahead: number; behind: number; detached: boolean }

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

/** Parsează `git status --porcelain --branch` → info de branch + fișiere. */
function parseStatus(out: string, t: (key: string) => string): { repo: RepoInfo; files: GitFile[] } {
  const repo: RepoInfo = { branch: '?', ahead: 0, behind: 0, detached: false }
  const files: GitFile[] = []
  for (const line of out.split('\n')) {
    if (!line) continue
    if (line.startsWith('## ')) {
      const info = line.slice(3)
      if (info.startsWith('HEAD (no branch)')) { repo.detached = true; repo.branch = t('git.detachedHead'); continue }
      const noCommits = info.match(/^No commits yet on (.+)$/)
      if (noCommits) { repo.branch = noCommits[1].trim(); continue }
      repo.branch = info.split('...')[0].split(' ')[0]
      const ab = info.match(/\[(.+)\]/)
      if (ab) {
        const a = ab[1].match(/ahead (\d+)/); if (a) repo.ahead = +a[1]
        const b = ab[1].match(/behind (\d+)/); if (b) repo.behind = +b[1]
      }
      continue
    }
    const index = line[0], work = line[1]
    let path = line.slice(3)
    const arrow = path.indexOf(' -> ')            // redenumire: „vechi -> nou"
    if (arrow >= 0) path = path.slice(arrow + 4)
    if (path.startsWith('"') && path.endsWith('"')) {
      try { path = JSON.parse(path) } catch { /* caractere speciale: păstrează bruta */ }
    }
    files.push({ path, index, work, untracked: index === '?' && work === '?' })
  }
  return { repo, files }
}

const isStaged = (f: GitFile) => f.index !== ' ' && f.index !== '?'
const isUnstaged = (f: GitFile) => f.work !== ' ' && f.work !== '?' && !f.untracked

/** Diff colorat, ușor (fără CodeMirror) — exact ce cere panoul. */
function DiffView({ text }: { text: string }) {
  const lines = text.split('\n')
  return (
    <pre className="min-h-0 flex-1 overflow-auto px-2 py-1 font-mono text-[11px] leading-snug">
      {lines.map((l, i) => {
        let cls = 'text-slate-400'
        if (l.startsWith('@@')) cls = 'wt-link'
        else if (l.startsWith('+++') || l.startsWith('---') || l.startsWith('diff ') || l.startsWith('index ')) cls = 'text-slate-600'
        else if (l.startsWith('+')) cls = 'wt-good bg-emerald-950/30'
        else if (l.startsWith('-')) cls = 'wt-danger bg-rose-950/30'
        return <div key={i} className={`whitespace-pre ${cls}`}>{l || ' '}</div>
      })}
    </pre>
  )
}

export default function GitPanel(props: { host: Host; sessionId: string; onClose: () => void; overlay?: boolean }) {
  const { t } = useI18n()
  const isAgent = !props.host.connection_type || props.host.connection_type === 'agent'
  const asideCls = 'fixed inset-y-0 right-0 z-40 flex w-[90vw] max-w-sm flex-col border-l border-ink-800 bg-ink-900 shadow-2xl'
    + (props.overlay ? '' : ' sm:static sm:z-auto sm:w-80 sm:max-w-none sm:shrink-0 sm:shadow-none')
  const scrimCls = 'fixed inset-0 z-30 bg-black/60' + (props.overlay ? '' : ' sm:hidden')

  const [cwd, setCwdState] = useState('')
  const [repo, setRepo] = useState<RepoInfo | null>(null)
  const [notRepo, setNotRepo] = useState(false)
  const [files, setFiles] = useState<GitFile[]>([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [sel, setSel] = useState<{ path: string; staged: boolean } | null>(null)
  const [diff, setDiff] = useState('')
  const [msg, setMsg] = useState('')
  const loadSeq = useRef(0)

  const gitcmd = useCallback(async (args: string[]): Promise<GitResult> => {
    return api<GitResult>(`/api/hosts/${props.host.id}/git`, {
      method: 'POST', body: JSON.stringify({ args, cwd }),
    })
  }, [props.host.id, cwd])

  const refresh = useCallback(async () => {
    if (!cwd) return
    const my = ++loadSeq.current
    setError('')
    try {
      const rp = await gitcmd(['rev-parse', '--show-toplevel'])
      if (my !== loadSeq.current) return
      if (rp.exit_code !== 0) { setNotRepo(true); setRepo(null); setFiles([]); setSel(null); return }
      setNotRepo(false)
      const st = await gitcmd(['status', '--porcelain', '--branch'])
      if (my !== loadSeq.current) return
      const parsed = parseStatus(st.stdout, t)
      setRepo(parsed.repo)
      setFiles(parsed.files)
    } catch (e) {
      if (my !== loadSeq.current) return
      setError(e instanceof ApiError ? e.message : t('git.error.generic'))
    }
  }, [cwd, gitcmd, t])

  // cwd-ul sesiunii: OSC 7 dacă e activ shell integration, altfel îl cerem
  // agentului (ca panoul de fișiere). Fără el, nu știm pe ce repo lucrăm.
  useEffect(() => {
    if (!isAgent) return
    const known = getCwd(props.sessionId)
    if (known) { setCwdState(known); return }
    api<{ cwd: string }>(`/api/hosts/${props.host.id}/fs/cwd?sid=${encodeURIComponent(props.sessionId)}`)
      .then((r) => setCwdState(r.cwd || ''))
      .catch(() => setCwdState(''))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isAgent])

  // la fiecare `cd` din terminal (OSC 7), re-evaluează repo-ul: `cd` într-un alt
  // proiect → panoul îl arată. Fără navigare manuală, deci urmărim mereu.
  useEffect(() => {
    if (!isAgent) return
    const onCwd = (e: Event) => {
      const d = (e as CustomEvent<{ sid: string; cwd: string }>).detail
      if (d.sid === props.sessionId) setCwdState(d.cwd)
    }
    window.addEventListener('wt-cwd', onCwd)
    return () => window.removeEventListener('wt-cwd', onCwd)
  }, [isAgent, props.sessionId])

  useEffect(() => { if (cwd) { setSel(null); setDiff(''); refresh() } }, [cwd, refresh])

  async function openDiff(f: GitFile, staged: boolean) {
    setSel({ path: f.path, staged })
    setDiff(t('git.loading'))
    try {
      let r: GitResult
      if (f.untracked) {
        // untracked: arată tot fișierul ca adăugat (--no-index iese cu 1, e ok)
        r = await gitcmd(['diff', '--no-index', '--', '/dev/null', f.path])
      } else {
        r = await gitcmd(staged ? ['diff', '--staged', '--', f.path] : ['diff', '--', f.path])
      }
      setDiff(r.stdout || t('git.nothingToShow'))
    } catch (e) {
      setDiff('')
      setError(e instanceof ApiError ? e.message : t('git.error.diff'))
    }
  }

  async function mutate(args: string[]) {
    setBusy(true)
    setError('')
    try {
      const r = await gitcmd(args)
      if (r.exit_code !== 0) setError((r.stderr || r.stdout || t('git.error.opFailed')).trim())
    } catch (e) {
      setError(e instanceof ApiError ? e.message : t('git.error.generic'))
    } finally {
      setBusy(false)
      setSel(null); setDiff('')
      refresh()
    }
  }

  const stage = (f: GitFile) => mutate(['add', '--', f.path])
  const unstage = (f: GitFile) => mutate(['reset', '-q', 'HEAD', '--', f.path])

  async function commit() {
    const m = msg.trim()
    if (!m) return
    setBusy(true)
    setError('')
    try {
      const r = await gitcmd(['commit', '-m', m])
      if (r.exit_code === 0) {
        setMsg(''); setSel(null); setDiff('')
        notify(t('git.commitDone'), r.stdout.split('\n')[0] || m, 'info')
        refresh()
      } else {
        setError((r.stderr || r.stdout || t('git.error.commitFailed')).trim())
      }
    } catch (e) {
      setError(e instanceof ApiError ? e.message : t('git.error.generic'))
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
      <button onClick={refresh} disabled={!cwd || busy}
        className="wt-touch ml-auto rounded px-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-300 disabled:opacity-30"
        title={t('git.reloadStatus')}><RefreshIcon /></button>
      <button onClick={props.onClose} aria-label={t('git.closeAria')}
        className="wt-touch rounded px-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-300">✕</button>
    </header>
  )

  if (!isAgent) {
    return (
      <>
        <div className={scrimCls} onClick={props.onClose} aria-hidden="true" />
        <aside aria-label={t('git.panelAria')} className={asideCls}>
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

  // rând de fișier: status, cale, buton stage/unstage
  const row = (f: GitFile, group: 'staged' | 'modified' | 'untracked') => {
    const ch = group === 'staged' ? f.index : f.untracked ? '?' : f.work
    const s = statusOf(ch)
    const active = sel?.path === f.path && sel.staged === (group === 'staged')
    return (
      <div key={group + f.path}
        className={`group flex items-center gap-2 px-3 py-1 text-[12px] ${active ? 'bg-ink-800' : 'hover:bg-ink-800/60'}`}>
        <span className={`w-4 shrink-0 text-center font-mono text-[11px] font-bold ${s.cls}`} title={t(s.label)}>{ch === '?' ? '?' : ch}</span>
        <button onClick={() => openDiff(f, group === 'staged')}
          className="min-w-0 flex-1 truncate text-left font-mono text-slate-200" title={f.path}>
          {f.path}
        </button>
        {group === 'staged' ? (
          <button onClick={() => unstage(f)} disabled={busy}
            className="shrink-0 rounded px-1.5 text-slate-500 hover:bg-ink-700 hover:text-amber-300 disabled:opacity-40"
            title={t('git.unstage')}>−</button>
        ) : (
          <button onClick={() => stage(f)} disabled={busy}
            className="shrink-0 rounded px-1.5 text-slate-500 hover:bg-ink-700 hover:text-emerald-300 disabled:opacity-40"
            title={t('git.stage')}>+</button>
        )}
      </div>
    )
  }

  const groupHead = (label: string, n: number) => (
    <div className="flex items-center gap-2 border-y border-ink-800/60 bg-ink-800/30 px-3 py-0.5 text-[10px] uppercase tracking-wide text-slate-500">
      <span>{label}</span><span className="tabular-nums text-slate-600">{n}</span>
    </div>
  )

  return (
    <>
      <div className={scrimCls} onClick={props.onClose} aria-hidden="true" />
      <aside aria-label={t('git.panelAria')} className={asideCls}>
        {header}

        {/* bara de branch */}
        {repo && (
          <div className="flex items-center gap-2 border-b border-ink-800 px-3 py-1.5 text-[11px]">
            <span className="font-mono font-medium text-slate-300" title={cwd}>⎇ {repo.branch}</span>
            {repo.ahead > 0 && <span className="wt-good tabular-nums" title={t('git.aheadTitle')}>↑{repo.ahead}</span>}
            {repo.behind > 0 && <span className="wt-warn tabular-nums" title={t('git.behindTitle')}>↓{repo.behind}</span>}
            {files.length === 0 && <span className="ml-auto text-slate-600">{t('git.cleanTree')}</span>}
          </div>
        )}

        {error && <div className="border-b border-ink-800 bg-ink-800 px-3 py-1.5 text-[11px] wt-danger">{error}</div>}

        {notRepo && (
          <div className="flex flex-1 flex-col items-center justify-center gap-2 p-4 text-center">
            <p className="text-xs text-slate-500">{t('git.notRepo')}</p>
            <p className="font-mono text-[10px] text-slate-600" title={cwd}>{cwd || '—'}</p>
          </div>
        )}

        {repo && (
          <>
            <div className={`overflow-y-auto ${sel ? 'max-h-[45%]' : 'flex-1'}`}>
              {staged.length > 0 && groupHead(t('git.groupStaged'), staged.length)}
              {staged.map((f) => row(f, 'staged'))}
              {modified.length > 0 && groupHead(t('git.groupModified'), modified.length)}
              {modified.map((f) => row(f, 'modified'))}
              {untracked.length > 0 && groupHead(t('git.groupUntracked'), untracked.length)}
              {untracked.map((f) => row(f, 'untracked'))}
              {files.length === 0 && (
                <div className="px-3 py-6 text-center text-[11px] text-slate-500">{t('git.nothingToCommit')}</div>
              )}
            </div>

            {/* diff-ul fișierului selectat */}
            {sel && (
              <div className="flex min-h-0 flex-1 flex-col border-t border-ink-800">
                <div className="flex items-center gap-2 border-b border-ink-800 px-3 py-1 text-[10px] text-slate-500">
                  <span className="truncate font-mono" title={sel.path}>{sel.path}</span>
                  <span className="ml-auto shrink-0">{sel.staged ? t('git.diffStaged') : t('git.diffWorktree')}</span>
                  <button onClick={() => { setSel(null); setDiff('') }} className="shrink-0 rounded px-1 hover:bg-ink-800 hover:text-slate-300" title={t('git.closeDiff')}>✕</button>
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
                className="w-full resize-none rounded bg-ink-800 px-2 py-1 font-mono text-[11px] text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500"
              />
              <div className="mt-1 flex items-center gap-2">
                <span className="text-[10px] text-slate-500">{t('git.stagedCount', { n: staged.length })}</span>
                <button
                  onClick={commit}
                  disabled={busy || !msg.trim() || staged.length === 0}
                  className="ml-auto rounded bg-emerald-600 px-3 py-1 text-xs font-medium text-white hover:bg-emerald-700 disabled:opacity-40"
                >{t('git.commit')}</button>
              </div>
            </div>
          </>
        )}
      </aside>
    </>
  )
}
