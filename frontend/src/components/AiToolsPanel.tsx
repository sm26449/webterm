import { lazy, Suspense, useCallback, useEffect, useRef, useState } from 'react'
import { errText, api, ApiError, Host } from '../lib/api'
import { useConfirm } from '../lib/confirm'
import { useI18n } from '../lib/i18n'
import { useDrawer } from '../lib/useDrawer'
import { lsGet, lsSet } from '../lib/storage'
import { resolveHome } from '../lib/transfers'
import {
  AiBases, AiScope, collectionDir, frontmatterDescription, itemName, itemPath,
  singlePath, slugify, templatesFor, validName,
} from '../lib/aitools'
import { PlusIcon, RefreshIcon } from './Icons'

const FileEditor = lazy(() => import('./FileEditor'))

// Panoul „AI tools": manager grafic pentru fişierele pe care le citesc harness-urile CLI
// (Claude Code: CLAUDE.md, sub-agenţi, skill-uri; AGENTS.md generic), la locaţiile lor reale.
// Totul prin API-ul fs existent (list/preview/upload/mkdir/delete) — niciun op nou în agent,
// deci fără re-semnare. Agentul scrie ca userul care rulează şi harness-ul, deci fişierul creat
// aici îi aparţine exact lui. Catalogul, căile şi şabloanele: lib/aitools.ts.
type Entry = { name: string; dir?: boolean }
type Item = { name: string; path: string; desc: string | null }
type Data = { claudeMd: string | null; agentsMd: string | null; agents: Item[]; skills: Item[] }
type Coll = 'agent' | 'skill'

const projKey = (hostId: number) => `wt_ai_proj_${hostId}`
const MAX_DESC = 40   // câte descrieri citim (un preview per element); restul rămân fără

export default function AiToolsPanel(props: {
  host: Host; onClose: () => void; overlay?: boolean; embed?: boolean
  /** directorul proiectului propus (cwd-ul terminalului, din OSC 7) */
  projectDir?: string
}) {
  const { t } = useI18n()
  const { confirm } = useConfirm()
  const asideRef = useRef<HTMLElement>(null)
  const drawer = useDrawer(asideRef, props.onClose, !props.embed)
  const hid = props.host.id
  const isAgent = (props.host.connection_type ?? 'agent') === 'agent'

  const initialProj = props.projectDir || lsGet(projKey(hid)) || ''
  const [scope, setScope] = useState<AiScope>(props.projectDir ? 'project' : 'global')
  const [project, setProject] = useState(initialProj)
  const [projInput, setProjInput] = useState(initialProj)
  const [home, setHome] = useState<string | null>(null)
  const [data, setData] = useState<Data | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [form, setForm] = useState<{ kind: Coll; name: string; tpl: string; err: string } | null>(null)
  const [editing, setEditing] = useState<{ path: string; name: string } | null>(null)

  const fsUrl = (op: string, path: string) => `/api/hosts/${hid}/fs${op}?path=${encodeURIComponent(path)}`
  const failMsg = useCallback((e: unknown) => errText(e, t) || (e instanceof Error ? e.message : t('files.genericErr')), [t])

  /** Listarea unui director; inexistent = null (normal: ~/.claude/agents nu există până nu-l creezi). */
  const listDir = useCallback(async (path: string): Promise<Entry[] | null> => {
    try {
      return (await api<{ entries: Entry[] }>(`/api/hosts/${hid}/fs?path=${encodeURIComponent(path)}`)).entries
    } catch (e) {
      if (e instanceof ApiError && (e.code === 'files.notFound' || e.code === 'files.notDirectory')) return null
      throw e
    }
  }, [hid])

  const load = useCallback(async () => {
    if (!isAgent) return
    setError(''); setData(null)
    try {
      const h = home ?? await resolveHome(hid)
      if (!home) setHome(h)
      const b: AiBases = { home: h, project: project || null }
      if (scope === 'project' && !project) { setData({ claudeMd: null, agentsMd: null, agents: [], skills: [] }); return }
      const has = async (p: string | null) => {
        if (!p) return null
        const slash = p.lastIndexOf('/')
        const entries = await listDir(p.slice(0, slash) || '/')
        return entries?.some((e) => !e.dir && e.name === p.slice(slash + 1)) ? p : null
      }
      const coll = async (kind: Coll): Promise<Item[]> => {
        const dir = collectionDir(kind, scope, b)!
        const entries = (await listDir(dir)) || []
        const items = entries.map((e) => itemName(kind, e)).filter((n): n is string => !!n)
          .sort().map((name) => ({ name, path: itemPath(kind, dir, name), desc: null as string | null }))
        // descrierile din frontmatter, în paralel, best-effort (un fişier stricat nu strică lista)
        await Promise.all(items.slice(0, MAX_DESC).map(async (it) => {
          try {
            const pv = await api<{ text?: string }>(fsUrl('/preview', it.path))
            it.desc = frontmatterDescription(pv.text || '')
          } catch { /* skill fără SKILL.md, permisiuni — rămâne fără descriere */ }
        }))
        return items
      }
      const [claudeMd, agentsMd, agents, skills] = await Promise.all([
        has(singlePath('claude-md', scope, b)), has(singlePath('agents-md', scope, b)), coll('agent'), coll('skill'),
      ])
      setData({ claudeMd, agentsMd, agents, skills })
    } catch (e) {
      setError(failMsg(e)); setData({ claudeMd: null, agentsMd: null, agents: [], skills: [] })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hid, isAgent, scope, project, home, listDir, failMsg])

  useEffect(() => { load() }, [load])

  function applyProject() {
    const p = projInput.trim().replace(/\/+$/, '') || ''
    if (p && !p.startsWith('/') && !p.startsWith('~')) { setError(t('ai.projectAbs')); return }
    setProject(p); setScope('project')
    if (p) lsSet(projKey(hid), p)
  }

  /** Scrie un fişier NOU (directoarele părinte create la nevoie), apoi îl deschide în editor. */
  async function createFile(path: string, text: string, label: string) {
    setBusy(true); setError('')
    try {
      const dir = path.slice(0, path.lastIndexOf('/'))
      await api(`/api/hosts/${hid}/fs/mkdir`, { method: 'POST', body: JSON.stringify({ path: dir, parents: true }) })
      // re-verificăm chiar înainte de scriere: upload-ul suprascrie, iar un fişier existent nu se atinge
      const fresh = await listDir(dir)
      if (fresh?.some((e) => e.name === path.slice(path.lastIndexOf('/') + 1))) {
        setError(t('ai.exists', { name: label })); return false
      }
      await api(fsUrl('/upload', path), { method: 'POST', body: new TextEncoder().encode(text) })
      await load()
      setEditing({ path, name: label })
      return true
    } catch (e) { setError(failMsg(e)); return false } finally { setBusy(false) }
  }

  async function createSingle(kind: 'claude-md' | 'agents-md') {
    if (!home) return
    const path = singlePath(kind, scope, { home, project: project || null })
    if (!path) return
    await createFile(path, templatesFor(kind)[0].body(''), kind === 'claude-md' ? 'CLAUDE.md' : 'AGENTS.md')
  }

  async function submitForm() {
    if (!form || !home) return
    const name = form.name.trim()
    // fără auto-corectare tăcută: un nume invalid NU se creează sub alt nume; sugestia stă în mesaj
    if (!validName(name)) {
      const sug = slugify(name)
      setForm({ ...form, err: t('ai.nameRule') + (sug ? ' ' + t('ai.nameSuggest', { name: sug }) : '') })
      return
    }
    const dir = collectionDir(form.kind, scope, { home, project: project || null })
    if (!dir) return
    const tpl = templatesFor(form.kind).find((x) => x.id === form.tpl) ?? templatesFor(form.kind)[0]
    const okd = await createFile(itemPath(form.kind, dir, name), tpl.body(name), name)
    if (okd) setForm(null)
  }

  async function remove(kind: Coll, it: Item) {
    const target = kind === 'agent' ? it.path : it.path.slice(0, it.path.lastIndexOf('/'))
    if (!(await confirm({
      title: t('ai.deleteTitle', { name: it.name }),
      message: t(kind === 'agent' ? 'ai.deleteAgentMsg' : 'ai.deleteSkillMsg', { path: shown(target) }),
      confirmLabel: t('ai.delete'), danger: true,
    }))) return
    setBusy(true); setError('')
    try {
      await api(`/api/hosts/${hid}/fs/delete`, { method: 'POST', body: JSON.stringify({ path: target, recursive: kind === 'skill' }) })
      await load()
    } catch (e) { setError(failMsg(e)) } finally { setBusy(false) }
  }

  // căile afişate cu `~` în loc de home — mai scurte şi exact cum le scrii în terminal
  const shown = (p: string) => (home && (p === home || p.startsWith(home + '/')) ? '~' + p.slice(home.length) : p)

  const asideCls = props.embed
    ? 'flex h-full w-full min-h-0 flex-col bg-ink-900'
    : 'fixed inset-y-0 right-0 z-40 flex w-[90vw] max-w-md flex-col border-l border-ink-800 bg-ink-900 shadow-2xl outline-none'
    + (props.overlay ? '' : ' sm:static sm:z-auto sm:w-96 sm:max-w-none sm:shrink-0 sm:shadow-none')
  const scrimCls = props.embed ? 'hidden' : 'fixed inset-0 z-30 bg-black/60' + (props.overlay ? '' : ' sm:hidden')
  const btn = 'rounded px-2 py-1 text-[11px] text-slate-400 hover:bg-ink-700 hover:text-slate-100 disabled:opacity-40'
  const bases: AiBases | null = home ? { home, project: project || null } : null

  const singleRow = (kind: 'claude-md' | 'agents-md', present: string | null) => {
    const path = bases && singlePath(kind, scope, bases)
    if (!path) return null
    const label = kind === 'claude-md' ? 'CLAUDE.md' : 'AGENTS.md'
    return (
      <div className="flex items-center gap-2 rounded-lg border border-ink-700/70 bg-ink-800/40 px-3 py-2">
        <div className="min-w-0 flex-1">
          <div className="font-mono text-[12px] font-medium text-slate-200">{label}</div>
          <div className="truncate font-mono text-[11px] text-slate-500" title={path}>{shown(path)}</div>
        </div>
        {present
          ? <button className={btn} disabled={busy} onClick={() => setEditing({ path, name: label })}>{t('ai.edit')}</button>
          : <button className={btn} disabled={busy} onClick={() => createSingle(kind)}>{t('ai.create')}</button>}
      </div>
    )
  }

  const collection = (kind: Coll, items: Item[]) => {
    const dir = bases && collectionDir(kind, scope, bases)
    if (!dir) return null
    const title = t(kind === 'agent' ? 'ai.agents' : 'ai.skills')
    return (
      <section aria-label={title} className="mt-4">
        <div className="flex items-center gap-2">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">{title}</h3>
          <span className="truncate font-mono text-[11px] text-slate-500" title={dir}>{shown(dir)}</span>
          <button className={btn + ' ml-auto inline-flex items-center gap-1'} disabled={busy}
            onClick={() => setForm({ kind, name: '', tpl: templatesFor(kind)[0].id, err: '' })}>
            <PlusIcon /> {t(kind === 'agent' ? 'ai.newAgent' : 'ai.newSkill')}
          </button>
        </div>
        {form?.kind === kind && (
          // eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- Escape închide formularul inline fără să închidă drawer-ul (vezi useDrawer)
          <form className="mt-2 grid gap-2 rounded-lg border border-sky-700/50 bg-ink-800/60 p-3"
            onSubmit={(e) => { e.preventDefault(); submitForm() }}
            onKeyDown={(e) => { if (e.key === 'Escape') { e.stopPropagation(); setForm(null) } }}>
            <label className="text-[11px] text-slate-400">
              {t('ai.name')}
              <input autoFocus value={form.name} spellCheck={false}
                onChange={(e) => setForm({ ...form, name: e.target.value, err: '' })}
                placeholder={kind === 'agent' ? 'code-reviewer' : 'release-notes'}
                className="mt-1 block w-full rounded bg-ink-900 px-2 py-1 font-mono text-xs text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500" />
            </label>
            <label className="text-[11px] text-slate-400">
              {t('ai.template')}
              <select value={form.tpl} onChange={(e) => setForm({ ...form, tpl: e.target.value })}
                className="mt-1 block w-full rounded bg-ink-900 px-2 py-1 text-xs text-slate-200 ring-1 ring-ink-700">
                {templatesFor(kind).map((x) => <option key={x.id} value={x.id}>{t('ai.tpl.' + x.id)}</option>)}
              </select>
            </label>
            {form.err && <div role="alert" className="text-[11px] wt-danger">{form.err}</div>}
            <div className="flex justify-end gap-2">
              <button type="button" className={btn} onClick={() => setForm(null)}>{t('common.cancel')}</button>
              <button type="submit" disabled={busy}
                className="rounded bg-sky-600 px-3 py-1 text-[11px] font-medium text-white hover:bg-sky-700 disabled:opacity-50">{t('ai.create')}</button>
            </div>
          </form>
        )}
        {items.length === 0 ? (
          <p className="mt-2 text-[11px] text-slate-500">{t(kind === 'agent' ? 'ai.noAgents' : 'ai.noSkills')}</p>
        ) : (
          <ul className="mt-2 grid gap-1.5">
            {items.map((it) => (
              <li key={it.name} className="flex items-start gap-2 rounded-lg border border-ink-700/70 bg-ink-800/40 px-3 py-2">
                <div className="min-w-0 flex-1">
                  <div className="truncate font-mono text-[12px] font-medium text-slate-200" title={it.path}>{it.name}</div>
                  {it.desc && <div className="line-clamp-2 text-[11px] text-slate-500" title={it.desc}>{it.desc}</div>}
                </div>
                <button className={btn} disabled={busy} onClick={() => setEditing({ path: it.path, name: it.name })}
                  aria-label={`${t('ai.edit')} ${it.name}`}>{t('ai.edit')}</button>
                <button className={btn + ' hover:!text-rose-300'} disabled={busy} onClick={() => remove(kind, it)}
                  aria-label={`${t('ai.delete')} ${it.name}`}>{t('ai.delete')}</button>
              </li>
            ))}
          </ul>
        )}
      </section>
    )
  }

  return (
    <>
      <div className={scrimCls} onClick={props.onClose} aria-hidden="true" />
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- Escape pe regiunea drawer-ului (vezi useDrawer) */}
      <aside ref={asideRef} className={asideCls} aria-label={t('ai.title')} onKeyDown={drawer.onKeyDown}>
        <div className="flex items-center gap-2 border-b border-ink-800 px-3 py-2">
          <span className="text-sm font-semibold text-slate-200">{t('ai.title')}</span>
          <span className="text-[11px] text-slate-500">Claude Code · AGENTS.md</span>
          <button onClick={load} className="wt-touch ml-auto shrink-0 rounded px-1.5 text-slate-400 hover:bg-ink-800"
            title={t('ai.reload')} aria-label={t('ai.reload')}><RefreshIcon /></button>
          {!props.embed && (
            <button onClick={props.onClose} aria-label={t('common.close')}
              className="wt-touch shrink-0 rounded px-2 py-1 text-slate-400 hover:bg-ink-800">✕</button>
          )}
        </div>
        {!isAgent ? (
          <div className="p-4 text-center text-xs text-slate-500">{t('files.noAgent', { type: (props.host.connection_type ?? '').toUpperCase() })}</div>
        ) : (
          <>
            <div className="border-b border-ink-800 px-3 py-2">
              <div role="tablist" aria-label={t('ai.scope')} className="flex gap-1">
                {(['global', 'project'] as AiScope[]).map((s) => (
                  <button key={s} role="tab" aria-selected={scope === s} onClick={() => setScope(s)}
                    className={`rounded px-2.5 py-1 text-xs font-medium ${scope === s ? 'bg-ink-700 text-slate-100' : 'text-slate-400 hover:bg-ink-800'}`}>
                    {t(s === 'global' ? 'ai.scopeGlobal' : 'ai.scopeProject')}
                  </button>
                ))}
              </div>
              {scope === 'project' && (
                <form className="mt-2 flex gap-2" onSubmit={(e) => { e.preventDefault(); applyProject() }}>
                  <input value={projInput} onChange={(e) => setProjInput(e.target.value)} spellCheck={false}
                    aria-label={t('ai.projectDir')} placeholder={t('ai.projectPh')}
                    className="min-w-0 flex-1 rounded bg-ink-800/60 px-2 py-1 font-mono text-xs text-slate-300 ring-1 ring-ink-700 focus:ring-sky-500" />
                  <button type="submit" className="shrink-0 rounded border border-ink-700 px-2 py-1 text-[11px] text-slate-300 hover:bg-ink-800">{t('ai.open')}</button>
                </form>
              )}
              <p className="mt-1.5 text-[11px] text-slate-500">
                {t(scope === 'global' ? 'ai.scopeGlobalHint' : 'ai.scopeProjectHint')}
              </p>
            </div>
            {error && <div role="alert" className="border-b border-ink-800 bg-ink-800 px-3 py-1.5 text-[11px] wt-danger">{error}</div>}
            <div className="min-h-0 flex-1 overflow-y-auto p-3">
              {data === null ? (
                <div className="p-4 text-center text-xs text-slate-500">{t('ai.loading')}</div>
              ) : scope === 'project' && !project ? (
                <div className="p-4 text-center text-xs text-slate-500">{t('ai.pickProject')}</div>
              ) : (
                <>
                  <div className="grid gap-1.5">
                    {singleRow('claude-md', data.claudeMd)}
                    {singleRow('agents-md', data.agentsMd)}
                  </div>
                  {collection('agent', data.agents)}
                  {collection('skill', data.skills)}
                </>
              )}
            </div>
          </>
        )}
      </aside>
      {editing && (
        <Suspense fallback={null}>
          <FileEditor hostId={hid} path={editing.path} name={editing.name}
            onClose={() => setEditing(null)} onSaved={() => { load() }} />
        </Suspense>
      )}
    </>
  )
}

