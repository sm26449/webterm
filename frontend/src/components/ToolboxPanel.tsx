import { useCallback, useEffect, useState } from 'react'
import { errText, api, ApiError, Connection, Host } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { RefreshIcon, TerminalPromptIcon, PlusIcon, TrashIcon, PencilIcon } from './Icons'

// Toolbox: lansatoare de conexiuni DB. O conexiune salvată → un click deschide o sesiune care
// rulează CLI-ul potrivit pe host (psql/mysql/mongosh/clickhouse-client/redis-cli), cu ţinta
// pre-completată. Slice 1: politica `ask` (clientul cere parola — zero secrete stocate).
// (Tab-urile Library/History vin în felii ulterioare.)
const ENGINES: { id: Connection['engine']; label: string; color: string; port: number }[] = [
  { id: 'postgres', label: 'PostgreSQL', color: '#6bb2f0', port: 5432 },
  { id: 'mysql', label: 'MySQL / MariaDB', color: '#e0b063', port: 3306 },
  { id: 'mongodb', label: 'MongoDB', color: '#4bd494', port: 27017 },
  { id: 'clickhouse', label: 'ClickHouse', color: '#f0cf5a', port: 9000 },
  { id: 'redis', label: 'Redis', color: '#f0857a', port: 6379 },
]
const engOf = (e: string) => ENGINES.find((x) => x.id === e)

type Draft = { id?: number; label: string; engine: Connection['engine']; target_host: string
  target_port: string; username: string; dbname: string; cred_policy: 'ask' }

export default function ToolboxPanel(props: {
  host: Host; onClose: () => void; overlay?: boolean
  /** deschide o sesiune care rulează CLI-ul conexiunii */
  onOpen: (host: Host, connId: number) => void
}) {
  const { t } = useI18n()
  const [rows, setRows] = useState<Connection[] | null>(null)
  const [error, setError] = useState('')
  const [edit, setEdit] = useState<Draft | null>(null)   // modalul de creare/editare

  const asideCls = 'fixed inset-y-0 right-0 z-40 flex w-[90vw] max-w-md flex-col border-l border-ink-800 bg-ink-900 shadow-2xl'
    + (props.overlay ? '' : ' sm:static sm:z-auto sm:w-96 sm:max-w-none sm:shrink-0 sm:shadow-none')
  const scrimCls = 'fixed inset-0 z-30 bg-black/60' + (props.overlay ? '' : ' sm:hidden')

  const load = useCallback(async () => {
    setError('')
    try {
      const r = await api<{ connections: Connection[] }>(`/api/hosts/${props.host.id}/connections`)
      setRows(r.connections)
    } catch (e) {
      setError(errText(e, t) || (e instanceof ApiError ? e.message : t('toolbox.error'))); setRows([])
    }
  }, [props.host.id, t])
  useEffect(() => { load() }, [load])

  async function save(d: Draft) {
    const body = { label: d.label, engine: d.engine, target_host: d.target_host,
      target_port: d.target_port ? Number(d.target_port) : null,
      username: d.username, dbname: d.dbname, cred_policy: 'ask' }
    try {
      await api(`/api/hosts/${props.host.id}/connections${d.id ? '/' + d.id : ''}`,
        { method: d.id ? 'PATCH' : 'POST', body: JSON.stringify(body) })
      setEdit(null); await load()
    } catch (e) { setError(errText(e, t) || (e instanceof ApiError ? e.message : t('toolbox.error'))) }
  }
  async function del(c: Connection) {
    if (!confirm(t('toolbox.confirmDelete', { label: c.label }))) return
    try { await api(`/api/hosts/${props.host.id}/connections/${c.id}`, { method: 'DELETE' }); await load() }
    catch (e) { setError(errText(e, t) || t('toolbox.error')) }
  }
  const blank = (): Draft => ({ label: '', engine: 'postgres', target_host: '', target_port: '',
    username: '', dbname: '', cred_policy: 'ask' })
  const toDraft = (c: Connection): Draft => ({ id: c.id, label: c.label, engine: c.engine,
    target_host: c.target_host, target_port: c.target_port ? String(c.target_port) : '',
    username: c.username, dbname: c.dbname, cred_policy: 'ask' })

  return (
    <>
      <div className={scrimCls} onClick={props.onClose} aria-hidden="true" />
      <aside className={asideCls} aria-label={t('toolbox.title')}>
        <div className="flex items-center gap-2 border-b border-ink-800 px-3 py-2">
          <span className="text-sm font-semibold text-slate-200">{t('toolbox.title')}</span>
          <span className="rounded bg-ink-800 px-1.5 py-0.5 text-[10px] font-medium text-slate-400">{t('toolbox.connections')}</span>
          <button onClick={load} className="wt-touch ml-auto shrink-0 rounded px-1.5 text-slate-400 hover:bg-ink-800"
            title={t('toolbox.reload')}><RefreshIcon /></button>
          <button onClick={() => setEdit(blank())} className="wt-touch shrink-0 rounded px-1.5 text-sky-400 hover:bg-ink-800"
            title={t('toolbox.new')} aria-label={t('toolbox.new')}><PlusIcon /></button>
          <button onClick={props.onClose} aria-label={t('common.close')}
            className="wt-touch shrink-0 rounded px-2 py-1 text-slate-400 hover:bg-ink-800">✕</button>
        </div>
        {error && <div className="border-b border-ink-800 bg-ink-800 px-3 py-1.5 text-[11px] wt-danger">{error}</div>}
        <div className="min-h-0 flex-1 overflow-y-auto">
          {rows === null ? (
            <div className="p-4 text-center text-xs text-slate-500">{t('toolbox.loading')}</div>
          ) : rows.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-500">
              {t('toolbox.empty')}<br />
              <button onClick={() => setEdit(blank())} className="mt-2 wt-link">{t('toolbox.newFirst')}</button>
            </div>
          ) : rows.map((c) => {
            const e = engOf(c.engine)
            return (
              <div key={c.id} className="group flex items-center gap-2 border-b border-ink-800/60 px-3 py-2">
                <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: e?.color || '#64748b' }}
                  title={e?.label} aria-hidden="true" />
                <button onClick={() => props.onOpen(props.host, c.id)}
                  className="min-w-0 flex-1 text-left" title={t('toolbox.open')}>
                  <div className="truncate text-[13px] font-medium text-slate-200">{c.label}</div>
                  <div className="truncate font-mono text-[11px] text-slate-500">
                    {c.username ? c.username + '@' : ''}{c.target_host || 'localhost'}
                    {c.target_port ? ':' + c.target_port : ''}{c.dbname ? '/' + c.dbname : ''}
                    <span className="ml-1 text-slate-600">· {t('toolbox.ask')}</span>
                  </div>
                </button>
                <div className="flex shrink-0 items-center gap-0.5 opacity-0 group-hover:opacity-100 [@media(hover:none)]:opacity-100">
                  <button onClick={() => setEdit(toDraft(c))} className="rounded p-1 text-slate-500 hover:bg-ink-700 hover:text-slate-200"
                    title={t('toolbox.edit')} aria-label={t('toolbox.edit')}><PencilIcon /></button>
                  <button onClick={() => del(c)} className="rounded p-1 text-slate-500 hover:bg-ink-700 hover:text-rose-300"
                    title={t('toolbox.delete')} aria-label={t('toolbox.delete')}><TrashIcon /></button>
                </div>
                <button onClick={() => props.onOpen(props.host, c.id)}
                  className="shrink-0 rounded px-1.5 py-0.5 text-sky-400 hover:bg-ink-800"
                  title={t('toolbox.open')} aria-label={t('toolbox.open')}><TerminalPromptIcon /></button>
              </div>
            )
          })}
        </div>
      </aside>

      {edit && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4" onClick={() => setEdit(null)}>
          <div className="glass w-full max-w-sm rounded-2xl p-5" onClick={(ev) => ev.stopPropagation()}>
            <h2 className="mb-3 text-base font-semibold">{edit.id ? t('toolbox.editTitle') : t('toolbox.newTitle')}</h2>
            <div className="space-y-2 text-sm">
              <label className="block">
                <span className="mb-0.5 block text-xs text-slate-400">{t('toolbox.fLabel')}</span>
                <input autoFocus value={edit.label} onChange={(ev) => setEdit({ ...edit, label: ev.target.value })}
                  placeholder="prod-postgres" className="w-full rounded bg-ink-800 px-2 py-1 text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" />
              </label>
              <label className="block">
                <span className="mb-0.5 block text-xs text-slate-400">{t('toolbox.fEngine')}</span>
                <select value={edit.engine}
                  onChange={(ev) => setEdit({ ...edit, engine: ev.target.value as Connection['engine'] })}
                  className="w-full rounded bg-ink-800 px-2 py-1 text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500">
                  {ENGINES.map((e) => <option key={e.id} value={e.id}>{e.label}</option>)}
                </select>
              </label>
              <div className="flex gap-2">
                <label className="block flex-1"><span className="mb-0.5 block text-xs text-slate-400">{t('toolbox.fHost')}</span>
                  <input value={edit.target_host} onChange={(ev) => setEdit({ ...edit, target_host: ev.target.value })}
                    placeholder="localhost" className="w-full rounded bg-ink-800 px-2 py-1 font-mono text-[12px] text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" /></label>
                <label className="block w-24"><span className="mb-0.5 block text-xs text-slate-400">{t('toolbox.fPort')}</span>
                  <input value={edit.target_port} inputMode="numeric" onChange={(ev) => setEdit({ ...edit, target_port: ev.target.value.replace(/\D/g, '') })}
                    placeholder={String(engOf(edit.engine)?.port || '')} className="w-full rounded bg-ink-800 px-2 py-1 font-mono text-[12px] text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" /></label>
              </div>
              <div className="flex gap-2">
                <label className="block flex-1"><span className="mb-0.5 block text-xs text-slate-400">{t('toolbox.fUser')}</span>
                  <input value={edit.username} onChange={(ev) => setEdit({ ...edit, username: ev.target.value })}
                    className="w-full rounded bg-ink-800 px-2 py-1 font-mono text-[12px] text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" /></label>
                <label className="block flex-1"><span className="mb-0.5 block text-xs text-slate-400">{t('toolbox.fDb')}</span>
                  <input value={edit.dbname} onChange={(ev) => setEdit({ ...edit, dbname: ev.target.value })}
                    className="w-full rounded bg-ink-800 px-2 py-1 font-mono text-[12px] text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" /></label>
              </div>
              <p className="text-[11px] text-slate-500">{t('toolbox.askHint')}</p>
            </div>
            <div className="mt-4 flex justify-end gap-2 text-sm">
              <button onClick={() => setEdit(null)} className="rounded px-3 py-1.5 text-slate-400 hover:bg-ink-800">{t('common.cancel')}</button>
              <button onClick={() => save(edit)} disabled={!edit.label.trim()}
                className="rounded bg-sky-600 px-3 py-1.5 font-medium text-white hover:bg-sky-700 disabled:opacity-40">{t('common.save')}</button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
