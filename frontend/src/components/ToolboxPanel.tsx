import { useCallback, useEffect, useState } from 'react'
import { errText, api, ApiError, Connection, DeployKeyDeployment, DeployKeyInfo, Host, withStepup } from '../lib/api'
import { copyText } from '../lib/clipboard'
import { useI18n } from '../lib/i18n'
import { TerminalPromptIcon, PlusIcon, TrashIcon, PencilIcon, CopyIcon } from './Icons'

// Bibliotecă de reţete built-in (client-side): comenzi comune pe categorii, cu {placeholder}-e.
// Acţiunea e Copy (universal — merge şi din pagina hostului, şi din sesiune); lipeşti în terminal.
const LIBRARY: { cat: string; items: { label: string; cmd: string }[] }[] = [
  { cat: 'git', items: [
    { label: 'status', cmd: 'git status' },
    { label: 'log grafic', cmd: 'git log --oneline --graph --decorate -20' },
    { label: 'pull --rebase', cmd: 'git pull --rebase' },
    { label: 'branch nou', cmd: 'git checkout -b {branch}' },
    { label: 'stash', cmd: 'git stash' },
  ] },
  { cat: 'docker', items: [
    { label: 'ps', cmd: 'docker ps -a' },
    { label: 'logs -f', cmd: 'docker logs -f {container}' },
    { label: 'shell în container', cmd: 'docker exec -it {container} sh' },
    { label: 'compose up', cmd: 'docker compose up -d' },
    { label: 'prune', cmd: 'docker system prune -f' },
  ] },
  { cat: 'systemd', items: [
    { label: 'status', cmd: 'systemctl status {service}' },
    { label: 'restart', cmd: 'systemctl restart {service}' },
    { label: 'jurnal live', cmd: 'journalctl -u {service} -f' },
  ] },
  { cat: 'system', items: [
    { label: 'disc', cmd: 'df -h' },
    { label: 'mărimi dir', cmd: 'du -sh * | sort -h' },
    { label: 'memorie', cmd: 'free -h' },
    { label: 'porturi', cmd: 'ss -tulnp' },
  ] },
  { cat: 'db', items: [
    { label: 'pg_dump', cmd: 'pg_dump -U {user} {db} > {db}.sql' },
    { label: 'mysqldump', cmd: 'mysqldump -u {user} -p {db} > {db}.sql' },
  ] },
]
type Hist = { id: number; command: string; cwd: string; exit_code: number | null; created: number }

// Toolbox: 3 tab-uri. Connections = lansatoare de conexiuni DB (un click → o sesiune care rulează
// CLI-ul potrivit pe host: psql/mysql/mongosh/clickhouse-client/redis-cli, cu ţinta pre-completată;
// politica `ask` = clientul cere parola, `stored` = parola criptată în vault, injectată o dată în
// promptul PTY de agent). Library = reţete built-in (Copy). History = comenzile hostului (OSC 133, Copy).
const ENGINES: { id: Connection['engine']; label: string; color: string; port: number }[] = [
  { id: 'postgres', label: 'PostgreSQL', color: '#6bb2f0', port: 5432 },
  { id: 'mysql', label: 'MySQL / MariaDB', color: '#e0b063', port: 3306 },
  { id: 'mongodb', label: 'MongoDB', color: '#4bd494', port: 27017 },
  { id: 'clickhouse', label: 'ClickHouse', color: '#f0cf5a', port: 9000 },
  { id: 'redis', label: 'Redis', color: '#f0857a', port: 6379 },
]
const engOf = (e: string) => ENGINES.find((x) => x.id === e)

type Draft = { id?: number; label: string; engine: Connection['engine']; target_host: string
  target_port: string; username: string; dbname: string; cred_policy: 'ask' | 'stored'; credential: string }

export default function ToolboxPanel(props: {
  host: Host; onClose: () => void; overlay?: boolean
  /** deschide o sesiune care rulează CLI-ul conexiunii */
  onOpen: (host: Host, connId: number) => void
}) {
  const { t } = useI18n()
  const [rows, setRows] = useState<Connection[] | null>(null)
  const [error, setError] = useState('')
  const [edit, setEdit] = useState<Draft | null>(null)   // modalul de creare/editare
  const [tab, setTab] = useState<'connections' | 'sshkeys' | 'library' | 'history'>('connections')
  const [q, setQ] = useState('')                          // filtru pt. Library/History
  const [hist, setHist] = useState<Hist[] | null>(null)   // istoricul de comenzi al hostului
  const copy = (cmd: string) => { copyText(cmd) }         // copyText afişează toast-ul standard

  // ── SSH keys (chei de deploy host→host): privata trăieşte pe hostul sursă; aici doar
  //    materialul public + graful sursă→ţintă, cu revoke per-muchie. Vezi audit v54 (H-1..H-4).
  const [dk, setDk] = useState<DeployKeyInfo | null>(null)
  const [dkHosts, setDkHosts] = useState<Host[]>([])      // ţinte posibile (hosturi de agent)
  const [dkBusy, setDkBusy] = useState('')
  const [deployTo, setDeployTo] = useState('')
  const [fromIp, setFromIp] = useState('')

  const loadDk = useCallback(async () => {
    try {
      const [info, hosts] = await Promise.all([
        api<DeployKeyInfo>(`/api/hosts/${props.host.id}/deploy-key`),
        api<Host[]>('/api/hosts'),
      ])
      setDk(info)
      setDkHosts(hosts.filter((h) => (h.connection_type ?? 'agent') === 'agent' && h.id !== props.host.id))
    } catch (e) { setError(errText(e, t)); setDk({ key: null, deployments: [], inbound: [] }) }
  }, [props.host.id, t])
  useEffect(() => { if (tab === 'sshkeys' && dk === null) loadDk() }, [tab, dk, loadDk])

  // garda anti-pivot (409 sshkey.pivot) cere un DA explicit → confirm() + retry cu confirmed
  async function dkRun(busy: string, fn: (confirmed: boolean) => Promise<unknown>) {
    setDkBusy(busy); setError('')
    try { await fn(false) } catch (e) {
      if (e instanceof ApiError && e.code === 'sshkey.pivot') {
        if (confirm(t('toolbox.ssh.pivotConfirm'))) {
          try { await fn(true) } catch (e2) { setError(errText(e2, t)) }
        }
      } else { setError(errText(e, t)) }
    }
    setDkBusy(''); await loadDk()
  }
  const dkGenerate = () => dkRun('generate', (confirmed) =>
    api(`/api/hosts/${props.host.id}/deploy-key/generate`, { method: 'POST', body: JSON.stringify({ confirmed }) }))
  const dkDeploy = () => dkRun('deploy', (confirmed) =>
    api(`/api/hosts/${deployTo}/deploy-key/deploy`, { method: 'POST',
      body: JSON.stringify({ key_host_id: props.host.id, from_ip: fromIp.trim(), confirmed }) }))
  const dkVerify = (d: DeployKeyDeployment) => dkRun('verify' + d.id, () =>
    api(`/api/hosts/${d.target_host_id}/deploy-key/verify`, { method: 'POST', body: JSON.stringify({ key_host_id: props.host.id }) }))
  const dkRevoke = (d: DeployKeyDeployment) => {
    if (!confirm(t('toolbox.ssh.confirmRevoke', { target: d.target_name }))) return
    dkRun('revoke' + d.id, () =>
      api(`/api/hosts/${d.target_host_id}/deploy-key/revoke`, { method: 'POST', body: JSON.stringify({ key_host_id: props.host.id }) }))
  }
  const dkDelete = () => {
    if (!confirm(t('toolbox.ssh.confirmDeleteKey'))) return
    dkRun('delete', () => api(`/api/hosts/${props.host.id}/deploy-key`, { method: 'DELETE' }))
  }
  const DK_STATUS: Record<DeployKeyDeployment['status'], string> = {
    deployed: 'bg-emerald-500', edited: 'bg-amber-400', missing: 'bg-rose-500', revoked: 'bg-slate-600',
  }

  const loadHist = useCallback(async () => {
    try {
      const r = await api<Hist[]>(`/api/history?host_id=${props.host.id}&limit=200`)
      setHist(r)
    } catch { setHist([]) }
  }, [props.host.id])
  useEffect(() => { if (tab === 'history' && hist === null) loadHist() }, [tab, hist, loadHist])

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
      username: d.username, dbname: d.dbname,
      cred_policy: d.engine === 'redis' ? 'ask' : d.cred_policy,
      // redis n-are `stored` (fără prompt) → nu trimite parola chiar dacă draftul o poartă dintr-un engine anterior
      credential: (d.engine !== 'redis' && d.cred_policy === 'stored') ? d.credential : '' }
    try {
      // pe host-uri 2FA orice mutaţie CRUD cere step-up (backend H1); withStepup rulează ceremonia şi
      // reîncearcă. Pe host-uri fără 2FA e transparent (fn() reuşeşte din prima).
      await withStepup(props.host.id, () => api(`/api/hosts/${props.host.id}/connections${d.id ? '/' + d.id : ''}`,
        { method: d.id ? 'PATCH' : 'POST', body: JSON.stringify(body) }))
      setEdit(null); await load()
    } catch (e) { setError(errText(e, t) || (e instanceof ApiError ? e.message : t('toolbox.error'))) }
  }
  async function del(c: Connection) {
    if (!confirm(t('toolbox.confirmDelete', { label: c.label }))) return
    try { await withStepup(props.host.id, () => api(`/api/hosts/${props.host.id}/connections/${c.id}`, { method: 'DELETE' })); await load() }
    catch (e) { setError(errText(e, t) || t('toolbox.error')) }
  }
  const blank = (): Draft => ({ label: '', engine: 'postgres', target_host: '', target_port: '',
    username: '', dbname: '', cred_policy: 'ask', credential: '' })
  const toDraft = (c: Connection): Draft => ({ id: c.id, label: c.label, engine: c.engine,
    target_host: c.target_host, target_port: c.target_port ? String(c.target_port) : '',
    username: c.username, dbname: c.dbname,
    cred_policy: c.cred_policy === 'stored' ? 'stored' : 'ask', credential: '' })

  return (
    <>
      <div className={scrimCls} onClick={props.onClose} aria-hidden="true" />
      <aside className={asideCls} aria-label={t('toolbox.title')}>
        <div className="flex items-center gap-1 border-b border-ink-800 px-2 py-1.5">
          {(['connections', 'sshkeys', 'library', 'history'] as const).map((tb) => (
            <button key={tb} onClick={() => setTab(tb)}
              aria-pressed={tab === tb}
              className={`rounded px-2 py-1 text-[12px] font-medium ${tab === tb
                ? 'bg-ink-800 text-slate-100' : 'text-slate-400 hover:bg-ink-800/60'}`}>
              {t('toolbox.tab.' + tb)}
            </button>
          ))}
          {tab === 'connections' && (
            <button onClick={() => setEdit(blank())} className="wt-touch ml-auto shrink-0 rounded px-1.5 text-sky-400 hover:bg-ink-800"
              title={t('toolbox.new')} aria-label={t('toolbox.new')}><PlusIcon /></button>
          )}
          <button onClick={props.onClose} aria-label={t('common.close')}
            className={`wt-touch shrink-0 rounded px-2 py-1 text-slate-400 hover:bg-ink-800${tab === 'connections' ? '' : ' ml-auto'}`}>✕</button>
        </div>
        {(tab === 'library' || tab === 'history') && (
          <div className="border-b border-ink-800 px-3 py-1.5">
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('toolbox.filterPh')}
              className="w-full rounded bg-ink-800/60 px-2 py-1 text-xs text-slate-300 ring-1 ring-ink-700 focus:ring-sky-500" />
          </div>
        )}
        {error && <div className="border-b border-ink-800 bg-ink-800 px-3 py-1.5 text-[11px] wt-danger">{error}</div>}
        <div className="min-h-0 flex-1 overflow-y-auto">

          {/* ── CONNECTIONS ── */}
          {tab === 'connections' && (rows === null ? (
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
                    <span className="ml-1 text-slate-600">· {c.cred_policy === 'stored' ? t('toolbox.stored') : t('toolbox.ask')}</span>
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
          }))}

          {/* ── SSH KEYS (chei de deploy host→host) ── */}
          {tab === 'sshkeys' && (dk === null ? (
            <div className="p-4 text-center text-xs text-slate-500">{t('toolbox.loading')}</div>
          ) : (
            <div className="space-y-3 p-3 text-[12px]">
              <p className="rounded bg-amber-500/10 px-2 py-1.5 text-[11px] leading-snug text-amber-300/90">
                {t('toolbox.ssh.warn')}
              </p>
              {!dk.key ? (
                <div className="text-center">
                  <p className="mb-2 text-[11.5px] leading-snug text-slate-400">{t('toolbox.ssh.none')}</p>
                  <button onClick={dkGenerate} disabled={dkBusy !== ''}
                    className="rounded bg-sky-600 px-3 py-1.5 text-[12px] font-medium text-white hover:bg-sky-700 disabled:opacity-40">
                    {dkBusy === 'generate' ? t('toolbox.ssh.generating') : t('toolbox.ssh.generate')}
                  </button>
                </div>
              ) : (
                <>
                  <div className="rounded border border-ink-800 bg-ink-800/40 p-2">
                    <div className="flex items-center gap-2">
                      <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-slate-300"
                        title={dk.key.fingerprint}>{dk.key.fingerprint}</span>
                      <button onClick={() => copy(dk.key!.public_key)}
                        className="shrink-0 rounded p-1 text-slate-500 hover:bg-ink-700 hover:text-sky-400"
                        title={t('toolbox.ssh.copyPub')} aria-label={t('toolbox.ssh.copyPub')}><CopyIcon /></button>
                      <button onClick={dkDelete} disabled={dkBusy !== ''}
                        className="shrink-0 rounded p-1 text-slate-500 hover:bg-ink-700 hover:text-rose-300"
                        title={t('toolbox.ssh.deleteKey')} aria-label={t('toolbox.ssh.deleteKey')}><TrashIcon /></button>
                    </div>
                    <div className="mt-0.5 font-mono text-[10px] text-slate-500">~/.ssh/webterm_ed25519</div>
                  </div>

                  <div className="rounded border border-ink-800 p-2">
                    <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-slate-500">{t('toolbox.ssh.deployTo')}</div>
                    <div className="flex flex-col gap-1.5">
                      <select value={deployTo} onChange={(ev) => setDeployTo(ev.target.value)}
                        className="w-full rounded bg-ink-800 px-2 py-1 text-[12px] text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500"
                        aria-label={t('toolbox.ssh.deployTo')}>
                        <option value="">—</option>
                        {dkHosts.map((h) => (
                          <option key={h.id} value={h.id} disabled={!h.online}>
                            {h.name}{h.agent_user ? ` (${h.agent_user})` : ''}{h.online ? '' : ' · offline'}
                          </option>
                        ))}
                      </select>
                      <input value={fromIp} onChange={(ev) => setFromIp(ev.target.value)}
                        placeholder={t('toolbox.ssh.fromIpPh')} aria-label={t('toolbox.ssh.fromIp')}
                        className="w-full rounded bg-ink-800 px-2 py-1 font-mono text-[11px] text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" />
                      <button onClick={dkDeploy} disabled={!deployTo || dkBusy !== ''}
                        className="rounded bg-sky-600 px-3 py-1.5 text-[12px] font-medium text-white hover:bg-sky-700 disabled:opacity-40">
                        {dkBusy === 'deploy' ? t('toolbox.ssh.deploying') : t('toolbox.ssh.deploy')}
                      </button>
                    </div>
                    <p className="mt-1 text-[10.5px] leading-snug text-slate-500">{t('toolbox.ssh.fromIpHint')}</p>
                  </div>

                  <div>
                    <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-slate-500">{t('toolbox.ssh.deployments')}</div>
                    {dk.deployments.length === 0 ? (
                      <p className="text-[11px] text-slate-500">{t('toolbox.ssh.noDeployments')}</p>
                    ) : dk.deployments.map((d) => (
                      <div key={d.id} className="group flex items-center gap-2 border-b border-ink-800/60 py-1.5">
                        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${DK_STATUS[d.status]}`}
                          title={t('toolbox.ssh.status.' + d.status)} aria-hidden="true" />
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-[12px] text-slate-200">{d.target_name}</div>
                          <div className="truncate font-mono text-[10.5px] text-slate-500">
                            {d.target_user || '?'}@{d.target_hostname || d.target_name}
                            {d.options ? ' · ' + d.options : ''} · {t('toolbox.ssh.status.' + d.status)}
                          </div>
                        </div>
                        <button onClick={() => copy(`ssh ${d.target_user || 'user'}@${d.target_hostname || d.target_name}`)}
                          className="shrink-0 rounded p-1 text-slate-500 hover:bg-ink-700 hover:text-sky-400"
                          title={t('toolbox.ssh.copySsh')} aria-label={t('toolbox.ssh.copySsh')}><CopyIcon /></button>
                        {d.status !== 'revoked' && (
                          <>
                            <button onClick={() => dkVerify(d)} disabled={dkBusy !== ''}
                              className="shrink-0 rounded px-1.5 py-0.5 text-[11px] text-slate-400 hover:bg-ink-700 hover:text-slate-200"
                              title={t('toolbox.ssh.verify')}>{t('toolbox.ssh.verify')}</button>
                            <button onClick={() => dkRevoke(d)} disabled={dkBusy !== ''}
                              className="shrink-0 rounded p-1 text-slate-500 hover:bg-ink-700 hover:text-rose-300"
                              title={t('toolbox.ssh.revoke')} aria-label={t('toolbox.ssh.revoke')}><TrashIcon /></button>
                          </>
                        )}
                      </div>
                    ))}
                    {dk.deployments.some((d) => d.status !== 'revoked') && (
                      <p className="mt-1.5 text-[10.5px] leading-snug text-slate-500">
                        {t('toolbox.ssh.sudoersHint')}{' '}
                        <button className="wt-link" onClick={() => {
                          const u = dk.deployments.find((d) => d.status !== 'revoked')?.target_user || 'webterm'
                          copy(`echo '${u} ALL=(root) NOPASSWD: /usr/bin/docker, /usr/bin/systemctl' | sudo tee /etc/sudoers.d/${u}-deploy && sudo chmod 440 /etc/sudoers.d/${u}-deploy`)
                        }}>{t('toolbox.ssh.sudoersCopy')}</button>
                      </p>
                    )}
                  </div>
                </>
              )}

              {dk.inbound.length > 0 && (
                <div>
                  <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-slate-500">{t('toolbox.ssh.inbound')}</div>
                  {dk.inbound.map((k, i) => (
                    <div key={i} className="border-b border-ink-800/60 py-1.5">
                      <div className="text-[12px] text-slate-200">{k.source_name}</div>
                      <div className="truncate font-mono text-[10.5px] text-slate-500" title={k.fingerprint}>{k.fingerprint}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}

          {/* ── LIBRARY (reţete built-in, Copy) ── */}
          {tab === 'library' && LIBRARY.map((grp) => {
            const items = grp.items.filter((it) => !q ||
              it.cmd.toLowerCase().includes(q.toLowerCase()) || it.label.toLowerCase().includes(q.toLowerCase()) ||
              grp.cat.includes(q.toLowerCase()))
            if (!items.length) return null
            return (
              <div key={grp.cat}>
                <div className="sticky top-0 bg-ink-900/95 px-3 py-1 font-mono text-[10px] uppercase tracking-wide text-slate-500">{grp.cat}</div>
                {items.map((it) => (
                  <button key={it.cmd} onClick={() => copy(it.cmd)}
                    className="group flex w-full items-center gap-2 border-b border-ink-800/60 px-3 py-1.5 text-left hover:bg-ink-800/50"
                    title={t('toolbox.copy')}>
                    <span className="w-28 shrink-0 truncate text-[12px] text-slate-300">{it.label}</span>
                    <code className="min-w-0 flex-1 truncate font-mono text-[11px] text-slate-500">{it.cmd}</code>
                    <span className="shrink-0 text-slate-600 group-hover:text-sky-400"><CopyIcon /></span>
                  </button>
                ))}
              </div>
            )
          })}

          {/* ── HISTORY (comenzile hostului, din OSC 133; Copy) ── */}
          {tab === 'history' && (hist === null ? (
            <div className="p-4 text-center text-xs text-slate-500">{t('toolbox.loading')}</div>
          ) : (() => {
            const items = hist.filter((h) => !q || h.command.toLowerCase().includes(q.toLowerCase()))
            if (!items.length) return <div className="p-6 text-center text-xs text-slate-500">{t('toolbox.histEmpty')}</div>
            return items.map((h) => (
              <button key={h.id} onClick={() => copy(h.command)}
                className="group flex w-full items-start gap-2 border-b border-ink-800/60 px-3 py-1.5 text-left hover:bg-ink-800/50"
                title={t('toolbox.copy')}>
                <span className={`mt-0.5 h-1.5 w-1.5 shrink-0 rounded-full ${h.exit_code === 0 ? 'bg-emerald-500' : h.exit_code == null ? 'bg-slate-600' : 'bg-rose-500'}`}
                  title={h.exit_code == null ? '' : 'exit ' + h.exit_code} aria-hidden="true" />
                <code className="min-w-0 flex-1 break-all font-mono text-[11.5px] text-slate-300">{h.command}</code>
                <span className="shrink-0 text-slate-600 group-hover:text-sky-400"><CopyIcon /></span>
              </button>
            ))
          })())}
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
              {edit.engine !== 'redis' && (
                <label className="block">
                  <span className="mb-0.5 block text-xs text-slate-400">{t('toolbox.fAuth')}</span>
                  <select value={edit.cred_policy}
                    onChange={(ev) => setEdit({ ...edit, cred_policy: ev.target.value as 'ask' | 'stored' })}
                    className="w-full rounded bg-ink-800 px-2 py-1 text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500">
                    <option value="ask">{t('toolbox.authAsk')}</option>
                    <option value="stored">{t('toolbox.authStored')}</option>
                  </select>
                </label>
              )}
              {edit.engine !== 'redis' && edit.cred_policy === 'stored' && (
                <label className="block">
                  <span className="mb-0.5 block text-xs text-slate-400">{t('toolbox.fPassword')}</span>
                  <input type="password" value={edit.credential} autoComplete="new-password"
                    onChange={(ev) => setEdit({ ...edit, credential: ev.target.value })}
                    placeholder={edit.id ? t('toolbox.pwKeep') : ''}
                    className="w-full rounded bg-ink-800 px-2 py-1 font-mono text-[12px] text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" />
                </label>
              )}
              <p className="text-[11px] text-slate-500">
                {edit.engine !== 'redis' && edit.cred_policy === 'stored' ? t('toolbox.storedHint') : t('toolbox.askHint')}
              </p>
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
