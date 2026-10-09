import { ReactNode, useCallback, useEffect, useRef, useState } from 'react'
import { errText, api, ApiError, Connection, DeployKeyDeployment, DeployKeyInfo, Host, Snippet, withStepup } from '../lib/api'
import { parseTagInput, snippetTags, targetsPayload } from '../lib/snippets'
import SnippetTags from './SnippetTags'
import { copyText } from '../lib/clipboard'
import { useConfirm } from '../lib/confirm'
import { useI18n } from '../lib/i18n'
import { SHEET_CLS } from '../lib/sheet'
import { useDrawer } from '../lib/useDrawer'
import SheetBar from './SheetBar'
import { useFocusTrap } from '../lib/useFocusTrap'
import { CheckIcon, CloseIcon, CopyIcon, PencilIcon, PlusIcon, TerminalPromptIcon, TrashIcon } from './Icons'
import HelpTip from './HelpTip'
import LoadFailed from './LoadFailed'
import { fmtTs, getTimezone, uiLocale } from '../lib/tz'
import { Button } from './ui'

// Bibliotecă de reţete built-in (client-side): comenzi comune pe categorii, cu {placeholder}-e.
// Acţiunea e Copy (universal — merge şi din pagina hostului, şi din sesiune); lipeşti în terminal.
// Etichetele trec prin catalog (en/ro) — înainte erau literale româneşti şi la userii EN.
type Tr = (k: string, v?: Record<string, string | number>) => string
const library = (t: Tr): { cat: string; items: { label: string; cmd: string }[] }[] => [
  { cat: 'git', items: [
    { label: t('toolbox.lib.gitStatus'), cmd: 'git status' },
    { label: t('toolbox.lib.gitLog'), cmd: 'git log --oneline --graph --decorate -20' },
    { label: t('toolbox.lib.gitPull'), cmd: 'git pull --rebase' },
    { label: t('toolbox.lib.gitBranch'), cmd: 'git checkout -b {branch}' },
    { label: t('toolbox.lib.gitStash'), cmd: 'git stash' },
  ] },
  { cat: 'docker', items: [
    { label: t('toolbox.lib.dockerPs'), cmd: 'docker ps -a' },
    { label: t('toolbox.lib.dockerLogs'), cmd: 'docker logs -f {container}' },
    { label: t('toolbox.lib.dockerShell'), cmd: 'docker exec -it {container} sh' },
    { label: t('toolbox.lib.dockerUp'), cmd: 'docker compose up -d' },
    { label: t('toolbox.lib.dockerPrune'), cmd: 'docker system prune -f' },
  ] },
  { cat: 'systemd', items: [
    { label: t('toolbox.lib.sdStatus'), cmd: 'systemctl status {service}' },
    { label: t('toolbox.lib.sdRestart'), cmd: 'systemctl restart {service}' },
    { label: t('toolbox.lib.sdJournal'), cmd: 'journalctl -u {service} -f' },
    { label: t('toolbox.lib.sdFailed'), cmd: 'systemctl --failed --no-legend --no-pager' },
    { label: t('toolbox.lib.sdTimers'), cmd: 'systemctl list-timers --all --no-pager' },
  ] },
  { cat: 'system', items: [
    { label: t('toolbox.lib.sysDisk'), cmd: 'df -h' },
    { label: t('toolbox.lib.sysDirSizes'), cmd: 'du -sh * | sort -h' },
    { label: t('toolbox.lib.sysMemory'), cmd: 'free -h' },
    { label: t('toolbox.lib.sysPorts'), cmd: 'ss -tulnp' },
  ] },
  { cat: 'db', items: [
    { label: t('toolbox.lib.dbPgDump'), cmd: 'pg_dump -U {user} {db} > {db}.sql' },
    { label: t('toolbox.lib.dbMysqlDump'), cmd: 'mysqldump -u {user} -p {db} > {db}.sql' },
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
  { id: 'influxdb', label: 'InfluxDB 1.x', color: '#4bc8d4', port: 8086 },
  { id: 'influxdb2', label: 'InfluxDB 2.x', color: '#9d8cf0', port: 8086 },
]
const engOf = (e: string) => ENGINES.find((x) => x.id === e)
// engine-uri FĂRĂ prompt de parolă: injecţia `stored` n-are unde să intre → rămân pe `ask`,
// iar formularul ascunde selectorul. (influx 2.x NU mai e aici: lansatorul lui emite propriul
// prompt de token, deci ask/stored merg ca la orice parolă — token-ul nu trece prin argv/ps.)
const noStored = (e: string) => e === 'redis'

type Draft = { id?: number; label: string; engine: Connection['engine']; target_host: string
  target_port: string; username: string; dbname: string; cred_policy: 'ask' | 'stored'; credential: string }
// rezultat per ţintă al deploy-batch / rotate (serverul le întoarce de la început — UI-ul le arunca)
type DkResult = { target_host_id: number; target_name?: string; ok: boolean; code?: string; error?: string; old_removed?: boolean }
type DkLeft = { target_host_id: number; target_name: string }

// Formularele de conexiune / snippet ca dialoguri REALE: focus-trap, Escape, rol + titlu legat.
// Erau div-uri peste panou — Tab ieşea în pagina de sub ele, Escape nu le închidea (audit a11y).
function TrapDialog(props: { onClose: () => void; labelledBy: string; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null)
  useFocusTrap(ref, props.onClose)
  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4" onClick={props.onClose}>
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby={props.labelledBy}
        className="glass w-full max-w-sm rounded-2xl p-5" onClick={(ev) => ev.stopPropagation()}>
        {props.children}
      </div>
    </div>
  )
}

export default function ToolboxPanel(props: {
  host: Host; onClose: () => void; overlay?: boolean; embed?: boolean
  /** deschide o sesiune care rulează CLI-ul conexiunii */
  onOpen: (host: Host, connId: number) => void
}) {
  const { t } = useI18n()
  const { confirm } = useConfirm()
  const asideRef = useRef<HTMLElement>(null)
  const drawer = useDrawer(asideRef, props.onClose, !props.embed)
  const [rows, setRows] = useState<Connection[] | null>(null)
  const [error, setError] = useState('')
  const [edit, setEdit] = useState<Draft | null>(null)   // modalul de creare/editare
  const [tab, setTab] = useState<'connections' | 'sshkeys' | 'library' | 'history'>('connections')
  const [q, setQ] = useState('')                          // filtru pt. Library/History
  const [hist, setHist] = useState<Hist[] | null>(null)   // istoricul de comenzi al hostului
  // eşecul de încărcare e o stare a lui, NU lista goală (altfel „n-ai nimic" minte)
  const [histErr, setHistErr] = useState<string | null>(null)
  const [connErr, setConnErr] = useState<string | null>(null)
  const copy = (cmd: string) => { copyText(cmd) }         // copyText afişează toast-ul standard

  // ── SSH keys (chei de deploy host→host): privata trăieşte pe hostul sursă; aici doar
  //    materialul public + graful sursă→ţintă, cu revoke per-muchie. Vezi audit v54 (H-1..H-4).
  const [dk, setDk] = useState<DeployKeyInfo | null>(null)
  const [dkFailed, setDkFailed] = useState(false)         // fetch eşuat ≠ „nicio cheie"
  const [dkHosts, setDkHosts] = useState<Host[]>([])      // ţinte posibile (hosturi de agent)
  const [dkBusy, setDkBusy] = useState('')
  const [deployTo, setDeployTo] = useState<Set<number>>(new Set())   // multi-ţintă
  const [fromIp, setFromIp] = useState('')
  // restricţia cheii deployate: shell complet | restrict (no-pty/-forwarding) | restrict+command forţat
  const [restrictMode, setRestrictMode] = useState<'none' | 'restrict' | 'command'>('none')
  const [restrictCmd, setRestrictCmd] = useState('')
  const [testResult, setTestResult] = useState<{ ok: boolean; detail: string; dest: string } | null>(null)
  // rezultatele ultimului deploy/rotate, per ţintă — rămân pe ecran până le închizi (eşecurile
  // nu mai dispar în tăcere sub un `loadDk()` verde); „retry failed" reia DOAR ţintele picate
  const [dkResults, setDkResults] = useState<{ kind: 'deploy' | 'rotate'; items: DkResult[]; leftOld: DkLeft[] } | null>(null)

  const loadDk = useCallback(async () => {
    try {
      const [info, hosts] = await Promise.all([
        api<DeployKeyInfo>(`/api/hosts/${props.host.id}/deploy-key`),
        api<Host[]>('/api/hosts'),
      ])
      setDk(info); setDkFailed(false)
      setDkHosts(hosts.filter((h) => (h.connection_type ?? 'agent') === 'agent' && h.id !== props.host.id))
    } catch (e) {
      // fetch eşuat NU e „nicio cheie": nu falsifica starea goală (ar oferi Generate peste o
      // cheie care poate există) — arată eroarea + Reîncearcă, păstrând orice dk anterior
      setError(errText(e, t)); setDkFailed(true)
    }
  }, [props.host.id, t])
  useEffect(() => { if (tab === 'sshkeys' && dk === null) loadDk() }, [tab, dk, loadDk])

  // garda anti-pivot (409 sshkey.pivot) cere un DA explicit → dialog propriu + retry cu confirmed
  const pivotOk = () => confirm({ title: t('toolbox.ssh.pivotTitle'), message: t('toolbox.ssh.pivotConfirm'), danger: true })
  async function dkRun(busy: string, fn: (confirmed: boolean) => Promise<unknown>) {
    setDkBusy(busy); setError('')
    try { await fn(false) } catch (e) {
      if (e instanceof ApiError && e.code === 'sshkey.pivot') {
        if (await pivotOk()) {
          try { await fn(true) } catch (e2) { setError(errText(e2, t)) }
        }
      } else { setError(errText(e, t)) }
    }
    setDkBusy(''); await loadDk()
  }
  const dkGenerate = () => dkRun('generate', (confirmed) =>
    api(`/api/hosts/${props.host.id}/deploy-key/generate`, { method: 'POST', body: JSON.stringify({ confirmed }) }))
  // deploy multi-ţintă: UN factor pe sursă (ruta = sursa), rezultat per ţintă. Batch-ul NU aruncă
  // la o ţintă picată — pivot-ul (409) vine tot ca rezultat per ţintă, deci îl confirmăm aici
  // şi reluăm doar ţintele în cauză, cu `confirmed`.
  const deployBody = (ids: number[], confirmed: boolean) => JSON.stringify({
    target_host_ids: ids, from_ip: fromIp.trim(), confirmed,
    restrict: restrictMode !== 'none', command: restrictMode === 'command' ? restrictCmd.trim() : '' })
  const dkDeployTo = (ids: number[]) => dkRun('deploy', async () => {
    const url = `/api/hosts/${props.host.id}/deploy-key/deploy-batch`
    let items = (await api<{ results: DkResult[] }>(url, { method: 'POST', body: deployBody(ids, false) })).results
    const pivots = items.filter((x) => !x.ok && x.code === 'sshkey.pivot').map((x) => x.target_host_id)
    if (pivots.length && await pivotOk()) {
      const again = (await api<{ results: DkResult[] }>(url, { method: 'POST', body: deployBody(pivots, true) })).results
      const byId = new Map(again.map((x) => [x.target_host_id, x]))
      items = items.map((x) => byId.get(x.target_host_id) ?? x)
    }
    setDkResults({ kind: 'deploy', items, leftOld: [] })
    setDeployTo(new Set())
  })
  const dkDeploy = () => dkDeployTo([...deployTo])
  const dkName = (id: number, fallback?: string) => fallback
    || dkHosts.find((h) => h.id === id)?.name
    || dk?.deployments.find((d) => d.target_host_id === id)?.target_name || `#${id}`
  // codul de eroare tradus (err.sshkey.*), altfel textul serverului
  const dkErr = (r: DkResult) => {
    if (r.code) { const k = 'err.' + r.code; const s = t(k); if (s !== k) return s }
    return r.error || t('toolbox.error')
  }
  const dkVerify = (d: DeployKeyDeployment) => dkRun('verify' + d.id, () =>
    api(`/api/hosts/${d.target_host_id}/deploy-key/verify`, { method: 'POST', body: JSON.stringify({ key_host_id: props.host.id }) }))
  const dkRevoke = async (d: DeployKeyDeployment) => {
    if (!(await confirm({ title: `${t('toolbox.ssh.revoke')} — ${d.target_name}`,
      message: t('toolbox.ssh.confirmRevoke', { target: d.target_name }), confirmLabel: t('toolbox.ssh.revoke'), danger: true }))) return
    dkRun('revoke' + d.id, () =>
      api(`/api/hosts/${d.target_host_id}/deploy-key/revoke`, { method: 'POST', body: JSON.stringify({ key_host_id: props.host.id }) }))
  }
  const dkTest = (d: DeployKeyDeployment) => dkRun('test' + d.id, async () => {
    setTestResult(null)
    const r = await api<{ ok: boolean; detail: string; dest: string }>(
      `/api/hosts/${props.host.id}/deploy-key/test`, { method: 'POST', body: JSON.stringify({ target_host_id: d.target_host_id }) })
    setTestResult(r)
  })
  const dkSshConfig = (d: DeployKeyDeployment) => dkRun('cfg' + d.id, () =>
    api(`/api/hosts/${props.host.id}/deploy-key/ssh-config`, { method: 'POST', body: JSON.stringify({ target_host_id: d.target_host_id }) }))
  // rotire: serverul redeployează ÎNTÂI pe fiecare ţintă şi abia apoi schimbă cheia sursei; ce a
  // rămas pe cheia veche (ţinte offline) vine în `left_with_old_key` — îl arătăm, nu-l pierdem
  const dkRotate = async () => {
    if (!(await confirm({ title: t('toolbox.ssh.rotate'), message: t('toolbox.ssh.confirmRotate'),
      confirmLabel: t('toolbox.ssh.rotate'), danger: true }))) return
    dkRun('rotate', async () => {
      const r = await api<{ results: DkResult[]; left_with_old_key?: DkLeft[] }>(
        `/api/hosts/${props.host.id}/deploy-key/rotate`, { method: 'POST', body: JSON.stringify({}) })
      setDkResults({ kind: 'rotate', items: r.results ?? [], leftOld: r.left_with_old_key ?? [] })
    })
  }
  const dkDelete = async () => {
    if (!(await confirm({ title: t('toolbox.ssh.deleteKey'), message: t('toolbox.ssh.confirmDeleteKey'),
      confirmLabel: t('toolbox.delete'), danger: true }))) return
    dkRun('delete', () => api(`/api/hosts/${props.host.id}/deploy-key`, { method: 'DELETE' }))
  }
  const DK_STATUS: Record<DeployKeyDeployment['status'], string> = {
    deployed: 'bg-emerald-500', edited: 'bg-amber-400', missing: 'bg-rose-500', revoked: 'bg-slate-600',
  }

  const loadHist = useCallback(async () => {
    try {
      const r = await api<Hist[]>(`/api/history?host_id=${props.host.id}&limit=200`)
      setHistErr(null); setHist(r)
    } catch (e) { setHistErr(errText(e, t)); setHist([]) }
  }, [props.host.id, t])
  useEffect(() => { if (tab === 'history' && hist === null) loadHist() }, [tab, hist, loadHist])

  // Comenzi proprii în Library: NU un store nou — refolosim snippet-urile existente
  // (/api/snippets, aceleaşi pe care le vezi în palette/sidebar). „Adaugă" = creează un snippet.
  const [snips, setSnips] = useState<Snippet[] | null>(null)
  // `tags` = ţintele pentru consola de flotă, ca text liber („prod, web"); gol = fără ţinte
  const [snipEdit, setSnipEdit] = useState<{ id?: number; title: string; body: string; tags: string } | null>(null)
  const loadSnips = useCallback(async () => {
    try { setSnips(await api<Snippet[]>('/api/snippets')) } catch { setSnips([]) }
  }, [])
  useEffect(() => { if (tab === 'library' && snips === null) loadSnips() }, [tab, snips, loadSnips])
  async function saveSnip(d: { id?: number; title: string; body: string; tags: string }) {
    try {
      await api(`/api/snippets${d.id ? '/' + d.id : ''}`, { method: d.id ? 'PATCH' : 'POST',
        body: JSON.stringify({ title: d.title, body: d.body, targets: targetsPayload(parseTagInput(d.tags)) }) })
      setSnipEdit(null); await loadSnips()
    } catch (e) { setError(errText(e, t)) }
  }
  async function delSnip(s: Snippet) {
    if (!(await confirm({ title: `${t('toolbox.delete')} — ${s.title}`, message: t('toolbox.lib.confirmDelete', { title: s.title }),
      confirmLabel: t('toolbox.delete'), danger: true }))) return
    try { await api(`/api/snippets/${s.id}`, { method: 'DELETE' }); await loadSnips() }
    catch (e) { setError(errText(e, t)) }
  }
  // data+ora comenzii din history (created e epoch în secunde)
  // pe fusul ales în Setări (lib/tz), nu pe al browserului — ca restul UI-ului
  const fmtShort = (epoch: number) => {
    try {
      return new Intl.DateTimeFormat(uiLocale(), { timeZone: getTimezone(), month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit' }).format(new Date(epoch * 1000))
    } catch { return fmtTs(epoch) }
  }

  const asideCls = drawer.sheet ? SHEET_CLS : props.embed
    ? 'flex h-full w-full min-h-0 flex-col bg-ink-900'
    : 'fixed inset-y-0 right-0 z-40 flex w-[90vw] max-w-md flex-col border-l border-ink-800 bg-ink-900 shadow-2xl outline-none'
    + (props.overlay ? '' : ' sm:static sm:z-auto sm:w-96 sm:max-w-none sm:shrink-0 sm:shadow-none')
  const scrimCls = props.embed ? 'hidden' : 'fixed inset-0 z-30 bg-black/60' + (props.overlay ? '' : ' sm:hidden')

  const load = useCallback(async () => {
    setError('')
    try {
      // pe host 2FA lista e gardată de step-up (topologie sensibilă: ţinte/useri/DB) — fără
      // `withStepup` panoul arăta doar un 403 sec, fără să deschidă fereastra de passkey
      const r = await withStepup(props.host.id, () =>
        api<{ connections: Connection[] }>(`/api/hosts/${props.host.id}/connections`))
      setConnErr(null); setRows(r.connections)
    } catch (e) {
      // eşecul de încărcare are starea lui (LoadFailed + Reîncearcă) — nu banner + „gol"
      setConnErr(errText(e, t) || (e instanceof ApiError ? e.message : t('toolbox.error'))); setRows([])
    }
  }, [props.host.id, t])
  useEffect(() => { load() }, [load])

  async function save(d: Draft) {
    const body = { label: d.label, engine: d.engine, target_host: d.target_host,
      target_port: d.target_port ? Number(d.target_port) : null,
      username: d.username, dbname: d.dbname,
      cred_policy: noStored(d.engine) ? 'ask' : d.cred_policy,
      // engine-urile fără prompt n-au `stored` → nu trimite parola chiar dacă draftul o poartă dintr-un engine anterior
      credential: (!noStored(d.engine) && d.cred_policy === 'stored') ? d.credential : '' }
    try {
      // pe host-uri 2FA orice mutaţie CRUD cere step-up (backend H1); withStepup rulează ceremonia şi
      // reîncearcă. Pe host-uri fără 2FA e transparent (fn() reuşeşte din prima).
      await withStepup(props.host.id, () => api(`/api/hosts/${props.host.id}/connections${d.id ? '/' + d.id : ''}`,
        { method: d.id ? 'PATCH' : 'POST', body: JSON.stringify(body) }))
      setEdit(null); await load()
    } catch (e) { setError(errText(e, t) || (e instanceof ApiError ? e.message : t('toolbox.error'))) }
  }
  async function del(c: Connection) {
    if (!(await confirm({ title: `${t('toolbox.delete')} — ${c.label}`, message: t('toolbox.confirmDelete', { label: c.label }),
      confirmLabel: t('toolbox.delete'), danger: true }))) return
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
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- Escape pe regiunea drawer-ului (vezi useDrawer): intenţionat pe <aside>, nu pe document */}
      <aside ref={asideRef} className={asideCls} aria-label={t('toolbox.title')} onKeyDown={drawer.onKeyDown}>
        {drawer.sheet && <SheetBar title={t('toolbox.title')} onBack={props.onClose} />}
        <div className="flex items-center gap-1 border-b border-ink-800 px-2 py-1.5">
          {(['connections', 'sshkeys', 'library', 'history'] as const).map((tb) => (
            <button key={tb} onClick={() => setTab(tb)}
              aria-pressed={tab === tb}
              className={`rounded-md px-2 py-1 text-xs font-medium ${tab === tb
                ? 'bg-ink-800 text-slate-100' : 'text-slate-400 hover:bg-ink-800/60'}`}>
              {t('toolbox.tab.' + tb)}
            </button>
          ))}
          {tab === 'connections' && (
            <button onClick={() => setEdit(blank())} className="wt-touch ml-auto shrink-0 rounded-md px-1.5 wt-link hover:bg-ink-800"
              title={t('toolbox.new')} aria-label={t('toolbox.new')}><PlusIcon /></button>
          )}
          {tab === 'library' && (
            <button onClick={() => setSnipEdit({ title: '', body: '', tags: '' })} className="wt-touch ml-auto shrink-0 rounded-md px-1.5 wt-link hover:bg-ink-800"
              title={t('toolbox.lib.add')} aria-label={t('toolbox.lib.add')}><PlusIcon /></button>
          )}
          {!props.embed && (
            <button onClick={props.onClose} aria-label={t('common.close')}
              className={`wt-touch shrink-0 rounded-md px-2 py-1 text-slate-400 hover:bg-ink-800${(tab === 'connections' || tab === 'library') ? '' : ' ml-auto'}`}><CloseIcon size={14} /></button>
          )}
        </div>
        {(tab === 'library' || tab === 'history') && (
          <div className="border-b border-ink-800 px-3 py-1.5">
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('toolbox.filterPh')} aria-label={t('toolbox.filterPh')}
              className="w-full rounded-md bg-ink-800/60 px-2 py-1 text-xs text-slate-300 ring-1 ring-ink-700 focus:ring-sky-500" />
          </div>
        )}
        {error && <div className="border-b border-ink-800 bg-ink-800 px-3 py-1.5 text-2xs wt-danger">{error}</div>}
        <div className="min-h-0 flex-1 overflow-y-auto">

          {/* ── CONNECTIONS (Databases) — grilă de carduri ── */}
          {tab === 'connections' && (rows === null ? (
            <div className="p-4 text-center text-xs text-slate-500">{t('toolbox.loading')}</div>
          ) : connErr !== null ? (
            <LoadFailed message={connErr} onRetry={() => { setRows(null); load() }} />
          ) : rows.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-500">
              <span className="inline-flex items-center gap-2">{t('toolbox.empty')}<HelpTip id="toolbox" /></span><br />
              <button onClick={() => setEdit(blank())} className="mt-2 wt-link">{t('toolbox.newFirst')}</button>
            </div>
          ) : (
            <div className="grid gap-3 p-3" style={{ gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))' }}>
              {rows.map((c) => {
                const e = engOf(c.engine)
                const color = e?.color || '#64748b'
                return (
                  <div key={c.id} className="flex flex-col gap-2 rounded-xl border border-ink-700/70 bg-ink-800/40 p-3">
                    <div className="flex items-start gap-2.5">
                      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-md font-mono text-2xs font-bold"
                        style={{ background: `${color}22`, color }} title={e?.label} aria-hidden="true">
                        {(e?.label || c.engine).slice(0, 2).toLowerCase()}
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-compact font-medium text-slate-200">{c.label}</div>
                        <div className="truncate font-mono text-2xs text-slate-500">
                          {c.username ? c.username + '@' : ''}{c.target_host || 'localhost'}
                          {c.target_port ? ':' + c.target_port : ''}{c.dbname ? '/' + c.dbname : ''}
                        </div>
                        <div className="text-2xs uppercase tracking-wide text-slate-600">
                          {e?.label || c.engine} · {c.cred_policy === 'stored' ? t('toolbox.stored') : t('toolbox.ask')}
                        </div>
                      </div>
                    </div>
                    <div className="mt-auto flex items-center gap-1 border-t border-ink-800/60 pt-2">
                      <button onClick={() => props.onOpen(props.host, c.id)}
                        className="inline-flex items-center gap-1 rounded-md bg-sky-600/15 px-2 py-0.5 text-2xs font-medium wt-accent hover:bg-sky-600/25"
                        title={t('toolbox.open')}><TerminalPromptIcon /> {t('toolbox.open')}</button>
                      <span className="ml-auto flex items-center gap-0.5">
                        <button onClick={() => setEdit(toDraft(c))} className="grid h-6 w-6 place-items-center rounded-md text-slate-500 hover:bg-ink-700 hover:text-slate-200"
                          title={t('toolbox.edit')} aria-label={`${t('toolbox.edit')} ${c.label}`}><PencilIcon /></button>
                        <button onClick={() => del(c)} className="grid h-6 w-6 place-items-center rounded-md text-slate-500 hover:bg-ink-700 hover:text-danger"
                          title={t('toolbox.delete')} aria-label={`${t('toolbox.delete')} ${c.label}`}><TrashIcon /></button>
                      </span>
                    </div>
                  </div>
                )
              })}
            </div>
          ))}

          {/* ── SSH KEYS (chei de deploy host→host) ── */}
          {tab === 'sshkeys' && (dk === null ? (
            dkFailed ? (
              <div className="p-6 text-center text-xs text-slate-500">
                {t('toolbox.error')}<br />
                <button onClick={loadDk} className="mt-2 wt-link">{t('toolbox.reload')}</button>
              </div>
            ) : <div className="p-4 text-center text-xs text-slate-500">{t('toolbox.loading')}</div>
          ) : (
            <div className="space-y-3 p-3 text-xs">
              <p className="rounded-md bg-amber-500/10 px-2 py-1.5 text-2xs leading-snug wt-warn">
                {t('toolbox.ssh.warn')}
              </p>
              {!dk.key ? (
                <div className="text-center">
                  <p className="mb-2 text-xs leading-snug text-slate-400">{t('toolbox.ssh.none')}</p>
                  <Button variant="primary" size="sm" onClick={dkGenerate} disabled={dkBusy !== ''}>
                    {dkBusy === 'generate' ? t('toolbox.ssh.generating') : t('toolbox.ssh.generate')}
                  </Button>
                </div>
              ) : (
                <>
                  <div className="rounded-md border border-ink-800 bg-ink-800/40 p-2">
                    <div className="flex items-center gap-2">
                      <span className="min-w-0 flex-1 truncate font-mono text-2xs text-slate-300"
                        title={dk.key.fingerprint}>{dk.key.fingerprint}</span>
                      <button onClick={() => copy(dk.key!.public_key)}
                        className="shrink-0 rounded-md p-1 text-slate-500 hover:bg-ink-700 hover:text-link"
                        title={t('toolbox.ssh.copyPub')} aria-label={t('toolbox.ssh.copyPub')}><CopyIcon /></button>
                      <button onClick={dkRotate} disabled={dkBusy !== ''}
                        className="shrink-0 rounded-md px-1.5 py-0.5 text-2xs text-slate-400 hover:bg-ink-700 hover:text-warn"
                        title={t('toolbox.ssh.rotateHint')}>{dkBusy === 'rotate' ? t('toolbox.ssh.rotating') : t('toolbox.ssh.rotate')}</button>
                      <button onClick={dkDelete} disabled={dkBusy !== ''}
                        className="shrink-0 rounded-md p-1 text-slate-500 hover:bg-ink-700 hover:text-danger"
                        title={t('toolbox.ssh.deleteKey')} aria-label={t('toolbox.ssh.deleteKey')}><TrashIcon /></button>
                    </div>
                    <div className="mt-0.5 font-mono text-2xs text-slate-500">~/.ssh/webterm_ed25519</div>
                  </div>

                  <div className="rounded-md border border-ink-800 p-2">
                    <div className="mb-1 text-2xs font-medium uppercase tracking-wide text-slate-500">{t('toolbox.ssh.deployTo')}</div>
                    <div className="flex flex-col gap-1.5">
                      <div className="max-h-36 overflow-y-auto rounded-md ring-1 ring-ink-700">
                        {dkHosts.length === 0 ? (
                          <div className="px-2 py-1.5 text-2xs text-slate-500">{t('toolbox.ssh.noTargets')}</div>
                        ) : dkHosts.map((h) => (
                          <label key={h.id} className={`flex items-center gap-2 px-2 py-1 text-xs ${h.online ? 'text-slate-200 hover:bg-ink-800/60' : 'text-slate-600'}`}>
                            <input type="checkbox" disabled={!h.online} checked={deployTo.has(h.id)}
                              onChange={(ev) => setDeployTo((s) => { const n = new Set(s); if (ev.target.checked) n.add(h.id); else n.delete(h.id); return n })} />
                            <span className="min-w-0 flex-1 truncate">{h.name}{h.agent_user ? ` (${h.agent_user})` : ''}</span>
                            {!h.online && <span className="shrink-0 text-2xs">{t('toolbox.ssh.offline')}</span>}
                          </label>
                        ))}
                      </div>
                      <input value={fromIp} onChange={(ev) => setFromIp(ev.target.value)}
                        placeholder={t('toolbox.ssh.fromIpPh')} aria-label={t('toolbox.ssh.fromIp')}
                        className="w-full rounded-md bg-ink-800 px-2 py-1 font-mono text-2xs text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" />
                      <select value={restrictMode} onChange={(ev) => setRestrictMode(ev.target.value as 'none' | 'restrict' | 'command')}
                        aria-label={t('toolbox.ssh.restrict')}
                        className="w-full rounded-md bg-ink-800 px-2 py-1 text-xs text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500">
                        <option value="none">{t('toolbox.ssh.restrictNone')}</option>
                        <option value="restrict">{t('toolbox.ssh.restrictLock')}</option>
                        <option value="command">{t('toolbox.ssh.restrictCmd')}</option>
                      </select>
                      {restrictMode === 'command' && (
                        <input value={restrictCmd} onChange={(ev) => setRestrictCmd(ev.target.value)}
                          placeholder={t('toolbox.ssh.restrictCmdPh')} aria-label={t('toolbox.ssh.restrictCmd')}
                          className="w-full rounded-md bg-ink-800 px-2 py-1 font-mono text-2xs text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" />
                      )}
                      <Button variant="primary" size="sm" onClick={dkDeploy} disabled={deployTo.size === 0 || dkBusy !== '' || (restrictMode === 'command' && !restrictCmd.trim())}>
                        {dkBusy === 'deploy' ? t('toolbox.ssh.deploying')
                          : deployTo.size > 1 ? t('toolbox.ssh.deployN', { n: deployTo.size }) : t('toolbox.ssh.deploy')}
                      </Button>
                    </div>
                    <p className="mt-1 text-2xs leading-snug text-slate-500">{t('toolbox.ssh.fromIpHint')}</p>
                  </div>

                  {/* rezultate per ţintă (deploy / rotate): rămân până le închizi; eşecurile cu codul
                      tradus + „reîncearcă ţintele picate" (pentru rotire: cu opţiunile din formular) */}
                  {dkResults && (dkResults.items.length > 0 || dkResults.leftOld.length > 0) && (() => {
                    const failed = dkResults.items.filter((r) => !r.ok).map((r) => r.target_host_id)
                    return (
                      <div role="status" className="rounded-md border border-ink-700 bg-ink-800/40 p-2">
                        <div className="mb-1 flex items-center gap-2">
                          <span className="text-2xs font-medium uppercase tracking-wide text-slate-500">
                            {t(dkResults.kind === 'rotate' ? 'toolbox.ssh.rotateResults' : 'toolbox.ssh.deployResults')}
                          </span>
                          <button onClick={() => setDkResults(null)} aria-label={t('toolbox.ssh.resultsDismiss')} title={t('toolbox.ssh.resultsDismiss')}
                            className="ml-auto grid h-6 w-6 place-items-center rounded-md text-slate-500 hover:bg-ink-700 hover:text-slate-200"><CloseIcon size={14} /></button>
                        </div>
                        <ul className="space-y-0.5 text-2xs">
                          {dkResults.items.map((r) => (
                            <li key={r.target_host_id} className="flex items-start gap-1.5">
                              <span className={`mt-0.5 shrink-0 ${r.ok ? 'wt-good' : 'wt-danger'}`} aria-hidden="true">{r.ok ? <CheckIcon size={12} /> : <CloseIcon size={12} />}</span>
                              <span className="min-w-0 flex-1 break-words">
                                <span className="text-slate-200">{dkName(r.target_host_id, r.target_name)}</span>
                                {' — '}
                                <span className={r.ok ? 'wt-good' : 'wt-danger'}>{r.ok ? t('toolbox.ssh.resultOk') : dkErr(r)}</span>
                                {r.ok && r.old_removed === false && <span className="wt-warn"> · {t('toolbox.ssh.oldNotRemoved')}</span>}
                              </span>
                            </li>
                          ))}
                        </ul>
                        {dkResults.leftOld.length > 0 && (
                          <p className="mt-1.5 text-2xs leading-snug wt-warn">
                            {t('toolbox.ssh.leftOld', { targets: dkResults.leftOld.map((x) => x.target_name || dkName(x.target_host_id)).join(', ') })}
                          </p>
                        )}
                        {failed.length > 0 && (
                          <div className="mt-1.5 flex flex-wrap items-center gap-2">
                            <button onClick={() => dkDeployTo(failed)} disabled={dkBusy !== ''}
                              className="rounded-md px-2 py-1 text-2xs font-medium text-slate-200 ring-1 ring-ink-600 hover:bg-ink-700 disabled:opacity-40">
                              {t('toolbox.ssh.retryFailed')}
                            </button>
                            {dkResults.kind === 'rotate' && <span className="text-2xs text-slate-500">{t('toolbox.ssh.retryUsesForm')}</span>}
                          </div>
                        )}
                      </div>
                    )
                  })()}

                  <div>
                    <div className="mb-1 text-2xs font-medium uppercase tracking-wide text-slate-500">{t('toolbox.ssh.deployments')}</div>
                    {dk.deployments.length === 0 ? (
                      <p className="text-2xs text-slate-500">{t('toolbox.ssh.noDeployments')}</p>
                    ) : dk.deployments.map((d) => (
                      <div key={d.id} className="group flex items-center gap-2 border-b border-ink-800/60 py-1.5">
                        <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${DK_STATUS[d.status]}`}
                          title={t('toolbox.ssh.status.' + d.status)} aria-hidden="true" />
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-xs text-slate-200">{d.hidden ? t('roles.noAccessHost') : (d.target_name || t('toolbox.ssh.deletedHost'))}</div>
                          <div className="truncate font-mono text-2xs text-slate-500">
                            {d.target_user || '?'}@{d.target_hostname || d.target_name}
                            {d.options ? ' · ' + d.options : ''} · {t('toolbox.ssh.status.' + d.status)}
                          </div>
                        </div>
                        <button onClick={() => copy(`ssh ${d.target_user || 'user'}@${d.target_hostname || d.target_name}`)}
                          className="shrink-0 rounded-md p-1 text-slate-500 hover:bg-ink-700 hover:text-link"
                          title={t('toolbox.ssh.copySsh')} aria-label={t('toolbox.ssh.copySsh')}><CopyIcon /></button>
                        {d.status !== 'revoked' && d.target_name && (
                          <>
                            <button onClick={() => dkTest(d)} disabled={dkBusy !== ''}
                              className="shrink-0 rounded-md px-1.5 py-0.5 text-2xs text-slate-400 hover:bg-ink-700 hover:text-ok"
                              title={t('toolbox.ssh.testHint')}>{dkBusy === 'test' + d.id ? '…' : t('toolbox.ssh.test')}</button>
                            <button onClick={() => dkVerify(d)} disabled={dkBusy !== ''}
                              className="shrink-0 rounded-md px-1.5 py-0.5 text-2xs text-slate-400 hover:bg-ink-700 hover:text-slate-200"
                              title={t('toolbox.ssh.verify')}>{t('toolbox.ssh.verify')}</button>
                            <button onClick={() => dkSshConfig(d)} disabled={dkBusy !== ''}
                              className="shrink-0 rounded-md px-1.5 py-0.5 text-2xs text-slate-400 hover:bg-ink-700 hover:text-link"
                              title={t('toolbox.ssh.aliasHint')}>{dkBusy === 'cfg' + d.id ? '…' : t('toolbox.ssh.alias')}</button>
                            <button onClick={() => dkRevoke(d)} disabled={dkBusy !== ''}
                              className="shrink-0 rounded-md p-1 text-slate-500 hover:bg-ink-700 hover:text-danger"
                              title={t('toolbox.ssh.revoke')} aria-label={t('toolbox.ssh.revoke')}><TrashIcon /></button>
                          </>
                        )}
                      </div>
                    ))}
                    {testResult && (
                      <div role="status" className={`mt-1.5 rounded-md px-2 py-1.5 text-2xs leading-snug ${testResult.ok ? 'bg-emerald-500/10 wt-good' : 'bg-rose-500/10 wt-danger'}`}>
                        <span className="font-medium">{testResult.ok ? t('toolbox.ssh.testOk') : t('toolbox.ssh.testFail')}</span>
                        {' '}<span className="font-mono">{testResult.dest}</span>
                        {testResult.detail ? <div className="mt-0.5 whitespace-pre-wrap break-all font-mono text-2xs text-slate-400">{testResult.detail}</div> : null}
                      </div>
                    )}
                    {dk.deployments.some((d) => d.status !== 'revoked') && (
                      <p className="mt-1.5 text-2xs leading-snug text-slate-500">
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
                  <div className="mb-1 text-2xs font-medium uppercase tracking-wide text-slate-500">{t('toolbox.ssh.inbound')}</div>
                  {dk.inbound.map((k, i) => (
                    <div key={i} className="border-b border-ink-800/60 py-1.5">
                      <div className="text-xs text-slate-200">{k.hidden ? t('roles.noAccessHost') : k.source_name}</div>
                      <div className="truncate font-mono text-2xs text-slate-500" title={k.fingerprint}>{k.fingerprint}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}

          {/* ── LIBRARY (reţete built-in, Copy) ── */}
          {tab === 'library' && (<>
            {/* comenzile TALE (snippets), cu add/edit/delete — un store, nu două */}
            {(() => {
              const mine = (snips || []).filter((s) => !q ||
                s.body.toLowerCase().includes(q.toLowerCase()) || s.title.toLowerCase().includes(q.toLowerCase()))
              if (!mine.length) return null
              return (
                <div>
                  <div className="sticky top-0 bg-ink-900/95 px-3 py-1 font-mono text-2xs uppercase tracking-wide text-slate-500">{t('toolbox.lib.yours')}</div>
                  {mine.map((s) => (
                    <div key={s.id} className="group flex items-center gap-2 border-b border-ink-800/60 px-3 py-1.5 hover:bg-ink-800/50">
                      <button onClick={() => copy(s.body)} className="flex min-w-0 flex-1 items-center gap-2 text-left" title={t('toolbox.copy')}>
                        <span className="w-28 shrink-0 truncate text-xs text-slate-300">{s.title}</span>
                        <code className="min-w-0 flex-1 truncate font-mono text-2xs text-slate-500">{s.body}</code>
                      </button>
                      <SnippetTags tags={snippetTags(s)} />
                      {/* vizibile şi la focus din tastatură, nu doar la hover (altfel Tab trecea prin butoane invizibile) */}
                      <button onClick={() => setSnipEdit({ id: s.id, title: s.title, body: s.body, tags: snippetTags(s).join(', ') })}
                        className="shrink-0 rounded-md p-1 text-slate-500 opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 hover:bg-ink-700 hover:text-slate-200 [@media(hover:none)]:opacity-100"
                        title={t('toolbox.edit')} aria-label={`${t('toolbox.edit')} ${s.title}`}><PencilIcon /></button>
                      <button onClick={() => delSnip(s)}
                        className="shrink-0 rounded-md p-1 text-slate-500 opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 hover:bg-ink-700 hover:text-danger [@media(hover:none)]:opacity-100"
                        title={t('toolbox.delete')} aria-label={`${t('toolbox.delete')} ${s.title}`}><TrashIcon /></button>
                    </div>
                  ))}
                </div>
              )
            })()}
            {library(t).map((grp) => {
            const items = grp.items.filter((it) => !q ||
              it.cmd.toLowerCase().includes(q.toLowerCase()) || it.label.toLowerCase().includes(q.toLowerCase()) ||
              grp.cat.includes(q.toLowerCase()))
            if (!items.length) return null
            return (
              <div key={grp.cat}>
                <div className="sticky top-0 bg-ink-900/95 px-3 py-1 font-mono text-2xs uppercase tracking-wide text-slate-500">{grp.cat}</div>
                {items.map((it) => (
                  <button key={it.cmd} onClick={() => copy(it.cmd)}
                    className="group flex w-full items-center gap-2 border-b border-ink-800/60 px-3 py-1.5 text-left hover:bg-ink-800/50"
                    title={t('toolbox.copy')}>
                    <span className="w-28 shrink-0 truncate text-xs text-slate-300">{it.label}</span>
                    <code className="min-w-0 flex-1 truncate font-mono text-2xs text-slate-500">{it.cmd}</code>
                    <span className="shrink-0 text-slate-600 group-hover:text-link"><CopyIcon /></span>
                  </button>
                ))}
              </div>
            )
          })}
          </>)}

          {/* ── HISTORY (comenzile hostului, din OSC 133; Copy) ── */}
          {tab === 'history' && (hist === null ? (
            <div className="p-4 text-center text-xs text-slate-500">{t('toolbox.loading')}</div>
          ) : histErr !== null ? (
            <LoadFailed message={histErr} onRetry={() => { setHistErr(null); setHist(null) }} />
          ) : (() => {
            const items = hist.filter((h) => !q || h.command.toLowerCase().includes(q.toLowerCase()))
            if (!items.length) return <div className="p-6 text-center text-xs text-slate-500">{t('toolbox.histEmpty')}</div>
            return items.map((h) => (
              <button key={h.id} onClick={() => copy(h.command)}
                className="group flex w-full items-start gap-2 border-b border-ink-800/60 px-3 py-1.5 text-left hover:bg-ink-800/50"
                title={t('toolbox.copy')}>
                <span className={`mt-0.5 h-1.5 w-1.5 shrink-0 rounded-full ${h.exit_code === 0 ? 'bg-emerald-500' : h.exit_code == null ? 'bg-slate-600' : 'bg-rose-500'}`}
                  title={h.exit_code == null ? '' : 'exit ' + h.exit_code} aria-hidden="true" />
                <span className="min-w-0 flex-1">
                  <code className="block break-all font-mono text-xs text-slate-300">{h.command}</code>
                  <span className="font-mono text-2xs text-slate-500" title={fmtTs(h.created)}>{fmtShort(h.created)}</span>
                </span>
                <span className="mt-0.5 shrink-0 text-slate-600 group-hover:text-link"><CopyIcon /></span>
              </button>
            ))
          })())}
        </div>
      </aside>

      {snipEdit && (
        <TrapDialog onClose={() => setSnipEdit(null)} labelledBy="wt-toolbox-snip-title">
            <h2 id="wt-toolbox-snip-title" className="mb-1 text-base font-semibold">{snipEdit.id ? t('toolbox.lib.editTitle') : t('toolbox.lib.newTitle')}</h2>
            <p className="mb-3 text-2xs leading-snug text-slate-500">{t('toolbox.lib.hint')}</p>
            <div className="space-y-2 text-sm">
              <label className="block">
                <span className="mb-0.5 block text-xs text-slate-400">{t('toolbox.lib.fTitle')}</span>
                <input autoFocus value={snipEdit.title} onChange={(ev) => setSnipEdit({ ...snipEdit, title: ev.target.value })}
                  placeholder="restart nginx" className="w-full rounded-md bg-ink-800 px-2 py-1 text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" />
              </label>
              <label className="block">
                <span className="mb-0.5 block text-xs text-slate-400">{t('toolbox.lib.fBody')}</span>
                <textarea value={snipEdit.body} onChange={(ev) => setSnipEdit({ ...snipEdit, body: ev.target.value })}
                  rows={3} placeholder="sudo systemctl restart {{service}}"
                  className="w-full rounded-md bg-ink-800 px-2 py-1 font-mono text-xs text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" />
              </label>
              <label className="block">
                <span className="mb-0.5 block text-xs text-slate-400">{t('snippets.targetsLabel')}</span>
                <input value={snipEdit.tags} onChange={(ev) => setSnipEdit({ ...snipEdit, tags: ev.target.value })}
                  placeholder={t('snippets.targetsPlaceholder')}
                  className="w-full rounded-md bg-ink-800 px-2 py-1 text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" />
                <span className="mt-0.5 block text-2xs leading-snug text-slate-500">{t('snippets.targetsHint')}</span>
              </label>
            </div>
            <div className="mt-4 flex justify-end gap-2 text-sm">
              <button onClick={() => setSnipEdit(null)} className="rounded-md px-3 py-1.5 text-slate-400 hover:bg-ink-800">{t('common.cancel')}</button>
              <Button variant="primary" onClick={() => saveSnip(snipEdit)} disabled={!snipEdit.title.trim() || !snipEdit.body.trim()}>{t('common.save')}</Button>
            </div>
        </TrapDialog>
      )}

      {edit && (
        <TrapDialog onClose={() => setEdit(null)} labelledBy="wt-toolbox-conn-title">
            <h2 id="wt-toolbox-conn-title" className="mb-3 text-base font-semibold">{edit.id ? t('toolbox.editTitle') : t('toolbox.newTitle')}</h2>
            <div className="space-y-2 text-sm">
              <label className="block">
                <span className="mb-0.5 block text-xs text-slate-400">{t('toolbox.fLabel')}</span>
                <input autoFocus value={edit.label} onChange={(ev) => setEdit({ ...edit, label: ev.target.value })}
                  placeholder="prod-postgres" className="w-full rounded-md bg-ink-800 px-2 py-1 text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" />
              </label>
              <label className="block">
                <span className="mb-0.5 block text-xs text-slate-400">{t('toolbox.fEngine')}</span>
                <select value={edit.engine}
                  onChange={(ev) => setEdit({ ...edit, engine: ev.target.value as Connection['engine'] })}
                  className="w-full rounded-md bg-ink-800 px-2 py-1 text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500">
                  {ENGINES.map((e) => <option key={e.id} value={e.id}>{e.label}</option>)}
                </select>
              </label>
              <div className="flex gap-2">
                <label className="block flex-1"><span className="mb-0.5 block text-xs text-slate-400">{t('toolbox.fHost')}</span>
                  <input value={edit.target_host} onChange={(ev) => setEdit({ ...edit, target_host: ev.target.value })}
                    placeholder="localhost" className="w-full rounded-md bg-ink-800 px-2 py-1 font-mono text-xs text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" /></label>
                <label className="block w-24"><span className="mb-0.5 block text-xs text-slate-400">{t('toolbox.fPort')}</span>
                  <input value={edit.target_port} inputMode="numeric" onChange={(ev) => setEdit({ ...edit, target_port: ev.target.value.replace(/\D/g, '') })}
                    placeholder={String(engOf(edit.engine)?.port || '')} className="w-full rounded-md bg-ink-800 px-2 py-1 font-mono text-xs text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" /></label>
              </div>
              {/* influxdb2: user → Org (2.x nu are useri aici, are organizaţii), fără câmp de bază
                  (o alegi cu `use` în shell); secretul e un TOKEN, nu o parolă — etichetăm ca atare */}
              <div className="flex gap-2">
                <label className="block flex-1"><span className="mb-0.5 block text-xs text-slate-400">
                  {t(edit.engine === 'influxdb2' ? 'toolbox.fOrg' : 'toolbox.fUser')}</span>
                  <input value={edit.username} onChange={(ev) => setEdit({ ...edit, username: ev.target.value })}
                    className="w-full rounded-md bg-ink-800 px-2 py-1 font-mono text-xs text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" /></label>
                {edit.engine !== 'influxdb2' && (
                  <label className="block flex-1"><span className="mb-0.5 block text-xs text-slate-400">{t('toolbox.fDb')}</span>
                    <input value={edit.dbname} onChange={(ev) => setEdit({ ...edit, dbname: ev.target.value })}
                      className="w-full rounded-md bg-ink-800 px-2 py-1 font-mono text-xs text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" /></label>
                )}
              </div>
              {!noStored(edit.engine) && (
                <label className="block">
                  <span className="mb-0.5 block text-xs text-slate-400">{t('toolbox.fAuth')}</span>
                  <select value={edit.cred_policy}
                    onChange={(ev) => setEdit({ ...edit, cred_policy: ev.target.value as 'ask' | 'stored' })}
                    className="w-full rounded-md bg-ink-800 px-2 py-1 text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500">
                    <option value="ask">{t('toolbox.authAsk')}</option>
                    <option value="stored">{t('toolbox.authStored')}</option>
                  </select>
                </label>
              )}
              {!noStored(edit.engine) && edit.cred_policy === 'stored' && (
                <label className="block">
                  <span className="mb-0.5 block text-xs text-slate-400">
                    {t(edit.engine === 'influxdb2' ? 'toolbox.fToken' : 'toolbox.fPassword')}</span>
                  <input type="password" value={edit.credential} autoComplete="new-password"
                    onChange={(ev) => setEdit({ ...edit, credential: ev.target.value })}
                    placeholder={edit.id ? t('toolbox.pwKeep') : ''}
                    className="w-full rounded-md bg-ink-800 px-2 py-1 font-mono text-xs text-slate-100 ring-1 ring-ink-700 focus:ring-sky-500" />
                </label>
              )}
              <p className="text-2xs text-slate-500">
                {edit.engine === 'influxdb2' ? t('toolbox.influx2Hint')
                  : !noStored(edit.engine) && edit.cred_policy === 'stored' ? t('toolbox.storedHint') : t('toolbox.askHint')}
              </p>
            </div>
            <div className="mt-4 flex justify-end gap-2 text-sm">
              <button onClick={() => setEdit(null)} className="rounded-md px-3 py-1.5 text-slate-400 hover:bg-ink-800">{t('common.cancel')}</button>
              <Button variant="primary" onClick={() => save(edit)} disabled={!edit.label.trim()}>{t('common.save')}</Button>
            </div>
        </TrapDialog>
      )}
    </>
  )
}
