import { FormEvent, useEffect, useRef, useState } from 'react'
import { errText, api, Host } from '../lib/api'
import { copyText } from '../lib/clipboard'
import { useI18n } from '../lib/i18n'
import InstallCommand, { AGENT_PYTHON_MIN } from './InstallCommand'
import { useFocusTrap } from '../lib/useFocusTrap'
import { btn } from './settings/ui'
import { fmtTs } from '../lib/tz'
import CoachTip from './CoachTip'
import { TIP_ADDHOST_AGENT, TIP_ADDHOST_SSH } from '../lib/coachtips'
import { isWalkthroughDone } from '../lib/walkthrough'
import { ServerIcon, KeyIcon } from './Icons'

type ConnType = 'agent' | 'ssh' | 'ssh-jump' | 'telnet' | 'telnet-jump'

const field =
  'w-full rounded-lg bg-ink-800 px-4 py-2.5 placeholder-slate-500 ring-1 ring-[rgb(var(--field-border))] focus:ring-sky-600'
const label = 'mb-1 block text-xs font-medium text-slate-400'

// După cât timp fără agent arătăm panoul de depanare. 45 s = instalarea (descărcare + pip-free
// start) durează de regulă sub 20 s; dacă a trecut dublul, ceva e blocat, nu lent.
const STUCK_AFTER_MS = 45_000
type AgentEvent = { ts: number; event: string; reason: string; detail: string }

// `host` prezent = mod EDITARE. Acelaşi formular: un host se editează cu exact câmpurile cu
// care a fost creat, iar comutarea agent↔SSH e doar o schimbare de tip — util fix atunci când
// agentul nu mai răspunde şi vrei să intri pe SSH ca să-l repari.
export default function AddHostModal(props: {
  onClose: () => void; host?: Host; onSaved?: () => void; tagSuggestions?: string[]
  /** adăugare SSH-jump deja scopată pe un agent (din meniul ⋯ al hostului): tip fixat, via blocat */
  presetJump?: { viaHostId: number; viaName: string }
  /** „Conectează o dată": deschide o sesiune pe ţinta efemeră tocmai creată, fără s-o salvezi în sidebar */
  onConnect?: (host: Host) => void
}) {
  const { t } = useI18n()
  const edit = props.host
  const pj = props.presetJump
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)
  const [connType, setConnType] = useState<ConnType>((edit?.connection_type as ConnType) || (pj ? 'ssh-jump' : 'agent'))
  // un host „jump" (ssh-jump/telnet-jump) e definit de agentul `via` — la editare arătăm doar
  // comutatorul de PROTOCOL (SSH↔Telnet), nu selectorul generic (a-l muta pe „agent" l-ar rupe).
  const isJump = connType === 'ssh-jump' || connType === 'telnet-jump'
  // Sfaturile contextuale (coach tips) nu apar peste walkthrough-ul de primă rulare (fie marcat
  // gata, fie nemontat acum) şi doar la CREARE — la editare hostul e deja configurat, un hint
  // „ce e modul agent" ar fi redundant. Copia variază după tipul ales (agent vs ssh/jump).
  const coachAllowed = !edit && (isWalkthroughDone() || !document.querySelector('[data-testid="walkthrough"]'))
  const [name, setName] = useState(edit?.name ?? '')
  const [note, setNote] = useState(edit?.note ?? '')
  const [tags, setTags] = useState((edit?.tags ?? []).join(', '))
  // câmpuri SSH
  const [hostname, setHostname] = useState(edit?.hostname ?? '')
  const [port, setPort] = useState(edit?.ssh_port ?? 22)
  const [username, setUsername] = useState(edit?.ssh_username ?? '')
  const [authMethod, setAuthMethod] = useState<'password' | 'key'>(
    (edit?.auth_method as 'password' | 'key') || 'password')
  const [secret, setSecret] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [sshPub, setSshPub] = useState('')       // cheia publică generată/derivată, de copiat
  const [sshBusy, setSshBusy] = useState(false)
  const [sshCopied, setSshCopied] = useState(false)
  const [policy, setPolicy] = useState<'stored' | 'ask'>(
    (edit?.credential_policy as 'stored' | 'ask') || 'stored')
  const [require2fa, setRequire2fa] = useState(edit?.require_2fa ?? false)
  // ssh-jump: hostul-agent prin al cărui tunel ajungem la ţintă (lista de agenţi din flotă)
  const [viaHost, setViaHost] = useState<number>(edit?.via_host_id ?? pj?.viaHostId ?? 0)
  const [agentHosts, setAgentHosts] = useState<Host[]>([])
  useEffect(() => {
    api<Host[]>('/api/hosts').then((hs) =>
      setAgentHosts(hs.filter((h) => (h.connection_type ?? 'agent') === 'agent'))).catch(() => {})
  }, [])
  // înrolare (doar agent, la creare): cât e valid link-ul + o parolă temporară opţională
  const [enrollTtl, setEnrollTtl] = useState(3600)
  const [enrollPass, setEnrollPass] = useState('')

  const [created, setCreated] = useState<Host | null>(null)
  const [online, setOnline] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  // La eşec, focusul merge pe primul câmp al formularului, marcat `aria-invalid` + legat de
  // mesaj (WCAG 3.3.1): serverul întoarce o singură eroare, nu una per câmp.
  const firstFieldRef = useRef<HTMLInputElement>(null)
  const invalid = error ? { 'aria-invalid': true as const, 'aria-describedby': 'addhost-error' } : {}
  function fail(msg: string) { setError(msg); firstFieldRef.current?.focus() }

  // Onboarding la scară: „O maşină" (formularul clasic) vs „Mai multe maşini" (token de grup —
  // un one-liner reutilizabil). Creat AICI, unde userul chiar adaugă hosturi; gestiunea (listă +
  // revocare) rămâne în Settings → Security. Doar la CREARE (la editare, un host = un host).
  const [mode, setMode] = useState<'one' | 'many'>('one')
  const [grp, setGrp] = useState({ name: '', days: 30, max_uses: 0, folder: '', require_2fa: false,
    current_password: '', enroll_password: '' })
  const [grpCmd, setGrpCmd] = useState('')

  async function submitGroup(e: FormEvent) {
    e.preventDefault()
    setError(''); setGrpCmd(''); setBusy(true)
    try {
      const r = await api<{ install_command: string }>('/api/enroll-groups',
        { method: 'POST', body: JSON.stringify(grp) })
      setGrpCmd(r.install_command)
      props.onSaved?.()      // reîmprospătează lista din Settings dacă e deschisă
    } catch (err) {
      fail(errText(err, t) || String(err))
    } finally {
      setBusy(false)
    }
  }

  // host agent: după creare, așteaptă agentul să apară online. Se opreşte când a venit —
  // altfel bătea /api/hosts la 2 s până închideai modalul (auditul frontend, B15).
  useEffect(() => {
    if (!created || created.connection_type !== 'agent' || online) return
    const t = setInterval(async () => {
      const hosts = await api<Host[]>('/api/hosts').catch(() => [])
      if (hosts.find((h) => h.id === created.id)?.online) setOnline(true)
    }, 2000)
    return () => clearInterval(t)
  }, [created, online])

  // „Aştept conexiunea agentului…" la nesfârşit era, după auditul de fluxuri (1.1), cea mai
  // frecventă fundătură a primei rulări: punctul galben arăta la fel după 10 s şi după 10 min.
  // După STUCK_AFTER_MS deschidem un panou de depanare (lista de cauze obişnuite) şi citim
  // jurnalul agentului de la gateway — acolo apar încercările REFUZATE (token greşit, conflict
  // de instanţă, pin TLS), pe care hostul „offline" nu le arăta nicăieri.
  const [stuck, setStuck] = useState(false)
  const [events, setEvents] = useState<AgentEvent[] | null>(null)
  useEffect(() => {
    if (!created || created.connection_type !== 'agent' || online) return
    const tm = setTimeout(() => setStuck(true), STUCK_AFTER_MS)
    return () => clearTimeout(tm)
  }, [created, online])
  useEffect(() => {
    if (!stuck || !created || online) return
    let alive = true
    const load = () =>
      api<{ events: AgentEvent[] }>(`/api/hosts/${created.id}/events`)
        .then((r) => { if (alive) setEvents(r.events.slice(0, 6)) })
        // 403 (step-up pe host cu 2FA) sau reţea: panoul rămâne util şi fără jurnal
        .catch(() => { if (alive) setEvents((e) => e ?? []) })
    load()
    const iv = setInterval(load, 10_000)
    return () => { alive = false; clearInterval(iv) }
  }, [stuck, created, online])
  // motivul refuzului, tradus când îl cunoaştem; altfel codul brut (mai bine decât nimic)
  function eventLabel(e: AgentEvent): string {
    const key = `addhost.ev.${e.reason || e.event}`
    const s = t(key)
    if (s !== key) return s
    return e.reason ? `${e.event} · ${e.reason}` : e.event
  }

  async function submit(e: FormEvent, once = false) {
    e.preventDefault()
    setError('')
    const body: Record<string, unknown> = { name, note, tags, connection_type: connType }
    if (once) body.ephemeral = true               // „conectează o dată": ţintă efemeră, nesalvată
    if (!edit) body.require_2fa = require2fa      // la editare, 2FA are endpoint propriu (cere step-up)
    if (connType === 'agent' && !edit) {
      body.enroll_ttl = enrollTtl
      if (enrollPass.trim()) body.enroll_password = enrollPass.trim()
    }
    if (connType !== 'agent') {
      Object.assign(body, {
        hostname,
        ssh_port: port,
        ssh_username: username,
        auth_method: authMethod,
        credential_policy: policy,
      })
      if (connType === 'ssh-jump' || connType === 'telnet-jump') body.via_host_id = viaHost
      // La EDITARE, un câmp gol de parolă înseamnă „las-o pe cea salvată", nu „şterge-o":
      // altfel simpla redenumire a hostului i-ar fi golit credenţialele.
      if (policy === 'ask') {
        if (!edit) Object.assign(body, { credential: '', passphrase: '' })
      } else if (secret || !edit) {
        Object.assign(body, { credential: secret, passphrase })
      }
    }
    setBusy(true)
    try {
      if (edit) {
        await api(`/api/hosts/${edit.id}`, { method: 'PATCH', body: JSON.stringify(body) })
        props.onSaved?.()
        props.onClose()
      } else {
        const h = await api<Host>('/api/hosts', { method: 'POST', body: JSON.stringify(body) })
        if (once) { props.onConnect?.(h); props.onClose() }   // efemer → conectează acum, fără ecranul post-creare
        else if (pj) { props.onSaved?.(); props.onClose() }   // ţintă jump salvată → închide; apare cuibărită sub agent
        else setCreated(h)
      }
    } catch (err) {
      fail(errText(err, t) || t('addhost.genericError'))
    } finally {
      setBusy(false)
    }
  }

  // Helpers de cheie SSH (doar pe hosturi SSH deja create): generează o pereche pe gateway şi
  // arată PUBLICA de pus în authorized_keys, ori derivă publica din cea stocată.
  async function sshKeyAction(path: 'generate' | 'public') {
    if (!edit) return
    setSshBusy(true); setError('')
    try {
      const r = await api<{ public_key: string }>(`/api/hosts/${edit.id}/ssh-key/${path}`,
        { method: 'POST', body: JSON.stringify({}) })
      setSshPub(r.public_key)
      if (path === 'generate') setSecret('')     // privata e acum stocată; golim câmpul
    } catch (err) {
      setError(errText(err, t) || String(err))
    } finally {
      setSshBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-label={edit ? t('addhost.editTitle') : t('addhost.title')}
        className="glass max-h-[90vh] w-full max-w-xl overflow-y-auto rounded-2xl p-6">
        {!created && mode === 'many' && !edit ? (
          <div className="space-y-4">
            <h2 className="font-semibold">{t('addhost.title')}</h2>
            {/* comutator O maşină / Mai multe maşini */}
            <div className="flex gap-1 rounded-xl bg-ink-800 p-1 text-sm">
              {(['one', 'many'] as const).map((m) => (
                <button key={m} type="button" onClick={() => setMode(m)} aria-pressed={mode === m}
                  className={`flex-1 rounded-lg px-3 py-1.5 font-medium transition ${
                    mode === m ? 'bg-sky-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}>
                  {m === 'one' ? t('addhost.modeOne') : t('addhost.modeMany')}
                </button>
              ))}
            </div>
            {grpCmd ? (
              <div role="status" aria-live="polite" className="space-y-3">
                <p className="text-sm text-slate-300">{t('addhost.groupCreated')}</p>
                <p className="text-xs wt-good">{t('settings.enrollGroups.copyNow')}</p>
                <InstallCommand command={grpCmd} />
                <p className="text-xs text-slate-500">{t('addhost.groupManageHint')}</p>
                <div className="text-right">
                  <button type="button" onClick={props.onClose} className={`${btn.primary} px-4 py-2`}>
                    {t('addhost.done')}
                  </button>
                </div>
              </div>
            ) : (
              <form onSubmit={submitGroup} className="space-y-3">
                <p className="text-xs text-slate-500">{t('addhost.manyDesc')}</p>
                <label className="block">
                  <span className={label}>{t('settings.enrollGroups.name')}</span>
                  <input ref={firstFieldRef} autoFocus required placeholder={t('settings.enrollGroups.namePlaceholder')}
                    {...invalid} value={grp.name} onChange={(e) => setGrp({ ...grp, name: e.target.value })} className={field} />
                </label>
                <div className="flex gap-2">
                  <label className="block flex-1">
                    <span className={label}>{t('settings.tokens.days')}</span>
                    <input type="number" min={1} max={365} value={grp.days}
                      onChange={(e) => setGrp({ ...grp, days: Number(e.target.value) })} className={field} />
                  </label>
                  <label className="block flex-1">
                    <span className={label}>{t('settings.enrollGroups.maxUses')}</span>
                    <input type="number" min={0} max={10000} value={grp.max_uses}
                      onChange={(e) => setGrp({ ...grp, max_uses: Number(e.target.value) })} className={field} />
                  </label>
                </div>
                <label className="block">
                  <span className={label}>{t('settings.enrollGroups.folder')}</span>
                  <input value={grp.folder} onChange={(e) => setGrp({ ...grp, folder: e.target.value })} className={field} />
                </label>
                <label className="flex cursor-pointer items-center gap-2.5 text-sm text-slate-300">
                  <input type="checkbox" checked={grp.require_2fa}
                    onChange={(e) => setGrp({ ...grp, require_2fa: e.target.checked })}
                    className="h-4 w-4 rounded accent-sky-600" />
                  {t('settings.enrollGroups.require2fa')}
                </label>
                <label className="block">
                  <span className={label}>{t('addhost.enrollPass')}</span>
                  <input type="text" autoComplete="off" value={grp.enroll_password}
                    onChange={(e) => setGrp({ ...grp, enroll_password: e.target.value })}
                    placeholder={t('addhost.enrollPassPlaceholder')} className={field} />
                  <span className="mt-1 block text-xs text-slate-500">{t('addhost.enrollPassHint')}</span>
                </label>
                <input type="password" value={grp.current_password} autoComplete="current-password"
                  onChange={(e) => setGrp({ ...grp, current_password: e.target.value })}
                  placeholder={t('settings.currentPasswordConfirm')} aria-label={t('settings.currentPassword')} className={field} />
                <div id="addhost-error" role="alert" className={error ? 'text-sm wt-danger' : 'sr-only'}>{error}</div>
                <div className="flex justify-end gap-2">
                  <button type="button" onClick={props.onClose} className={`${btn.ghost} px-4 py-2`}>
                    {t('addhost.cancel')}
                  </button>
                  <button disabled={busy || !grp.name || !grp.current_password} className={`${btn.primary} px-4 py-2`}>
                    {t('settings.enrollGroups.create')}
                  </button>
                </div>
              </form>
            )}
          </div>
        ) : !created ? (
          <form onSubmit={submit} className="space-y-4">
            <h2 className="font-semibold">{edit ? t('addhost.editTitle', { name: edit.name }) : t('addhost.title')}</h2>
            {!edit && !pj && (
              <div className="flex gap-1 rounded-xl bg-ink-800 p-1 text-sm">
                {(['one', 'many'] as const).map((m) => (
                  <button key={m} type="button" onClick={() => setMode(m)} aria-pressed={mode === m}
                    className={`flex-1 rounded-lg px-3 py-1.5 font-medium transition ${
                      mode === m ? 'bg-sky-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}>
                    {m === 'one' ? t('addhost.modeOne') : t('addhost.modeMany')}
                  </button>
                ))}
              </div>
            )}
            {edit && (
              <p className="text-xs text-slate-500">{t('addhost.editHint')}</p>
            )}

            {/* Selectorul de tip. Trei cazuri:
                - host JUMP (preset din meniul agentului, SAU editarea unui ssh-jump/telnet-jump):
                  doar PROTOCOLUL spre ţintă [SSH-jump][Telnet-jump] — via/target rămân;
                - non-jump (creare sau editare agent/ssh/telnet): selectorul generic [Agent][SSH][Telnet].
                Jump-urile se CREEAZĂ din meniul ⋯ al agentului (de-aia lipsesc din selectorul generic). */}
            {(pj || isJump) ? (
              <div className="flex gap-1 rounded-xl bg-ink-800 p-1 text-sm">
                {([['ssh-jump', 'SSH-jump'], ['telnet-jump', 'Telnet-jump']] as [ConnType, string][]).map(([ct, lbl]) => (
                  <button key={ct} type="button" aria-pressed={connType === ct}
                    onClick={() => { setConnType(ct); setPort(ct === 'telnet-jump' ? 23 : 22) }}
                    className={`flex-1 rounded-lg px-2 py-1.5 text-[13px] font-medium transition ${
                      connType === ct ? 'bg-sky-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}>
                    {lbl}
                  </button>
                ))}
              </div>
            ) : (
              <div className="flex gap-1 rounded-xl bg-ink-800 p-1 text-sm">
                {([['agent', 'Agent'], ['ssh', 'SSH'], ['telnet', 'Telnet']] as [ConnType, string][]).map(([ct, label]) => (
                  <button key={ct} type="button" aria-pressed={connType === ct}
                    onClick={() => { setConnType(ct); setPort(ct === 'telnet' ? 23 : 22) }}
                    className={`flex-1 rounded-lg px-2 py-1.5 text-[13px] font-medium transition ${
                      connType === ct ? 'bg-sky-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}>
                    {label}
                  </button>
                ))}
              </div>
            )}
            <p className="text-xs text-slate-500">
              {pj
                ? (connType === 'telnet-jump'
                    ? t('addhost.telnetJumpVia', { name: pj.viaName })
                    : t('addhost.sshJumpVia', { name: pj.viaName }))
                : connType === 'agent'
                ? t('addhost.agentDesc')
                : connType === 'ssh'
                ? t('addhost.sshDesc')
                : connType === 'ssh-jump'
                ? t('addhost.sshJumpDesc')
                : connType === 'telnet-jump'
                ? t('addhost.telnetJumpDesc')
                : t('addhost.telnetDesc')}
            </p>

            {/* Sfat contextual, variat după tip: agent = tot pachetul (sesiuni/fişiere/Docker/
                servicii/forward-uri, instalat cu comanda de mai jos); ssh/jump = sesiuni/fişiere/
                serial + bastion. Non-modal, o singură dată (vezi CoachTip + lib/coachtips). */}
            {coachAllowed && connType === 'agent' && (
              <CoachTip
                tipKey={TIP_ADDHOST_AGENT}
                show
                icon={<ServerIcon />}
                title={t('tips.addhost.agent.title')}
                body={t('tips.addhost.agent.body')}
                className="mt-1"
              />
            )}
            {coachAllowed && connType !== 'agent' && (
              <CoachTip
                tipKey={TIP_ADDHOST_SSH}
                show
                icon={<KeyIcon />}
                title={t('tips.addhost.ssh.title')}
                body={t('tips.addhost.ssh.body')}
                className="mt-1"
              />
            )}

            <label className="block">
              <span className={label}>{t('addhost.name')}</span>
              <input ref={firstFieldRef} autoFocus required placeholder={t('addhost.namePlaceholder')}
                {...invalid} value={name} onChange={(e) => setName(e.target.value)} className={field} />
            </label>

            {connType !== 'agent' && (
              <div className="space-y-3 rounded-xl border border-ink-700 p-3">
                {(connType === 'ssh-jump' || connType === 'telnet-jump') && (
                  <label className="block">
                    <span className={label}>{t('addhost.jumpVia')}</span>
                    <select required value={viaHost || ''} disabled={!!pj} onChange={(e) => setViaHost(Number(e.target.value))}
                      className={`${field} disabled:opacity-60`}>
                      <option value="">{t('addhost.jumpViaPick')}</option>
                      {pj && !agentHosts.some((h) => h.id === pj.viaHostId) && <option value={pj.viaHostId}>{pj.viaName}</option>}
                      {agentHosts.map((h) => <option key={h.id} value={h.id}>{h.name}</option>)}
                    </select>
                    <span className="mt-0.5 block text-[11px] text-slate-500">{t('addhost.jumpViaHint')}</span>
                  </label>
                )}
                <div className="flex gap-2">
                  <label className="block min-w-0 flex-1">
                    <span className={label}>{(connType === 'ssh-jump' || connType === 'telnet-jump') ? t('addhost.jumpTarget') : 'Hostname / IP'}</span>
                    <input required placeholder={t('addhost.hostnamePlaceholder')} value={hostname}
                      onChange={(e) => setHostname(e.target.value)} className={field} />
                  </label>
                  <label className="block w-24 shrink-0">
                    <span className={label}>{t('addHost.port')}</span>
                    <input type="number" min={1} max={65535} value={port} aria-label={t('addHost.port')}
                      onChange={(e) => setPort(Number(e.target.value))} className={field} />
                  </label>
                </div>
                {/* telnet-jump: login INTERACTIV peste tunel (ca bastionul telnet/serial) — fără
                    user/parolă stocate. Deci câmpul de user şi politica de credenţiale lipsesc. */}
                {connType !== 'telnet-jump' && (
                <label className="block">
                  <span className={label}>{t('addhost.user')}{(connType === 'ssh' || connType === 'ssh-jump') ? '' : t('addhost.optionalSuffix')}</span>
                  <input required={connType === 'ssh' || connType === 'ssh-jump'}
                    placeholder={(connType === 'ssh' || connType === 'ssh-jump') ? t('addhost.userPlaceholderSsh') : t('addhost.userPlaceholderOther')}
                    value={username}
                    onChange={(e) => setUsername(e.target.value)} className={field} />
                </label>
                )}

                {connType === 'ssh' && (
                  <div>
                    <span className={label}>{t('addhost.authentication')}</span>
                    <div className="flex gap-2 text-sm">
                      {(['password', 'key'] as const).map((m) => (
                        <label key={m} className={`flex-1 cursor-pointer rounded-lg px-3 py-1.5 text-center ring-1 ${
                          authMethod === m ? 'bg-ink-700 ring-sky-600' : 'ring-ink-700 hover:bg-ink-800'
                        }`}>
                          <input type="radio" name="auth" className="sr-only"
                            checked={authMethod === m} onChange={() => setAuthMethod(m)} />
                          {m === 'password' ? t('addhost.password') : t('addhost.sshKey')}
                        </label>
                      ))}
                    </div>
                  </div>
                )}

                {connType !== 'telnet-jump' && (<>
                {/* politica de stocare a credențialelor */}
                <div>
                  <span className={label}>{t('addhost.credentials')}</span>
                  <div className="flex gap-2 text-sm">
                    {(['stored', 'ask'] as const).map((p) => (
                      <label key={p} className={`flex-1 cursor-pointer rounded-lg px-3 py-1.5 text-center ring-1 ${
                        policy === p ? 'bg-ink-700 ring-sky-600' : 'ring-ink-700 hover:bg-ink-800'
                      }`}>
                        <input type="radio" name="policy" className="sr-only"
                          checked={policy === p} onChange={() => setPolicy(p)} />
                        {p === 'stored' ? t('addhost.credStored') : t('addhost.credAsk')}
                      </label>
                    ))}
                  </div>
                </div>

                {policy === 'stored' && (
                  connType === 'ssh' && authMethod === 'key' ? (
                    <div className="space-y-3">
                      <label className="block">
                        <span className={label}>{t('addhost.privateKey')}</span>
                        <textarea placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                          value={secret} onChange={(e) => setSecret(e.target.value)}
                          rows={4} className={`${field} font-mono text-xs`} />
                      </label>
                      <label className="block">
                        <span className={label}>{t('addhost.passphrase')}</span>
                        <input type="password" placeholder={t('addhost.passphrasePlaceholder')} value={passphrase}
                          onChange={(e) => setPassphrase(e.target.value)} className={field} autoComplete="new-password" />
                      </label>
                      {/* generarea/afişarea cheii necesită un host existent (are nevoie de host_id).
                          La CREARE nu putem genera încă — spunem clar de ce, ca userul fără cheie
                          să nu ajungă în fundătură crezând că trebuie să lipească una. */}
                      {!edit && (
                        <p className="text-xs text-slate-500">{t('addhost.genKeyAfterSave')}</p>
                      )}
                      {edit && (
                        <div className="rounded-lg bg-ink-800/60 p-2 ring-1 ring-ink-700">
                          <div className="flex flex-wrap gap-2">
                            <button type="button" disabled={sshBusy} onClick={() => sshKeyAction('generate')}
                              className="rounded-lg bg-ink-800 px-2.5 py-1 text-xs text-slate-200 ring-1 ring-ink-700 hover:bg-ink-700 disabled:opacity-40">
                              {t('addhost.genKey')}
                            </button>
                            <button type="button" disabled={sshBusy} onClick={() => sshKeyAction('public')}
                              className="rounded-lg bg-ink-800 px-2.5 py-1 text-xs text-slate-200 ring-1 ring-ink-700 hover:bg-ink-700 disabled:opacity-40">
                              {t('addhost.showPubKey')}
                            </button>
                          </div>
                          {sshPub && (
                            <div className="mt-2">
                              <p className="text-[11px] text-slate-500">{t('addhost.pubKeyHint')}</p>
                              <div className="mt-1 flex items-center gap-2">
                                <code className="min-w-0 flex-1 break-all rounded bg-ink-900 px-2 py-1 font-mono text-[11px] text-slate-200">{sshPub}</code>
                                <button type="button" onClick={() => copyText(sshPub).then((okc) => { if (okc) { setSshCopied(true); setTimeout(() => setSshCopied(false), 1500) } })}
                                  className="shrink-0 text-xs wt-link hover:underline">
                                  {sshCopied ? t('settings.cloud.copied') : t('settings.cloud.copy')}
                                </button>
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ) : (
                    <label className="block">
                      <span className={label}>{t('addhost.password')}{connType === 'telnet' ? ' Telnet' : ' SSH'}</span>
                      <input type="password" placeholder="•••••••" value={secret}
                        onChange={(e) => setSecret(e.target.value)} className={field} autoComplete="new-password" />
                    </label>
                  )
                )}
                {policy === 'ask' && (
                  <p className="text-xs text-slate-500">{t('addhost.askNote')}</p>
                )}
                </>)}
              </div>
            )}

            {/* la editare, 2FA rămâne în meniul hostului: dezactivarea ei cere step-up,
                deci nu poate călători într-un PATCH obişnuit */}
            {!edit && (
              <label className="flex cursor-pointer items-center gap-2.5 text-sm text-slate-300">
                <input type="checkbox" checked={require2fa}
                  onChange={(e) => setRequire2fa(e.target.checked)}
                  className="h-4 w-4 rounded accent-sky-600" />
                {t('addhost.require2fa')}
              </label>
            )}

            {/* Înrolare (doar agent, la creare): cât e valid link-ul + o parolă temporară
                opţională. Parola merge ca header la instalare (nu în URL), deci un URL scurs
                într-un log nu ajunge — dă-o pe alt canal decât one-liner-ul. */}
            {connType === 'agent' && !edit && (
              <div className="flex flex-col gap-2 rounded-lg border border-ink-800 p-3">
                <label className="block">
                  <span className={label}>{t('addhost.enrollTtl')}</span>
                  <select value={enrollTtl} onChange={(e) => setEnrollTtl(Number(e.target.value))} className={field}>
                    <option value={900}>{t('addhost.ttl15m')}</option>
                    <option value={3600}>{t('addhost.ttl1h')}</option>
                    <option value={86400}>{t('addhost.ttl24h')}</option>
                    <option value={604800}>{t('addhost.ttl7d')}</option>
                  </select>
                </label>
                <label className="block">
                  <span className={label}>{t('addhost.enrollPass')}</span>
                  <input type="text" autoComplete="off" value={enrollPass}
                    onChange={(e) => setEnrollPass(e.target.value)}
                    placeholder={t('addhost.enrollPassPlaceholder')} className={field} />
                  <span className="mt-1 block text-xs text-slate-500">{t('addhost.enrollPassHint')}</span>
                </label>
              </div>
            )}

            <label className="block">
              <span className={label}>{t('addhost.note')}</span>
              <input placeholder={t('addhost.notePlaceholder')} value={note}
                onChange={(e) => setNote(e.target.value)} className={field} />
            </label>

            <label className="block">
              <span className={label}>{t('addhost.tags')}</span>
              <input placeholder={t('addhost.tagsPlaceholder')} value={tags} list="wt-tag-suggestions"
                onChange={(e) => setTags(e.target.value)} className={field} />
              {(props.tagSuggestions ?? []).length > 0 && (
                <datalist id="wt-tag-suggestions">
                  {(props.tagSuggestions ?? []).map((tg) => <option key={tg} value={tg} />)}
                </datalist>
              )}
            </label>

            <div id="addhost-error" role="alert" className={error ? 'text-sm wt-danger' : 'sr-only'}>{error}</div>
            <div className="flex flex-wrap justify-end gap-2">
              <button type="button" onClick={props.onClose} className={`${btn.ghost} px-4 py-2`}>
                {t('addhost.cancel')}
              </button>
              {/* preset jump: pe lângă „Salvează" (ţintă cuibărită sub agent), oferă „Conectează o
                  dată" — deschide sesiunea pe o ţintă EFEMERĂ, fără s-o lase în sidebar. */}
              {pj && props.onConnect && (
                <button type="button" disabled={busy || !name.trim() || !hostname.trim() || !viaHost}
                  onClick={(e) => submit(e as unknown as FormEvent, true)}
                  className="rounded-lg px-4 py-2 text-sm font-medium text-slate-200 ring-1 ring-ink-600 hover:bg-ink-800 disabled:opacity-50">
                  {t('addhost.connectOnce')}
                </button>
              )}
              <button disabled={busy} className={`${btn.primary} px-4 py-2`}>
                {busy ? (edit ? t('addhost.saving') : t('addhost.adding'))
                  : edit ? t('addhost.save')
                  : connType === 'agent' ? t('addhost.continue')
                  : pj ? t('addhost.saveTarget') : t('addhost.add')}
              </button>
            </div>
          </form>
        ) : created.connection_type !== 'agent' ? (
          <div>
            <h2 className="font-semibold">{t('addhost.hostAddedTitle', { type: created.connection_type?.toUpperCase() ?? '', name: created.name })}</h2>
            <p className="mt-1 text-sm text-slate-500">
              {t('addhost.otherIntro')}{created.connection_type === 'ssh' ? t('addhost.sshFingerprint') : ''}.
              {created.connection_type === 'ssh' ? t('addhost.sshInstallLater') : ''}
            </p>
            <div className="mt-4 flex justify-end">
              <button onClick={props.onClose} className={`${btn.primary} px-4 py-2`}>
                {t('addhost.done')}
              </button>
            </div>
          </div>
        ) : (
          <div>
            <h2 className="font-semibold">{t('addhost.installTitle', { name: created.name })}</h2>
            <p className="mt-1 text-sm text-slate-500">
              {t('addhost.installDesc')}
            </p>
            {/* `?? ''`, nu `!`: un răspuns fără comandă afişa literal „undefined" (audit B27) */}
            <InstallCommand command={created.install_command ?? ''}
                            commandDedicated={created.install_command_dedicated} />
            <div role="alert" className={error ? 'mt-2 text-sm wt-danger' : 'sr-only'}>{error}</div>
            <div className="mt-4 flex items-center justify-between">
              {/* `role="status"`: „agentul s-a conectat" e anunţat, nu doar colorat în verde */}
              <div className="text-sm" role="status">
                {online ? (
                  <span className="wt-good">{t('addhost.agentConnected')}</span>
                ) : (
                  <span className="text-slate-500">
                    <span aria-hidden="true" className="mr-1 inline-block h-2 w-2 animate-pulse rounded-full bg-amber-500" />
                    {t('addhost.waitingAgent')}
                  </span>
                )}
              </div>
              <button onClick={props.onClose} className={`${online ? btn.primary : btn.ghost} px-4 py-2`}>
                {online ? t('addhost.done') : t('addhost.closeInstallLater')}
              </button>
            </div>
            {stuck && !online && (
              <section className="mt-4 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs" aria-labelledby="addhost-stuck-title">
                <h3 id="addhost-stuck-title" className="wt-warn text-sm font-semibold">{t('addhost.stuckTitle')}</h3>
                <p className="mt-1 text-slate-400">{t('addhost.stuckIntro')}</p>
                <ol className="mt-2 list-decimal space-y-1 pl-4 text-slate-300">
                  <li>{t('addhost.stuckFirewall', { gateway: window.location.host })}</li>
                  <li>{t('addhost.stuckToken')}</li>
                  <li>{t('addhost.stuckPython', { min: AGENT_PYTHON_MIN })}</li>
                  <li>{t('addhost.stuckTime')}</li>
                  <li>
                    {t('addhost.stuckLog')}{' '}
                    <code className="select-all rounded bg-ink-900 px-1 font-mono text-[11px] text-slate-200">journalctl --user -u webterm-agent -n 50</code>{' '}
                    · <code className="select-all rounded bg-ink-900 px-1 font-mono text-[11px] text-slate-200">tail -n 30 ~/.webterm/ptyd.log</code>
                  </li>
                </ol>
                {/* ce a văzut gateway-ul: încercări refuzate = cauza, nu simptomul */}
                <h4 className="mt-3 font-semibold text-slate-300">{t('addhost.stuckEvents')}</h4>
                {events && events.length > 0 ? (
                  <ul className="mt-1 space-y-0.5">
                    {events.map((e, i) => (
                      <li key={i} className="flex gap-2">
                        <span className="shrink-0 font-mono tabular-nums text-slate-500">{fmtTs(e.ts)}</span>
                        <span className={/bad_token|conflict|pin_mismatch|refused/.test(e.reason) ? 'wt-danger' : 'text-slate-300'}>
                          {eventLabel(e)}{e.detail ? ` — ${e.detail}` : ''}
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="mt-1 text-slate-500">{events === null ? t('addhost.stuckLoading') : t('addhost.stuckNoEvents')}</p>
                )}
              </section>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
