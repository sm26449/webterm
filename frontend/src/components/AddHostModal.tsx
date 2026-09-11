import { FormEvent, useEffect, useRef, useState } from 'react'
import { errText, api, Host } from '../lib/api'
import { copyText } from '../lib/clipboard'
import { useI18n } from '../lib/i18n'
import InstallCommand from './InstallCommand'
import { useFocusTrap } from '../lib/useFocusTrap'

type ConnType = 'agent' | 'ssh' | 'telnet'

const field =
  'w-full rounded-lg bg-ink-800 px-4 py-2.5 placeholder-slate-500 ring-1 ring-ink-700 focus:ring-sky-600'
const label = 'mb-1 block text-xs font-medium text-slate-400'

// `host` prezent = mod EDITARE. Acelaşi formular: un host se editează cu exact câmpurile cu
// care a fost creat, iar comutarea agent↔SSH e doar o schimbare de tip — util fix atunci când
// agentul nu mai răspunde şi vrei să intri pe SSH ca să-l repari.
export default function AddHostModal(props: { onClose: () => void; host?: Host; onSaved?: () => void }) {
  const { t } = useI18n()
  const edit = props.host
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)
  const [connType, setConnType] = useState<ConnType>((edit?.connection_type as ConnType) || 'agent')
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

  const [created, setCreated] = useState<Host | null>(null)
  const [online, setOnline] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  // Onboarding la scară: „O maşină" (formularul clasic) vs „Mai multe maşini" (token de grup —
  // un one-liner reutilizabil). Creat AICI, unde userul chiar adaugă hosturi; gestiunea (listă +
  // revocare) rămâne în Settings → Security. Doar la CREARE (la editare, un host = un host).
  const [mode, setMode] = useState<'one' | 'many'>('one')
  const [grp, setGrp] = useState({ name: '', days: 30, max_uses: 0, folder: '', require_2fa: false,
    current_password: '' })
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
      setError(errText(err, t) || String(err))
    } finally {
      setBusy(false)
    }
  }

  // host agent: după creare, așteaptă agentul să apară online
  useEffect(() => {
    if (!created || created.connection_type !== 'agent') return
    const t = setInterval(async () => {
      const hosts = await api<Host[]>('/api/hosts').catch(() => [])
      if (hosts.find((h) => h.id === created.id)?.online) setOnline(true)
    }, 2000)
    return () => clearInterval(t)
  }, [created])

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError('')
    const body: Record<string, unknown> = { name, note, tags, connection_type: connType }
    if (!edit) body.require_2fa = require2fa      // la editare, 2FA are endpoint propriu (cere step-up)
    if (connType !== 'agent') {
      Object.assign(body, {
        hostname,
        ssh_port: port,
        ssh_username: username,
        auth_method: authMethod,
        credential_policy: policy,
      })
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
        setCreated(await api<Host>('/api/hosts', { method: 'POST', body: JSON.stringify(body) }))
      }
    } catch (err) {
      setError(errText(err, t) || t('addhost.genericError'))
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
                <button key={m} type="button" onClick={() => setMode(m)}
                  className={`flex-1 rounded-lg px-3 py-1.5 font-medium transition ${
                    mode === m ? 'bg-sky-600 text-white' : 'text-slate-400 hover:text-slate-200'}`}>
                  {m === 'one' ? t('addhost.modeOne') : t('addhost.modeMany')}
                </button>
              ))}
            </div>
            {grpCmd ? (
              <div role="status" aria-live="polite" className="space-y-3">
                <p className="text-sm text-slate-300">{t('addhost.groupCreated')}</p>
                <p className="text-xs text-emerald-300">{t('settings.enrollGroups.copyNow')}</p>
                <InstallCommand command={grpCmd} />
                <p className="text-xs text-slate-500">{t('addhost.groupManageHint')}</p>
                <div className="text-right">
                  <button type="button" onClick={props.onClose}
                    className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-700">
                    {t('addhost.done')}
                  </button>
                </div>
              </div>
            ) : (
              <form onSubmit={submitGroup} className="space-y-3">
                <p className="text-xs text-slate-500">{t('addhost.manyDesc')}</p>
                <label className="block">
                  <span className={label}>{t('settings.enrollGroups.name')}</span>
                  <input autoFocus required placeholder={t('settings.enrollGroups.namePlaceholder')}
                    value={grp.name} onChange={(e) => setGrp({ ...grp, name: e.target.value })} className={field} />
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
                <input type="password" value={grp.current_password} autoComplete="current-password"
                  onChange={(e) => setGrp({ ...grp, current_password: e.target.value })}
                  placeholder={t('settings.currentPasswordConfirm')} aria-label={t('settings.currentPassword')} className={field} />
                {error && <div className="text-sm wt-danger">{error}</div>}
                <div className="flex justify-end gap-2">
                  <button type="button" onClick={props.onClose} className="rounded-lg px-4 py-2 text-sm text-slate-400 hover:bg-ink-800">
                    {t('addhost.cancel')}
                  </button>
                  <button disabled={busy || !grp.name || !grp.current_password}
                    className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50">
                    {t('settings.enrollGroups.create')}
                  </button>
                </div>
              </form>
            )}
          </div>
        ) : !created ? (
          <form onSubmit={submit} className="space-y-4">
            <h2 className="font-semibold">{edit ? t('addhost.editTitle', { name: edit.name }) : t('addhost.title')}</h2>
            {!edit && (
              <div className="flex gap-1 rounded-xl bg-ink-800 p-1 text-sm">
                {(['one', 'many'] as const).map((m) => (
                  <button key={m} type="button" onClick={() => setMode(m)}
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

            {/* tip conexiune */}
            <div className="flex gap-1 rounded-xl bg-ink-800 p-1 text-sm">
              {([['agent', 'Agent'], ['ssh', 'SSH'], ['telnet', 'Telnet']] as [ConnType, string][]).map(([t, label]) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => { setConnType(t); setPort(t === 'telnet' ? 23 : 22) }}
                  className={`flex-1 rounded-lg px-3 py-1.5 font-medium transition ${
                    connType === t ? 'bg-sky-600 text-white' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
            <p className="text-xs text-slate-500">
              {connType === 'agent'
                ? t('addhost.agentDesc')
                : connType === 'ssh'
                ? t('addhost.sshDesc')
                : t('addhost.telnetDesc')}
            </p>

            <label className="block">
              <span className={label}>{t('addhost.name')}</span>
              <input autoFocus required placeholder={t('addhost.namePlaceholder')}
                value={name} onChange={(e) => setName(e.target.value)} className={field} />
            </label>

            {connType !== 'agent' && (
              <div className="space-y-3 rounded-xl border border-ink-700 p-3">
                <div className="flex gap-2">
                  <label className="block min-w-0 flex-1">
                    <span className={label}>Hostname / IP</span>
                    <input required placeholder={t('addhost.hostnamePlaceholder')} value={hostname}
                      onChange={(e) => setHostname(e.target.value)} className={field} />
                  </label>
                  <label className="block w-24 shrink-0">
                    <span className={label}>{t('addHost.port')}</span>
                    <input type="number" min={1} max={65535} value={port} aria-label={t('addHost.port')}
                      onChange={(e) => setPort(Number(e.target.value))} className={field} />
                  </label>
                </div>
                <label className="block">
                  <span className={label}>{t('addhost.user')}{connType === 'ssh' ? '' : t('addhost.optionalSuffix')}</span>
                  <input required={connType === 'ssh'}
                    placeholder={connType === 'ssh' ? t('addhost.userPlaceholderSsh') : t('addhost.userPlaceholderOther')}
                    value={username}
                    onChange={(e) => setUsername(e.target.value)} className={field} />
                </label>

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

            <label className="block">
              <span className={label}>{t('addhost.note')}</span>
              <input placeholder={t('addhost.notePlaceholder')} value={note}
                onChange={(e) => setNote(e.target.value)} className={field} />
            </label>

            <label className="block">
              <span className={label}>{t('addhost.tags')}</span>
              <input placeholder={t('addhost.tagsPlaceholder')} value={tags}
                onChange={(e) => setTags(e.target.value)} className={field} />
            </label>

            {error && <div className="text-sm wt-danger">{error}</div>}
            <div className="flex justify-end gap-2">
              <button type="button" onClick={props.onClose} className="rounded-lg px-4 py-2 text-sm text-slate-400 hover:bg-ink-800">
                {t('addhost.cancel')}
              </button>
              <button disabled={busy} className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50">
                {busy ? (edit ? t('addhost.saving') : t('addhost.adding'))
                  : edit ? t('addhost.save')
                  : connType === 'agent' ? t('addhost.continue') : t('addhost.add')}
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
              <button onClick={props.onClose} className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500">
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
            <InstallCommand command={created.install_command!}
                            commandDedicated={created.install_command_dedicated} />
            {error && <div className="mt-2 text-sm wt-danger">{error}</div>}
            <div className="mt-4 flex items-center justify-between">
              <div className="text-sm">
                {online ? (
                  <span className="wt-good">{t('addhost.agentConnected')}</span>
                ) : (
                  <span className="text-slate-500">
                    <span className="mr-1 inline-block h-2 w-2 animate-pulse rounded-full bg-amber-500" />
                    {t('addhost.waitingAgent')}
                  </span>
                )}
              </div>
              <button onClick={props.onClose}
                className={`rounded-lg px-4 py-2 text-sm font-medium ${
                  online ? 'bg-emerald-600 text-white hover:bg-emerald-500' : 'text-slate-400 hover:bg-ink-800'
                }`}>
                {online ? t('addhost.done') : t('addhost.closeInstallLater')}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
