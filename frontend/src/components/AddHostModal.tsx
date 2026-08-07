import { FormEvent, useEffect, useRef, useState } from 'react'
import { errText, api, Host } from '../lib/api'
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
  // câmpuri SSH
  const [hostname, setHostname] = useState(edit?.hostname ?? '')
  const [port, setPort] = useState(edit?.ssh_port ?? 22)
  const [username, setUsername] = useState(edit?.ssh_username ?? '')
  const [authMethod, setAuthMethod] = useState<'password' | 'key'>(
    (edit?.auth_method as 'password' | 'key') || 'password')
  const [secret, setSecret] = useState('')
  const [passphrase, setPassphrase] = useState('')
  const [policy, setPolicy] = useState<'stored' | 'ask'>(
    (edit?.credential_policy as 'stored' | 'ask') || 'stored')
  const [require2fa, setRequire2fa] = useState(edit?.require_2fa ?? false)

  const [created, setCreated] = useState<Host | null>(null)
  const [online, setOnline] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

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
    const body: Record<string, unknown> = { name, note, connection_type: connType }
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

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-label={edit ? t('addhost.editTitle') : t('addhost.title')}
        className="glass max-h-[90vh] w-full max-w-xl overflow-y-auto rounded-2xl p-6">
        {!created ? (
          <form onSubmit={submit} className="space-y-4">
            <h2 className="font-semibold">{edit ? t('addhost.editTitle', { name: edit.name }) : t('addhost.title')}</h2>
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
                    <span className={label}>Port</span>
                    <input type="number" min={1} max={65535} value={port} aria-label="Port"
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
