import { FormEvent, useEffect, useRef, useState } from 'react'
import { api, ApiError, errText } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { fmtTs } from '../../lib/tz'
import { copyText } from '../../lib/clipboard'
import { downloadBlob, field, heading } from './ui'

// Backup & restore: arhivă criptată descărcabilă, backup automat programat, copii stocate pe
// server, copie off-host (OAuth Google Drive/Dropbox sau SFTP/FTPS direct) şi restore din .wtbk.
// Extras din SettingsModal ca tab de sine stătător (îşi ţine starea, se încarcă la montare).
export default function BackupTab(props: { onAccountChanged: () => void }) {
  const { t } = useI18n()

  // ── Backup off-host în cloud (Google Drive / Dropbox), conectat prin OAuth din UI ──
  type CloudProvider = { id: string; label: string; console_url: string; app_type: string }
  type CloudStatus = {
    provider: string; configured: boolean; connected: boolean; has_passphrase: boolean
    account: string; keep: number; include_transcripts: boolean
    last: { ts?: number; ok?: boolean; name?: string; size?: number; error?: string }
    redirect_uri: string; providers: CloudProvider[]
    direct: {
      host: string; port: number; user: string; path: string
      has_key: boolean; has_password: boolean; hostkey: string; has_ca: boolean
    }
  }
  const [cloud, setCloud] = useState<CloudStatus | null>(null)
  // Parola CONTULUI, cerută de operaţiile care scot secrete din instanţă sau o pot prelua.
  // Distinctă de parola de criptare a arhivei: pe aceea o alege cel care descarcă, deci
  // nu dovedeşte nimic. Vezi _require_reauth_for_secret în gateway.
  const [bkReauth, setBkReauth] = useState('')
  const [cloudForm, setCloudForm] = useState({
    provider: 'gdrive', client_id: '', client_secret: '', passphrase: '',
    keep: 14, include_transcripts: false, current_password: '',
  })
  const [cloudMsg, setCloudMsg] = useState('')
  const [cloudErr, setCloudErr] = useState('')
  const [cloudBusy, setCloudBusy] = useState(false)
  const [cloudHelp, setCloudHelp] = useState(false)
  const [copied, setCopied] = useState(false)
  // ── Destinaţie DIRECTĂ (SFTP/FTPS), scrisă din UI — vezi backup_dest.py ──
  // Secretele (cheie SSH / parolă / passphrase) se golesc din formular după salvare: serverul nu
  // le mai întoarce. Pentru SFTP, host-key-ul serverului se PINUIEŞTE prin probe (TOFU) înainte
  // de salvare — o cheie schimbată ulterior duce la refuz (anti-MITM).
  const [directForm, setDirectForm] = useState({
    kind: 'sftp', host: '', port: 22, user: '', path: '.',
    auth: 'key' as 'key' | 'password', ssh_key: '', password: '',
    hostkey: '', ca: '', passphrase: '', keep: 14, include_transcripts: false,
    current_password: '',
  })
  const [probeInfo, setProbeInfo] = useState<{ fingerprint: string; type: string; hostkey: string } | null>(null)
  const isDirect = cloudForm.provider === 'sftp' || cloudForm.provider === 'ftps'

  const loadCloud = () =>
    api<CloudStatus>('/api/backup/cloud').then((s) => {
      setCloud(s)
      setCloudForm((f) => ({
        ...f, provider: s.provider || f.provider, keep: s.keep || f.keep,
        include_transcripts: s.include_transcripts,
      }))
      // prefill destinaţie directă din stare (fără secrete: doar host/port/user/cale + host-key/CA
      // deja pinuite şi flagurile has_key/has_password care spun ce metodă de auth e configurată)
      if (s.direct && (s.provider === 'sftp' || s.provider === 'ftps')) {
        setDirectForm((f) => ({
          ...f, kind: s.provider, host: s.direct.host || f.host,
          port: s.direct.port || f.port, user: s.direct.user || f.user,
          path: s.direct.path || f.path, hostkey: s.direct.hostkey || f.hostkey,
          auth: s.direct.has_password ? 'password' : 'key',
          keep: s.keep || f.keep, include_transcripts: s.include_transcripts,
        }))
      }
    }).catch(() => {})

  // SFTP TOFU: testează conexiunea şi întoarce amprenta host-key-ului de confirmat vizual.
  async function probeHost() {
    setCloudErr(''); setCloudMsg(''); setCloudBusy(true)
    try {
      const info = await api<{ fingerprint: string; type: string; hostkey: string }>(
        '/api/backup/cloud/probe',
        { method: 'POST', body: JSON.stringify({
          host: directForm.host, port: directForm.port, user: directForm.user,
          ssh_key: directForm.auth === 'key' ? directForm.ssh_key : '',
          password: directForm.auth === 'password' ? directForm.password : '',
          current_password: directForm.current_password,
        }) })
      setProbeInfo(info)
      setDirectForm((f) => ({ ...f, hostkey: info.hostkey }))
      setCloudMsg(t('settings.direct.probeOk'))
    } catch (e) {
      setCloudErr(errText(e, t) || String(e))
    }
    setCloudBusy(false)
  }

  async function saveDirect(e: FormEvent) {
    e.preventDefault()
    setCloudErr(''); setCloudMsg(''); setCloudBusy(true)
    try {
      const s = await api<CloudStatus>('/api/backup/cloud/direct',
        { method: 'POST', body: JSON.stringify({
          kind: directForm.kind, host: directForm.host, port: directForm.port,
          user: directForm.user, path: directForm.path,
          ssh_key: directForm.auth === 'key' ? directForm.ssh_key : '',
          password: directForm.auth === 'password' ? directForm.password : '',
          hostkey: directForm.hostkey, ca: directForm.ca,
          passphrase: directForm.passphrase, keep: directForm.keep,
          include_transcripts: directForm.include_transcripts,
          current_password: directForm.current_password,
        }) })
      setCloud(s)
      // secretele nu se mai întorc de la server: le golim din formular după salvare
      setDirectForm((f) => ({ ...f, ssh_key: '', password: '', passphrase: '', current_password: '' }))
      setProbeInfo(null)
      setCloudMsg(t('settings.cloud.saved'))
    } catch (e) {
      setCloudErr(errText(e, t) || String(e))
    }
    setCloudBusy(false)
  }

  async function saveCloud(e: FormEvent) {
    e.preventDefault()
    setCloudErr(''); setCloudMsg(''); setCloudBusy(true)
    try {
      const s = await api<CloudStatus>('/api/backup/cloud/config',
        { method: 'POST', body: JSON.stringify(cloudForm) })
      setCloud(s)
      // secretele nu se mai întorc de la server: le golim din formular după salvare
      setCloudForm((f) => ({ ...f, client_secret: '', passphrase: '', current_password: '' }))
      setCloudMsg(t('settings.cloud.saved'))
    } catch (e) {
      setCloudErr(errText(e, t) || String(e))
    }
    setCloudBusy(false)
  }

  async function connectCloud() {
    setCloudErr(''); setCloudMsg('')
    try {
      const { url } = await api<{ url: string }>('/api/backup/cloud/authorize')
      // filă nouă: consimțământul e la provider, iar Setările rămân deschise dedesubt
      window.open(url, '_blank', 'noopener')
      setCloudMsg(t('settings.cloud.authOpened'))
    } catch (e) {
      setCloudErr(errText(e, t) || String(e))
    }
  }

  async function cloudAction(path: string, okMsg: string) {
    setCloudErr(''); setCloudMsg(''); setCloudBusy(true)
    try {
      await api(`/api/backup/cloud/${path}`, { method: 'POST' })
      await loadCloud()
      setCloudMsg(okMsg)
    } catch (e) {
      setCloudErr(errText(e, t) || String(e))
    }
    setCloudBusy(false)
  }

  const copyRedirect = () => {
    if (!cloud) return
    copyText(cloud.redirect_uri).then((ok) => {
      if (!ok) return
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }

  // ── Backup / restore ──
  type StoredBackup = { name: string; size: number; created: number }
  type BackupStatus = {
    schedule: 'off' | 'daily' | 'weekly'
    include_transcripts: boolean
    last_scheduled: number
    backups: StoredBackup[]
    retention_days: number
  }
  const [bkStatus, setBkStatus] = useState<BackupStatus | null>(null)
  const [bkPass, setBkPass] = useState('')
  const [bkPass2, setBkPass2] = useState('')
  const [bkTx, setBkTx] = useState(false)
  const [bkMsg, setBkMsg] = useState('')
  const [bkErr, setBkErr] = useState('')
  const [bkBusy, setBkBusy] = useState(false)
  const restoreRef = useRef<HTMLInputElement>(null)
  const [restoreFile, setRestoreFile] = useState<File | null>(null)
  const [restorePass, setRestorePass] = useState('')

  const loadBackup = () =>
    api<BackupStatus>('/api/backup/status').then(setBkStatus).catch(() => {})

  async function downloadBackupNow() {
    setBkMsg(''); setBkErr('')
    if (bkPass.length < 8) { setBkErr(t('settings.backup.encPassMin8')); return }
    if (bkPass !== bkPass2) { setBkErr(t('settings.passMismatch')); return }
    setBkBusy(true)
    try {
      await downloadBlob('/api/backup/download',
        { passphrase: bkPass, include_transcripts: bkTx, current_password: bkReauth },
        'webterm-backup.wtbk')
      setBkMsg(t('settings.backup.downloaded'))
      setBkPass(''); setBkPass2(''); setBkReauth('')
    } catch (e) {
      setBkErr(errText(e, t) || t('settings.backup.failed'))
    } finally { setBkBusy(false) }
  }

  async function downloadStored(name: string) {
    setBkMsg(''); setBkErr('')
    const pass = prompt(t('settings.backup.encPassPrompt'))
    if (pass === null) return
    if (pass.length < 8) { setBkErr(t('settings.passMin8')); return }
    setBkBusy(true)
    try {
      const acct = prompt(t('settings.reauthPrompt'))
      if (acct === null) { setBkBusy(false); return }
      await downloadBlob(`/api/backup/stored/${encodeURIComponent(name)}/download`,
        { passphrase: pass, current_password: acct }, name + '.wtbk')
      setBkMsg(t('settings.backup.downloadedStored'))
      await markBackupSeen()
    } catch (e) {
      setBkErr(errText(e, t) || t('settings.downloadFailed'))
    } finally { setBkBusy(false) }
  }

  async function deleteStored(name: string) {
    if (!confirm(t('settings.backup.deleteConfirm', { name }))) return
    setBkErr('')
    try {
      await api(`/api/backup/stored/${encodeURIComponent(name)}`, { method: 'DELETE' })
      await loadBackup()
    } catch (e) { setBkErr(errText(e, t) || t('settings.deleteFailed')) }
  }

  async function markBackupSeen() {
    try { await api('/api/backup/seen', { method: 'POST' }); props.onAccountChanged() } catch { /* best-effort */ }
  }

  async function saveSchedule(schedule: 'off' | 'daily' | 'weekly') {
    setBkErr(''); setBkMsg('')
    try {
      const s = await api<BackupStatus>('/api/backup/schedule', {
        method: 'POST', body: JSON.stringify({ schedule, include_transcripts: bkStatus?.include_transcripts ?? false }),
      })
      setBkStatus(s)
      setBkMsg(schedule === 'off'
        ? t('settings.backup.autoOff')
        : t('settings.backup.autoOn', { freq: schedule === 'daily' ? t('settings.backup.freqDaily') : t('settings.backup.freqWeekly') }))
    } catch (e) { setBkErr(errText(e, t) || t('settings.error')) }
  }

  async function toggleScheduleTx(include: boolean) {
    if (!bkStatus) return
    try {
      const s = await api<BackupStatus>('/api/backup/schedule', {
        method: 'POST', body: JSON.stringify({ schedule: bkStatus.schedule, include_transcripts: include }),
      })
      setBkStatus(s)
    } catch { /* ignore */ }
  }

  async function doRestore() {
    setBkErr(''); setBkMsg('')
    if (!restoreFile) { setBkErr(t('settings.backup.chooseFile')); return }
    if (restorePass.length < 8) { setBkErr(t('settings.backup.enterRestorePass')); return }
    if (!confirm(t('settings.backup.restoreConfirm'))) return
    setBkBusy(true)
    try {
      const res = await fetch('/api/backup/restore', {
        method: 'POST', credentials: 'same-origin',
        // percent-encoded: parola poate avea unicode, iar headerele HTTP sunt latin-1
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Restore-Pass': encodeURIComponent(restorePass),
          'X-Reauth-Pass': encodeURIComponent(bkReauth),
        },
        body: restoreFile,
      })
      if (!res.ok) {
        let detail = res.statusText
        try { detail = (await res.json()).detail ?? detail } catch { /* non-JSON */ }
        throw new ApiError(res.status, detail)
      }
      setBkMsg(t('settings.backup.restoreValidated'))
      setRestoreFile(null); setRestorePass('')
    } catch (e) {
      setBkErr(errText(e, t) || t('settings.backup.restoreFailed'))
    } finally { setBkBusy(false) }
  }

  // vizitarea secţiunii Backup „vede" notificarea (punctul de pe rotiţa Setări) → o stinge la
  // montarea tab-ului, nu doar la descărcare (altfel rămânea aprinsă dacă ştergeai fără să descarci)
  useEffect(() => {
    loadBackup()
    markBackupSeen()
    loadCloud()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div>
      {/* ── Descarcă un backup acum ── */}
      <h3 className={heading + ' !mt-0'}>{t('settings.backup.downloadTitle')}</h3>
      <p className="mt-1 text-xs text-slate-500">
        {t('settings.backup.downloadHintA')} <span className="text-slate-300">{t('settings.backup.encryptedWithPass')}</span> {t('settings.backup.downloadHintB')} <span className="text-slate-300">{t('settings.backup.dontLoseIt')}</span>{t('settings.backup.downloadHintC')}
      </p>
      <div className="mt-2 flex flex-col gap-2">
        <input type="password" value={bkPass} onChange={(e) => setBkPass(e.target.value)}
          placeholder={t('settings.backup.encPassPlaceholder')} aria-label={t('settings.backup.encPass')}
          autoComplete="new-password" className={field} />
        <input type="password" value={bkPass2} onChange={(e) => setBkPass2(e.target.value)}
          placeholder={t('settings.backup.confirmPass')} aria-label={t('settings.backup.confirmPass')} autoComplete="new-password" className={field} />
        <input type="password" value={bkReauth} onChange={(e) => setBkReauth(e.target.value)}
          placeholder={t('settings.reauthPlaceholder')} aria-label={t('settings.reauthLabel')}
          autoComplete="current-password" className={field} />
        <label className="flex items-center gap-2 text-sm text-slate-400">
          <input type="checkbox" checked={bkTx} onChange={(e) => setBkTx(e.target.checked)}
            className="h-4 w-4 rounded accent-sky-600" />
          {t('settings.backup.includeTranscripts')}
        </label>
        <div className="flex items-center gap-2">
          <button disabled={bkBusy} onClick={downloadBackupNow}
            className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50">
            {bkBusy ? t('settings.backup.preparing') : t('settings.downloadEncryptedBackup')}
          </button>
          {bkMsg && <span className="text-sm wt-good">{bkMsg}</span>}
          {bkErr && <span className="text-sm wt-danger">{bkErr}</span>}
        </div>
      </div>

      {/* ── Backup automat ── */}
      <h3 className={heading}>{t('settings.backup.autoTitle')}</h3>
      <p className="mt-1 text-xs text-slate-500">
        {t('settings.backup.autoHintA')}{bkStatus ? ' ' + t('settings.backup.autoHintRetention', { days: bkStatus.retention_days }) : ''}{t('settings.backup.autoHintB')}
      </p>
      <div className="mt-2 flex gap-2">
        {([['off', t('settings.backup.off')], ['daily', t('settings.backup.daily')], ['weekly', t('settings.backup.weekly')]] as const).map(([val, label]) => (
          <button key={val} onClick={() => saveSchedule(val)}
            className={`rounded-lg px-3 py-1.5 text-sm ring-1 ${
              (bkStatus?.schedule ?? 'off') === val
                ? 'bg-sky-600 text-white ring-sky-600'
                : 'bg-ink-800 text-slate-300 ring-ink-700 hover:bg-ink-700'
            }`}>
            {label}
          </button>
        ))}
      </div>
      {bkStatus && bkStatus.schedule !== 'off' && (
        <label className="mt-2 flex items-center gap-2 text-sm text-slate-400">
          <input type="checkbox" checked={bkStatus.include_transcripts}
            onChange={(e) => toggleScheduleTx(e.target.checked)} className="h-4 w-4 rounded accent-sky-600" />
          {t('settings.backup.includeTranscriptsAuto')}
        </label>
      )}

      {/* backup-uri stocate pe server */}
      {bkStatus && bkStatus.backups.length > 0 && (
        <div className="mt-3 space-y-1">
          <div className="text-xs text-slate-500">{t('settings.backup.storedLabel', { days: bkStatus.retention_days })}</div>
          {bkStatus.backups.map((b) => (
            <div key={b.name} className="flex items-center justify-between gap-2 rounded-lg bg-ink-800 px-3 py-2 text-sm">
              <span className="min-w-0 flex-1 truncate font-mono text-xs text-slate-300" title={b.name}>
                {b.name}
                <span className="ml-2 text-slate-500">{(b.size / 1024).toFixed(0)} KB</span>
              </span>
              <button onClick={() => downloadStored(b.name)} className="shrink-0 text-xs wt-link hover:underline">{t('settings.download')}</button>
              <button onClick={() => deleteStored(b.name)} className="shrink-0 text-xs wt-danger hover:underline">{t('settings.delete')}</button>
            </div>
          ))}
        </div>
      )}

      {/* ── Copie off-host în cloud (Google Drive / Dropbox) ── */}
      <h3 className={heading}>{t('settings.cloud.title')}</h3>
      <p className="mt-1 text-xs text-slate-500">{t('settings.cloud.hint')}</p>

      {/* stare curentă: prima linie pe care o citește omul când deschide secțiunea */}
      <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
        <span className={`rounded-full px-2 py-0.5 ring-1 ${
          cloud?.connected ? 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30'
            : cloud?.configured ? 'bg-amber-500/10 text-amber-300 ring-amber-500/30'
              : 'bg-ink-800 text-slate-400 ring-ink-700'}`}>
          {cloud?.connected ? t('settings.cloud.connectedAs', { account: cloud.account || '—' })
            : cloud?.configured ? t('settings.cloud.notConnected')
              : t('settings.cloud.notConfigured')}
        </span>
        {cloud?.last?.ts ? (
          <span className={cloud.last.ok ? 'text-slate-500' : 'wt-danger'}>
            {cloud.last.ok
              ? t('settings.cloud.lastOk', {
                when: fmtTs(cloud.last.ts),
                name: cloud.last.name || '',
              })
              : t('settings.cloud.lastFailed', {
                when: fmtTs(cloud.last.ts),
                error: cloud.last.error || '',
              })}
          </span>
        ) : null}
      </div>

      {/* pasul 1: alegerea destinaţiei — OAuth (Drive/Dropbox) sau server propriu (SFTP/FTPS).
          instrucțiunile stau lângă câmpuri, nu în documentație, ca să nu ceară alt tab */}
      <div className="mt-3 flex flex-wrap gap-2">
        {(cloud?.providers ?? []).map((p) => (
          <button key={p.id} type="button"
            onClick={() => setCloudForm((f) => ({ ...f, provider: p.id }))}
            className={`wt-touch rounded-lg px-3 py-1.5 text-sm ${
              cloudForm.provider === p.id ? 'bg-sky-600 text-white' : 'bg-ink-800 text-slate-300 hover:bg-ink-700'}`}
          >{p.label}</button>
        ))}
        {[{ id: 'sftp', label: 'SFTP' }, { id: 'ftps', label: 'FTPS' }].map((p) => (
          <button key={p.id} type="button"
            onClick={() => { setCloudForm((f) => ({ ...f, provider: p.id })); setDirectForm((f) => ({ ...f, kind: p.id, port: p.id === 'sftp' ? 22 : 21 })) }}
            className={`wt-touch rounded-lg px-3 py-1.5 text-sm ${
              cloudForm.provider === p.id ? 'bg-sky-600 text-white' : 'bg-ink-800 text-slate-300 hover:bg-ink-700'}`}
          >{p.label}</button>
        ))}
        {!isDirect && (
          <button type="button" onClick={() => setCloudHelp(!cloudHelp)}
            className="text-xs wt-link hover:underline">
            {cloudHelp ? t('settings.cloud.hideSteps') : t('settings.cloud.showSteps')}
          </button>
        )}
      </div>

      {!isDirect && cloudHelp && (() => {
        const p = (cloud?.providers ?? []).find((x) => x.id === cloudForm.provider)
        return (
          <ol className="mt-2 flex list-decimal flex-col gap-1 rounded-lg bg-ink-800/60 p-3 pl-7 text-xs text-slate-400 ring-1 ring-ink-700">
            <li>
              {t('settings.cloud.step1')}{' '}
              <a href={p?.console_url} target="_blank" rel="noreferrer" className="wt-link hover:underline">
                {p?.console_url}
              </a>
            </li>
            <li>{t('settings.cloud.step2')} <span className="font-mono text-slate-300">{p?.app_type}</span></li>
            <li>
              {t('settings.cloud.step3')}
              <div className="mt-1 flex items-center gap-2">
                <code className="min-w-0 flex-1 truncate rounded bg-ink-900 px-2 py-1 text-[11px] text-slate-300">
                  {cloud?.redirect_uri}
                </code>
                <button type="button" onClick={copyRedirect} className="shrink-0 text-xs wt-link hover:underline">
                  {copied ? t('settings.cloud.copied') : t('settings.cloud.copy')}
                </button>
              </div>
            </li>
            <li>{t('settings.cloud.step4')}</li>
            <li>{t('settings.cloud.step5')}</li>
          </ol>
        )
      })()}

      {/* pasul 2 (OAuth): credențialele aplicației + parola de criptare */}
      {!isDirect && (
      <form onSubmit={saveCloud} className="mt-3 flex flex-col gap-2">
        <input value={cloudForm.client_id} spellCheck={false} autoComplete="off"
          onChange={(e) => setCloudForm((f) => ({ ...f, client_id: e.target.value }))}
          placeholder={t('settings.cloud.clientId')} aria-label={t('settings.cloud.clientId')} className={field} />
        <input type="password" value={cloudForm.client_secret} autoComplete="new-password"
          onChange={(e) => setCloudForm((f) => ({ ...f, client_secret: e.target.value }))}
          placeholder={cloud?.configured ? t('settings.cloud.clientSecretKeep') : t('settings.cloud.clientSecret')}
          aria-label={t('settings.cloud.clientSecret')} className={field} />
        <input type="password" value={cloudForm.passphrase} autoComplete="new-password"
          onChange={(e) => setCloudForm((f) => ({ ...f, passphrase: e.target.value }))}
          placeholder={t('settings.cloud.passphrase')} aria-label={t('settings.cloud.passphrase')} className={field} />
        <p className="text-xs text-slate-500">{t('settings.cloud.passphraseHint')}</p>
        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 text-sm text-slate-400">
            {t('settings.cloud.keep')}
            <input type="number" min={1} max={365} value={cloudForm.keep}
              onChange={(e) => setCloudForm((f) => ({ ...f, keep: Number(e.target.value) }))}
              aria-label={t('settings.cloud.keep')}
              className={field + ' w-20'} />
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-400">
            <input type="checkbox" checked={cloudForm.include_transcripts}
              onChange={(e) => setCloudForm((f) => ({ ...f, include_transcripts: e.target.checked }))}
              className="h-4 w-4 rounded accent-sky-600" />
            {t('settings.backup.includeTranscripts')}
          </label>
        </div>
        {/* re-auth: configurarea deschide un canal permanent prin care pleacă backup-uri */}
        <input type="password" value={cloudForm.current_password} autoComplete="current-password"
          onChange={(e) => setCloudForm((f) => ({ ...f, current_password: e.target.value }))}
          placeholder={t('settings.cloud.accountPassword')} aria-label={t('settings.cloud.accountPassword')} className={field} />
        <div className="flex flex-wrap items-center gap-2">
          <button type="submit" disabled={cloudBusy}
            className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50">
            {t('settings.cloud.save')}
          </button>
          <button type="button" onClick={connectCloud} disabled={!cloud?.configured || cloudBusy}
            className="rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-200 ring-1 ring-ink-700 hover:bg-ink-700 disabled:opacity-40">
            {cloud?.connected ? t('settings.cloud.reconnect') : t('settings.cloud.connect')}
          </button>
          <button type="button" disabled={!cloud?.connected || cloudBusy}
            onClick={() => cloudAction('upload', t('settings.cloud.uploaded'))}
            className="rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-200 ring-1 ring-ink-700 hover:bg-ink-700 disabled:opacity-40">
            {t('settings.cloud.uploadNow')}
          </button>
          {cloud?.connected && (
            <button type="button" disabled={cloudBusy}
              onClick={() => cloudAction('disconnect', t('settings.cloud.disconnected'))}
              className="text-xs wt-danger hover:underline">
              {t('settings.cloud.disconnect')}
            </button>
          )}
          <button type="button" onClick={loadCloud} className="text-xs wt-link hover:underline">
            {t('settings.cloud.refresh')}
          </button>
        </div>
        {cloudMsg && <span className="text-sm wt-good">{cloudMsg}</span>}
        {cloudErr && <span className="text-sm wt-danger">{cloudErr}</span>}
      </form>
      )}

      {/* pasul 2 (server propriu): SFTP/FTPS scris din UI. Arhiva pleacă DEJA criptată; aici
          configurăm doar unde şi cum ne conectăm, cu credenţialele criptate în seif. */}
      {isDirect && (
      <form onSubmit={saveDirect} data-testid="direct-backup-form" className="mt-3 flex flex-col gap-2">
        <p className="text-xs text-slate-500">
          {directForm.kind === 'sftp' ? t('settings.direct.sftpHint') : t('settings.direct.ftpsHint')}
        </p>
        <div className="flex gap-2">
          <input value={directForm.host} spellCheck={false} autoComplete="off"
            onChange={(e) => setDirectForm((f) => ({ ...f, host: e.target.value }))}
            placeholder={t('settings.direct.host')} aria-label={t('settings.direct.host')}
            className={field + ' flex-1'} />
          <input type="number" min={1} max={65535} value={directForm.port}
            onChange={(e) => setDirectForm((f) => ({ ...f, port: Number(e.target.value) }))}
            placeholder={t('settings.direct.port')} aria-label={t('settings.direct.port')}
            className={field + ' w-24'} />
        </div>
        <input value={directForm.user} spellCheck={false} autoComplete="off"
          onChange={(e) => setDirectForm((f) => ({ ...f, user: e.target.value }))}
          placeholder={t('settings.direct.user')} aria-label={t('settings.direct.user')} className={field} />
        <input value={directForm.path} spellCheck={false} autoComplete="off"
          onChange={(e) => setDirectForm((f) => ({ ...f, path: e.target.value }))}
          placeholder={t('settings.direct.path')} aria-label={t('settings.direct.path')} className={field} />

        {/* metoda de auth: cheie SSH (doar SFTP) sau parolă */}
        {directForm.kind === 'sftp' && (
          <div className="flex gap-2">
            {(['key', 'password'] as const).map((m) => (
              <button key={m} type="button"
                onClick={() => setDirectForm((f) => ({ ...f, auth: m }))}
                className={`wt-touch rounded-lg px-3 py-1.5 text-sm ${
                  directForm.auth === m ? 'bg-sky-600 text-white' : 'bg-ink-800 text-slate-300 hover:bg-ink-700'}`}
              >{m === 'key' ? t('settings.direct.authKey') : t('settings.direct.authPassword')}</button>
            ))}
          </div>
        )}
        {directForm.kind === 'sftp' && directForm.auth === 'key' ? (
          <textarea value={directForm.ssh_key} spellCheck={false} autoComplete="off" rows={4}
            onChange={(e) => setDirectForm((f) => ({ ...f, ssh_key: e.target.value }))}
            placeholder={cloud?.direct?.has_key ? t('settings.direct.sshKeyKeep') : t('settings.direct.sshKey')}
            aria-label={t('settings.direct.sshKey')} className={field + ' font-mono text-xs'} />
        ) : (
          <input type="password" value={directForm.password} autoComplete="new-password"
            onChange={(e) => setDirectForm((f) => ({ ...f, password: e.target.value }))}
            placeholder={cloud?.direct?.has_password ? t('settings.direct.passwordKeep') : t('settings.direct.password')}
            aria-label={t('settings.direct.password')} className={field} />
        )}

        {/* SFTP: pinuirea host-key-ului (TOFU). Fără amprentă confirmată nu se poate salva. */}
        {directForm.kind === 'sftp' && (
          <div className="rounded-lg bg-ink-800/60 p-3 ring-1 ring-ink-700">
            <div className="flex flex-wrap items-center gap-2">
              <button type="button" onClick={probeHost} disabled={cloudBusy || !directForm.host || !directForm.user}
                className="rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-200 ring-1 ring-ink-700 hover:bg-ink-700 disabled:opacity-40">
                {t('settings.direct.probe')}
              </button>
              {directForm.hostkey
                ? <span className="text-xs wt-good">{t('settings.direct.hostkeyPinned')}</span>
                : <span className="text-xs text-amber-400">{t('settings.direct.hostkeyNeeded')}</span>}
            </div>
            {probeInfo && (
              <p className="mt-2 break-all text-xs text-slate-400">
                {t('settings.direct.confirmFingerprint')}
                <span className="mt-1 block font-mono text-slate-200">{probeInfo.fingerprint}</span>
              </p>
            )}
          </div>
        )}
        {/* FTPS: CA/cert PEM opţional pentru servere self-signed (public, nu e secret) */}
        {directForm.kind === 'ftps' && (
          <textarea value={directForm.ca} spellCheck={false} autoComplete="off" rows={3}
            onChange={(e) => setDirectForm((f) => ({ ...f, ca: e.target.value }))}
            placeholder={cloud?.direct?.has_ca ? t('settings.direct.caKeep') : t('settings.direct.ca')}
            aria-label={t('settings.direct.ca')} className={field + ' font-mono text-xs'} />
        )}

        <input type="password" value={directForm.passphrase} autoComplete="new-password"
          onChange={(e) => setDirectForm((f) => ({ ...f, passphrase: e.target.value }))}
          placeholder={t('settings.cloud.passphrase')} aria-label={t('settings.cloud.passphrase')} className={field} />
        <p className="text-xs text-slate-500">{t('settings.cloud.passphraseHint')}</p>
        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2 text-sm text-slate-400">
            {t('settings.cloud.keep')}
            <input type="number" min={1} max={365} value={directForm.keep}
              onChange={(e) => setDirectForm((f) => ({ ...f, keep: Number(e.target.value) }))}
              aria-label={t('settings.cloud.keep')} className={field + ' w-20'} />
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-400">
            <input type="checkbox" checked={directForm.include_transcripts}
              onChange={(e) => setDirectForm((f) => ({ ...f, include_transcripts: e.target.checked }))}
              className="h-4 w-4 rounded accent-sky-600" />
            {t('settings.backup.includeTranscripts')}
          </label>
        </div>
        {/* re-auth: configurarea deschide un canal permanent prin care pleacă backup-uri */}
        <input type="password" value={directForm.current_password} autoComplete="current-password"
          onChange={(e) => setDirectForm((f) => ({ ...f, current_password: e.target.value }))}
          placeholder={t('settings.cloud.accountPassword')} aria-label={t('settings.cloud.accountPassword')} className={field} />
        <div className="flex flex-wrap items-center gap-2">
          <button type="submit" disabled={cloudBusy || (directForm.kind === 'sftp' && !directForm.hostkey)}
            className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50">
            {t('settings.cloud.save')}
          </button>
          <button type="button" disabled={!cloud?.connected || cloudBusy}
            onClick={() => cloudAction('upload', t('settings.cloud.uploaded'))}
            className="rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-200 ring-1 ring-ink-700 hover:bg-ink-700 disabled:opacity-40">
            {t('settings.cloud.uploadNow')}
          </button>
          {cloud?.connected && isDirect && (
            <button type="button" disabled={cloudBusy}
              onClick={() => cloudAction('disconnect', t('settings.direct.removed'))}
              className="text-xs wt-danger hover:underline">
              {t('settings.direct.remove')}
            </button>
          )}
          <button type="button" onClick={loadCloud} className="text-xs wt-link hover:underline">
            {t('settings.cloud.refresh')}
          </button>
        </div>
        {cloudMsg && <span className="text-sm wt-good">{cloudMsg}</span>}
        {cloudErr && <span className="text-sm wt-danger">{cloudErr}</span>}
      </form>
      )}

      {/* ── Restore ── */}
      <h3 className={heading}>{t('settings.backup.restoreTitle')}</h3>
      <p className="mt-1 text-xs text-slate-500">
        {t('settings.backup.restoreHintA')} <span className="font-mono">.wtbk</span> {t('settings.backup.restoreHintB')}
        <span className="text-amber-400"> {t('settings.backup.restoreRestarts')}</span> {t('settings.backup.restoreHintC')}
      </p>
      <div className="mt-2 flex flex-col gap-2">
        <div className="flex items-center gap-2">
          <button onClick={() => restoreRef.current?.click()}
            className="rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700">
            {t('settings.chooseFile')}
          </button>
          <span className="min-w-0 truncate text-xs text-slate-400">{restoreFile ? restoreFile.name : t('settings.noFileChosen')}</span>
          <input ref={restoreRef} type="file" accept=".wtbk,application/octet-stream" className="hidden"
            onChange={(e) => setRestoreFile(e.target.files?.[0] ?? null)} />
        </div>
        <input type="password" value={restorePass} onChange={(e) => setRestorePass(e.target.value)}
          placeholder={t('settings.backup.restorePassPlaceholder')} aria-label={t('settings.backup.restorePass')}
          autoComplete="off" className={field} />
        <div>
          <button disabled={bkBusy || !restoreFile} onClick={doRestore}
            className="rounded-lg bg-rose-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-rose-700 disabled:opacity-50">
            {bkBusy ? t('settings.backup.validating') : t('settings.backup.restoreAndRestart')}
          </button>
        </div>
      </div>
    </div>
  )
}
