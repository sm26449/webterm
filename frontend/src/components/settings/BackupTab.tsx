import { FormEvent, useEffect, useRef, useState } from 'react'
import { api, ApiError, errText } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { useSectionVisible } from '../../lib/perms'
import { fmtTs } from '../../lib/tz'
import { copyText } from '../../lib/clipboard'
import { downloadBlob, field } from './ui'
import { Button, Field, SegmentedControl, SettingsSection, Switch } from '../ui'
import { canSave, type LoadState } from '../../lib/loadable'
import NotLoaded from './NotLoaded'
import { useConfirm } from '../../lib/confirm'
import { askSecret } from '../../lib/secretPrompt'
import HelpTip from '../HelpTip'

// Backup & restore: arhivă criptată descărcabilă, backup automat programat, copii stocate pe
// server, copie off-host (OAuth Google Drive/Dropbox sau SFTP/FTPS direct) şi restore din .wtbk.
// Extras din SettingsModal ca tab de sine stătător (îşi ţine starea, se încarcă la montare).
export default function BackupTab(props: { onAccountChanged: () => void }) {
  const { t } = useI18n()
  const vis = useSectionVisible()   // 3.6: secţiunile fără permisiunea globală nu apar
  const { confirm } = useConfirm()   // nu `window.confirm`: vezi lib/confirm.tsx (temă, focus-trap, nu blochează pagina)

  // ── Backup off-host în cloud (Google Drive / Dropbox), conectat prin OAuth din UI ──
  type CloudProvider = { id: string; label: string; console_url: string; app_type: string }
  type CloudStatus = {
    provider: string; configured: boolean; connected: boolean; has_passphrase: boolean
    account: string; keep: number; include_transcripts: boolean
    last: { ts?: number; ok?: boolean; name?: string; size?: number; error?: string }
    last_ok: number                       // ts al ultimei copii off-host REUŞITE (0 = niciodată)
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
  const [probeInfo, setProbeInfo] = useState<{ fingerprint: string; type: string; hostkey: string; auth_tested?: boolean } | null>(null)
  const isDirect = cloudForm.provider === 'sftp' || cloudForm.provider === 'ftps'

  // U04: o stare necunoscută nu e „neconfigurat" — formularele nu se trimit peste valori implicite
  const [cloudState, setCloudState] = useState<LoadState>({ status: 'loading' })
  const loadCloud = (quiet = true) => {
    if (!quiet) setCloudState({ status: 'loading' })
    return api<CloudStatus>('/api/backup/cloud').then((s) => {
      setCloud(s)
      setCloudState({ status: 'ok' })
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
    }).catch((e) => setCloudState({ status: 'error', error: errText(e, t) }))
  }

  // SFTP: amprenta host-key-ului de confirmat vizual. Pinul aparţine destinaţiei: orice schimbare de
  // tip / host / port îl goleşte (mai jos), ca „pinned" să nu mintă pentru o maşină nouă (lot 3).
  // `trustKey` (lot 3): a doua trecere cu parolă — amprenta a fost văzută şi acceptată; abia acum
  // serverul trimite parola, şi doar unui server care prezintă exact acea cheie
  async function probeHost(trustKey?: string) {
    setCloudErr(''); setCloudMsg(''); setCloudBusy(true)
    try {
      const info = await api<{ fingerprint: string; type: string; hostkey: string; auth_tested?: boolean }>(
        '/api/backup/cloud/probe',
        { method: 'POST', body: JSON.stringify({
          host: directForm.host, port: directForm.port, user: directForm.user,
          ssh_key: directForm.auth === 'key' ? directForm.ssh_key : '',
          password: directForm.auth === 'password' ? directForm.password : '',
          current_password: directForm.current_password,
          trust_hostkey: trustKey ?? '',
        }) })
      setProbeInfo(info)
      setDirectForm((f) => ({ ...f, hostkey: info.hostkey }))
      setCloudMsg(t(info.auth_tested === false ? 'settings.direct.probeKeyOnly' : 'settings.direct.probeOk'))
    } catch (e) {
      setCloudErr(errText(e, t) || String(e))
    }
    setCloudBusy(false)
  }

  async function saveDirect(e: FormEvent) {
    e.preventDefault()
    if (!canSave(cloudState)) { setCloudErr(t('settings.notLoadedNoSave')); return }
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
    if (!canSave(cloudState)) { setCloudErr(t('settings.notLoadedNoSave')); return }
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
    void copyText(cloud.redirect_uri).then((ok) => {
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
    // starea scheduler-ului, persistată de gateway: ultima ÎNCERCARE (reuşită sau nu), ultimul
    // eşec (golit la următorul succes complet) şi următoarea scadenţă — înainte un backup
    // programat care pica zile la rând era complet invizibil aici (audit UX §7.f1)
    last_run: { ts: number; ok: boolean; name: string; error: string } | null
    last_error: { ts: number; error: string; stage?: 'snapshot' | 'cloud' } | null
    next_due: number | null
    backups: StoredBackup[]
    retention_days: number
    /** 3.6.8: când a fost VERIFICAT ultima dată un backup (decriptat, despachetat, integritatea DB-ului) */
    restore_verified_at?: number | null
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
  // 3.7.1 (audit UX Setări #5/Me3): restaurarea stă acum ULTIMA, într-o zonă periculoasă, departe de
  // exportul manual — deci îşi cere parola contului în câmpul ei (aceeaşi cerere: X-Reauth-Pass),
  // în loc să o împrumute tacit din formularul de descărcare de sus.
  const [restoreReauth, setRestoreReauth] = useState('')
  const [restoreBusy, setRestoreBusy] = useState(false)
  // mesajele stau lângă acţiunea care le-a produs (înainte toate apăreau lângă „Download")
  const [schedMsg, setSchedMsg] = useState('')
  const [schedErr, setSchedErr] = useState('')
  const [storedMsg, setStoredMsg] = useState('')
  const [storedErr, setStoredErr] = useState('')
  const [restoreMsg, setRestoreMsg] = useState('')
  const [restoreErr, setRestoreErr] = useState('')

  // U04: fără stare încărcată, „Oprit" evidenţiat era o minciună, iar un clic pe programare
  // trimitea `include_transcripts: false` peste setarea reală
  const [bkState, setBkState] = useState<LoadState>({ status: 'loading' })
  const loadBackup = (quiet = true) => {
    if (!quiet) setBkState({ status: 'loading' })
    return api<BackupStatus>('/api/backup/status')
      .then((s) => { setBkStatus(s); setBkState({ status: 'ok' }) })
      .catch((e) => setBkState({ status: 'error', error: errText(e, t) }))
  }

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
    setStoredMsg(''); setStoredErr('')
    const pass = await askSecret(t('settings.backup.encPassPrompt'))
    if (pass === null) return
    if (pass.length < 8) { setStoredErr(t('settings.passMin8')); return }
    setBkBusy(true)
    try {
      const acct = await askSecret(t('settings.reauthPrompt'))
      if (acct === null) { setBkBusy(false); return }
      await downloadBlob(`/api/backup/stored/${encodeURIComponent(name)}/download`,
        { passphrase: pass, current_password: acct }, name + '.wtbk')
      setStoredMsg(t('settings.backup.downloadedStored'))
      await markBackupSeen()
    } catch (e) {
      setStoredErr(errText(e, t) || t('settings.downloadFailed'))
    } finally { setBkBusy(false) }
  }

  // 3.6.8: un backup care n-a fost niciodată restaurat e o speranţă. „Verifică" îl despachetează şi
  // rulează integrity_check pe DB-ul din el (cu cheia seifului prezentă) — nu restaurează nimic.
  async function verifyStored(name: string) {
    setStoredErr(''); setStoredMsg(''); setBkBusy(true)
    try {
      await api(`/api/backup/stored/${encodeURIComponent(name)}/verify`, { method: 'POST' })
      setStoredMsg(t('settings.backup.verified', { name }))
      await loadBackup()
    } catch (e) {
      setStoredErr(errText(e, t))
    } finally { setBkBusy(false) }
  }

  async function deleteStored(name: string) {
    if (!(await confirm({
      title: t('settings.backup.deleteTitle'),
      message: t('settings.backup.deleteConfirm', { name }),
      confirmLabel: t('settings.backup.deleteAction'), danger: true,
    }))) return
    setStoredErr('')
    try {
      await api(`/api/backup/stored/${encodeURIComponent(name)}`, { method: 'DELETE' })
      await loadBackup()
    } catch (e) { setStoredErr(errText(e, t) || t('settings.deleteFailed')) }
  }

  async function markBackupSeen() {
    try { await api('/api/backup/seen', { method: 'POST' }); props.onAccountChanged() } catch { /* best-effort */ }
  }

  async function saveSchedule(schedule: 'off' | 'daily' | 'weekly') {
    if (!canSave(bkState)) return
    setSchedErr(''); setSchedMsg('')
    try {
      const s = await api<BackupStatus>('/api/backup/schedule', {
        method: 'POST', body: JSON.stringify({ schedule, include_transcripts: bkStatus?.include_transcripts ?? false }),
      })
      setBkStatus(s)
      setSchedMsg(schedule === 'off'
        ? t('settings.backup.autoOff')
        : t('settings.backup.autoOn', { freq: schedule === 'daily' ? t('settings.backup.freqDaily') : t('settings.backup.freqWeekly') }))
    } catch (e) { setSchedErr(errText(e, t) || t('settings.error')) }
  }

  async function toggleScheduleTx(include: boolean) {
    if (!bkStatus || !canSave(bkState)) return
    try {
      const s = await api<BackupStatus>('/api/backup/schedule', {
        method: 'POST', body: JSON.stringify({ schedule: bkStatus.schedule, include_transcripts: include }),
      })
      setBkStatus(s)
    } catch (e) { setSchedErr(errText(e, t) || t('settings.error')) }
  }

  async function doRestore() {
    setRestoreErr(''); setRestoreMsg('')
    if (!restoreFile) { setRestoreErr(t('settings.backup.chooseFile')); return }
    if (restorePass.length < 8) { setRestoreErr(t('settings.backup.enterRestorePass')); return }
    // ce anume restaurezi, în textul de confirmare: numele, mărimea şi data fişierului (din
    // obiectul File — arhiva e criptată, deci fără parolă nu putem citi mai mult de atât)
    if (!(await confirm({
      title: t('settings.backup.restoreTitle'),
      message: restorePreview(restoreFile) + '\n\n' + t('settings.backup.restoreConfirm'),
      confirmLabel: t('settings.backup.restoreAndRestart'), danger: true,
    }))) return
    setRestoreBusy(true)
    try {
      const res = await fetch('/api/backup/restore', {
        method: 'POST', credentials: 'same-origin',
        // percent-encoded: parola poate avea unicode, iar headerele HTTP sunt latin-1
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Restore-Pass': encodeURIComponent(restorePass),
          'X-Reauth-Pass': encodeURIComponent(restoreReauth),
        },
        body: restoreFile,
      })
      if (!res.ok) {
        let detail = res.statusText
        try { detail = (await res.json()).detail ?? detail } catch { /* non-JSON */ }
        throw new ApiError(res.status, detail)
      }
      setRestoreMsg(t('settings.backup.restoreValidated'))
      setRestoreFile(null); setRestorePass(''); setRestoreReauth('')
    } catch (e) {
      setRestoreErr(errText(e, t) || t('settings.backup.restoreFailed'))
    } finally { setRestoreBusy(false) }
  }

  const restorePreview = (f: File) => t('settings.backup.restorePreview', {
    name: f.name, size: (f.size / 1024).toFixed(0), when: fmtTs(Math.floor(f.lastModified / 1000)),
  })

  // vizitarea secţiunii Backup „vede" notificarea (punctul de pe rotiţa Setări) → o stinge la
  // montarea tab-ului, nu doar la descărcare (altfel rămânea aprinsă dacă ştergeai fără să descarci)
  useEffect(() => {
    void loadBackup()
    void markBackupSeen()
    void loadCloud()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // ── 3.7.1 (audit UX Setări #5, §4.4): Backup ca PLAN — întâi starea (program, destinaţie, ultima
  // reuşită, următoarea rulare), apoi programul şi destinaţia, apoi copiile de pe server, exportul
  // manual şi, ultima, restaurarea într-o zonă periculoasă. Cererile şi validările sunt cele de dinainte.
  const schedName = (s: BackupStatus['schedule']) =>
    s === 'daily' ? t('settings.backup.daily') : s === 'weekly' ? t('settings.backup.weekly') : t('settings.backup.off')
  const providerOptions = [
    ...(cloud?.providers ?? []).map((p) => ({ value: p.id, label: p.label })),
    { value: 'sftp', label: 'SFTP' }, { value: 'ftps', label: 'FTPS' },
  ]
  const pickProvider = (id: string) => {
    setCloudForm((f) => ({ ...f, provider: id }))
    if (id === 'sftp' || id === 'ftps') {
      setDirectForm((f) => (f.kind === id ? f : { ...f, kind: id, port: id === 'sftp' ? 22 : 21, hostkey: '' }))
      setProbeInfo(null)
    }
  }
  // de ce e dezactivată o acţiune: lângă ea, legat prin aria-describedby (audit Me4 / #11)
  const cloudWhy = !cloud?.configured ? t('settings.cloud.whyConnect')
    : !cloud.connected ? t('settings.cloud.whyUpload') : ''
  const directWhy = !cloud?.connected ? t('settings.direct.whyUpload') : ''
  const keepHint = t('settings.backup.keepStoredHint')
  const status = (msg: string, err: string, errId?: string) => (
    <>
      <span role="status" className={msg ? 'text-sm wt-good' : 'sr-only'}>{msg}</span>
      <span id={errId} role="alert" className={err ? 'text-sm wt-danger' : 'sr-only'}>{err}</span>
    </>
  )
  const actionRow = (direct: boolean) => (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="primary" type="submit"
          disabled={cloudBusy || (direct && directForm.kind === 'sftp' && !directForm.hostkey)}
          aria-describedby={direct && directForm.kind === 'sftp' && !directForm.hostkey ? 'bk-hostkey-why' : undefined}>
          {t('settings.cloud.save')}
        </Button>
        {!direct && (
          <Button variant="secondary" type="button" onClick={() => { void connectCloud() }}
            disabled={!cloud?.configured || cloudBusy} aria-describedby={!cloud?.configured ? 'bk-cloud-why' : undefined}>
            {cloud?.connected ? t('settings.cloud.reconnect') : t('settings.cloud.connect')}
          </Button>
        )}
        <Button variant="secondary" type="button" disabled={!cloud?.connected || cloudBusy}
          aria-describedby={!cloud?.connected ? (direct ? 'bk-direct-why' : 'bk-cloud-why') : 'bk-upload-hint'}
          onClick={() => { void cloudAction('upload', t('settings.cloud.uploaded')) }}>
          {t('settings.cloud.uploadNow')}
        </Button>
        {cloud?.connected && (
          <Button variant="ghost" size="sm" type="button" className="wt-touch" disabled={cloudBusy}
            onClick={() => { void cloudAction('disconnect', direct ? t('settings.direct.removed') : t('settings.cloud.disconnected')) }}>
            {direct ? t('settings.direct.remove') : t('settings.cloud.disconnect')}
          </Button>
        )}
        <Button variant="ghost" size="sm" type="button" className="wt-touch" onClick={() => { void loadCloud() }}>
          {t('settings.cloud.refresh')}
        </Button>
      </div>
      {(direct ? directWhy : cloudWhy)
        ? <p id={direct ? 'bk-direct-why' : 'bk-cloud-why'} className="text-xs text-slate-500">{direct ? directWhy : cloudWhy}</p>
        : <p id="bk-upload-hint" className="text-xs text-slate-500">{t('settings.cloud.uploadTestHint')}</p>}
      {status(cloudMsg, cloudErr)}
    </>
  )
  const passphraseField = (value: string, set: (v: string) => void) => (
    <Field label={t('settings.cloud.passphrase')} hint={t('settings.cloud.passphraseHint')}>
      <input type="password" value={value} autoComplete="new-password" onChange={(e) => set(e.target.value)} className={field} />
    </Field>
  )
  const keepAndTx = (keep: number, setKeep: (n: number) => void, tx: boolean, setTx: (v: boolean) => void) => (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
      <Field inline label={t('settings.cloud.keep')}>
        <input type="number" min={1} max={365} value={keep} onChange={(e) => setKeep(Number(e.target.value))}
          className={field + ' w-20'} />
      </Field>
      <Switch checked={tx} onChange={setTx} label={t('settings.backup.includeTranscripts')} />
    </div>
  )
  const reauthField = (value: string, set: (v: string) => void, hint: string) => (
    <Field label={t('settings.backup.yourPassword')} hint={hint}>
      <input type="password" value={value} autoComplete="current-password" onChange={(e) => set(e.target.value)} className={field} />
    </Field>
  )

  return (
    <div className="space-y-4">
      <SettingsSection title={t('settings.backup.planTitle')} titleExtra={<HelpTip id="backup" />} description={t('settings.backup.planDesc')}
        instanceWide hidden={!vis('backupAuto') && !vis('backupCloud')}>
        {/* starea planului: primul lucru pe care îl citeşti (audit #5) */}
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 rounded-md bg-ink-800/60 px-3 py-2 text-xs ring-1 ring-ink-700"
          data-testid="backup-sched-status">
          <dt className="text-slate-500">{t('settings.backup.plan.schedule')}</dt>
          <dd className="text-slate-200">{bkStatus ? schedName(bkStatus.schedule) : '—'}</dd>
          <dt className="text-slate-500">{t('settings.backup.plan.destination')}</dt>
          <dd className={cloud?.connected && !cloud.last_ok ? 'wt-warn' : 'text-slate-200'}>
            {cloud?.connected
              ? `${cloud.account || cloud.provider} · ${cloud.last_ok
                ? t('settings.backup.cloudLastGood', { when: fmtTs(cloud.last_ok) })
                : t('settings.backup.cloudNever')}`
              : cloud?.configured ? t('settings.cloud.notConnected') : t('settings.cloud.notConfigured')}
          </dd>
          <dt className="text-slate-500">{t('settings.backup.plan.last')}</dt>
          <dd className={bkStatus?.last_run && !bkStatus.last_run.ok ? 'wt-danger' : 'text-slate-200'}>
            {!bkStatus ? '—' : bkStatus.last_run
              ? (bkStatus.last_run.ok
                ? t('settings.backup.plan.lastOk', { when: fmtTs(bkStatus.last_run.ts), name: bkStatus.last_run.name })
                : t('settings.backup.plan.lastFailed', { when: fmtTs(bkStatus.last_run.ts) }))
              : t('settings.backup.plan.never')}
          </dd>
          <dt className="text-slate-500">{t('settings.backup.plan.next')}</dt>
          <dd className="text-slate-200">
            {!bkStatus ? '—' : bkStatus.schedule === 'off' || bkStatus.next_due == null
              ? t('settings.backup.plan.notScheduled')
              : bkStatus.next_due <= Date.now() / 1000
                ? t('settings.backup.plan.overdue')
                : fmtTs(bkStatus.next_due)}
          </dd>
        </dl>
        {bkStatus?.last_error && (
          <p className="mt-2 break-words text-xs wt-danger" role="alert">
            {t('settings.backup.lastError', { when: fmtTs(bkStatus.last_error.ts), error: bkStatus.last_error.error })}
          </p>
        )}

        {/* 1 · programul: se aplică la alegere (ca orice alegere, audit M6) */}
        <div data-setting-id="backupAuto" hidden={!vis('backupAuto')} className="mt-4 flex flex-col gap-2">
          <h4 id="bk-sched-h" className="text-sm font-medium text-slate-200">{t('settings.backup.autoTitle')}</h4>
          <p className="text-xs text-slate-500">
            {t('settings.backup.autoHintA')}{bkStatus ? ' ' + t('settings.backup.autoHintRetention', { days: bkStatus.retention_days }) : ''}{t('settings.backup.autoHintB')}
          </p>
          <NotLoaded state={bkState} onRetry={() => { void loadBackup(false) }} />
          <div className="flex flex-wrap items-center gap-3">
            <SegmentedControl labelledBy="bk-sched-h" value={bkStatus?.schedule ?? null} disabled={!canSave(bkState)}
              options={(['off', 'daily', 'weekly'] as const).map((v) => ({ value: v, label: schedName(v) }))}
              onChange={(v) => { void saveSchedule(v) }} />
            {status(schedMsg, schedErr)}
          </div>
          {bkStatus && bkStatus.schedule !== 'off' && (
            <Switch checked={bkStatus.include_transcripts} onChange={(v) => { void toggleScheduleTx(v) }}
              label={t('settings.backup.includeTranscriptsAuto')} />
          )}
        </div>

        {/* 2 · destinaţia externă: OAuth (Drive/Dropbox) sau server propriu (SFTP/FTPS). Instrucţiunile
            stau lângă câmpuri, nu în documentaţie, ca să nu ceară alt tab */}
        <div data-setting-id="backupCloud" hidden={!vis('backupCloud')} className="mt-5 flex flex-col gap-2">
          <h4 id="bk-dest-h" className="text-sm font-medium text-slate-200">{t('settings.cloud.title')}</h4>
          <p className="text-xs text-slate-500">{t('settings.cloud.hint')}</p>
          <NotLoaded state={cloudState} onRetry={() => { void loadCloud(false) }} />
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className={`rounded-full px-2 py-0.5 ring-1 ${
              cloud?.connected ? 'wt-good bg-emerald-500/10 ring-emerald-500/30'
                : cloud?.configured ? 'wt-warn bg-amber-500/10 ring-amber-500/30'
                  : 'bg-ink-800 text-slate-400 ring-ink-700'}`}>
              {cloud?.connected ? t('settings.cloud.connectedAs', { account: cloud.account || '—' })
                : cloud?.configured ? t('settings.cloud.notConnected')
                  : t('settings.cloud.notConfigured')}
            </span>
            {cloud?.last?.ts ? (
              <span className={cloud.last.ok ? 'text-slate-500' : 'wt-danger'}>
                {cloud.last.ok
                  ? t('settings.cloud.lastOk', { when: fmtTs(cloud.last.ts), name: cloud.last.name || '' })
                  : t('settings.cloud.lastFailed', { when: fmtTs(cloud.last.ts), error: cloud.last.error || '' })}
              </span>
            ) : null}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <SegmentedControl labelledBy="bk-dest-h" value={cloudForm.provider} options={providerOptions}
              onChange={pickProvider} />
            {!isDirect && (
              <Button variant="ghost" size="sm" type="button" className="wt-touch" aria-expanded={cloudHelp} onClick={() => setCloudHelp(!cloudHelp)}>
                {cloudHelp ? t('settings.cloud.hideSteps') : t('settings.cloud.showSteps')}
              </Button>
            )}
          </div>

          {!isDirect && cloudHelp && (() => {
            const p = (cloud?.providers ?? []).find((x) => x.id === cloudForm.provider)
            return (
              <ol className="flex list-decimal flex-col gap-1 rounded-md bg-ink-800/60 p-3 pl-7 text-xs text-slate-400 ring-1 ring-ink-700">
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
                    <code className="min-w-0 flex-1 truncate rounded-md bg-ink-900 px-2 py-1 text-2xs text-slate-300">
                      {cloud?.redirect_uri}
                    </code>
                    <Button variant="ghost" size="sm" type="button" className="wt-touch" onClick={copyRedirect}>
                      {copied ? t('settings.cloud.copied') : t('settings.cloud.copy')}
                    </Button>
                  </div>
                </li>
                <li>{t('settings.cloud.step4')}</li>
                <li>{t('settings.cloud.step5')}</li>
              </ol>
            )
          })()}

          {/* OAuth: credenţialele aplicaţiei + parola de criptare */}
          {!isDirect && (
            <form onSubmit={(e) => { void saveCloud(e) }} className="flex flex-col gap-3">
              <Field label={t('settings.cloud.clientId')}>
                <input value={cloudForm.client_id} spellCheck={false} autoComplete="off"
                  onChange={(e) => setCloudForm((f) => ({ ...f, client_id: e.target.value }))} className={field} />
              </Field>
              <Field label={t('settings.cloud.clientSecret')} hint={cloud?.configured ? keepHint : undefined}>
                <input type="password" value={cloudForm.client_secret} autoComplete="new-password"
                  onChange={(e) => setCloudForm((f) => ({ ...f, client_secret: e.target.value }))} className={field} />
              </Field>
              {passphraseField(cloudForm.passphrase, (v) => setCloudForm((f) => ({ ...f, passphrase: v })))}
              {keepAndTx(cloudForm.keep, (n) => setCloudForm((f) => ({ ...f, keep: n })),
                cloudForm.include_transcripts, (v) => setCloudForm((f) => ({ ...f, include_transcripts: v })))}
              {/* re-auth: configurarea deschide un canal permanent prin care pleacă backup-uri */}
              {reauthField(cloudForm.current_password, (v) => setCloudForm((f) => ({ ...f, current_password: v })),
                t('settings.backup.reauthChannelHint'))}
              {actionRow(false)}
            </form>
          )}

          {/* server propriu: SFTP/FTPS scris din UI. Arhiva pleacă DEJA criptată; aici configurăm doar
              unde şi cum ne conectăm, cu credenţialele criptate în seif. */}
          {isDirect && (
            <form onSubmit={(e) => { void saveDirect(e) }} data-testid="direct-backup-form" className="flex flex-col gap-3">
              <p className="flex items-start gap-2 text-xs text-slate-500">
                <span>{directForm.kind === 'sftp' ? t('settings.direct.sftpHint') : t('settings.direct.ftpsHint')}</span>
                <HelpTip id="directBackup" />
              </p>
              <div className="flex gap-2">
                <Field label={t('settings.direct.host')} className="min-w-0 flex-1">
                  <input value={directForm.host} spellCheck={false} autoComplete="off"
                    placeholder={t('settings.direct.hostExample')}
                    onChange={(e) => { setDirectForm((f) => ({ ...f, host: e.target.value, hostkey: '' })); setProbeInfo(null) }}
                    className={field} />
                </Field>
                <Field label={t('settings.direct.port')} className="w-24 shrink-0">
                  <input type="number" min={1} max={65535} value={directForm.port}
                    onChange={(e) => { setDirectForm((f) => ({ ...f, port: Number(e.target.value), hostkey: '' })); setProbeInfo(null) }}
                    className={field} />
                </Field>
              </div>
              <Field label={t('settings.direct.user')}>
                <input value={directForm.user} spellCheck={false} autoComplete="off"
                  onChange={(e) => setDirectForm((f) => ({ ...f, user: e.target.value }))} className={field} />
              </Field>
              <Field label={t('settings.direct.path')}>
                <input value={directForm.path} spellCheck={false} autoComplete="off" placeholder={t('settings.direct.pathExample')}
                  onChange={(e) => setDirectForm((f) => ({ ...f, path: e.target.value }))} className={field} />
              </Field>

              {/* metoda de auth: cheie SSH (doar SFTP) sau parolă */}
              {directForm.kind === 'sftp' && (
                <SegmentedControl label={t('settings.direct.authMethod')} value={directForm.auth}
                  options={[{ value: 'key', label: t('settings.direct.authKey') }, { value: 'password', label: t('settings.direct.authPassword') }]}
                  onChange={(m) => setDirectForm((f) => ({ ...f, auth: m }))} className="self-start" />
              )}
              {directForm.kind === 'sftp' && directForm.auth === 'key' ? (
                <Field label={t('settings.direct.sshKey')} hint={cloud?.direct?.has_key ? keepHint : undefined}>
                  <textarea value={directForm.ssh_key} spellCheck={false} autoComplete="off" rows={4}
                    onChange={(e) => setDirectForm((f) => ({ ...f, ssh_key: e.target.value }))}
                    className={field + ' font-mono text-xs'} />
                </Field>
              ) : (
                <Field label={t('settings.direct.password')} hint={cloud?.direct?.has_password ? keepHint : undefined}>
                  <input type="password" value={directForm.password} autoComplete="new-password"
                    onChange={(e) => setDirectForm((f) => ({ ...f, password: e.target.value }))} className={field} />
                </Field>
              )}

              {/* SFTP: pinuirea host-key-ului (TOFU). Fără amprentă confirmată nu se poate salva. */}
              {directForm.kind === 'sftp' && (
                <div className="rounded-md bg-ink-800/60 p-3 ring-1 ring-ink-700">
                  <div className="flex flex-wrap items-center gap-2">
                    <Button variant="secondary" type="button" onClick={() => { void probeHost() }}
                      disabled={cloudBusy || !directForm.host || !directForm.user}
                      aria-describedby={!directForm.host || !directForm.user ? 'bk-probe-why' : undefined}>
                      {t('settings.direct.probe')}
                    </Button>
                    {directForm.hostkey
                      ? <span className="text-xs wt-good">{t('settings.direct.hostkeyPinned')}</span>
                      : <span id="bk-hostkey-why" className="text-xs wt-warn">{t('settings.direct.hostkeyNeeded')}</span>}
                  </div>
                  {(!directForm.host || !directForm.user) && (
                    <p id="bk-probe-why" className="mt-1 text-xs text-slate-500">{t('settings.direct.whyProbe')}</p>
                  )}
                  {probeInfo && (
                    <p className="mt-2 break-all text-xs text-slate-400">
                      {t('settings.direct.confirmFingerprint')}
                      <span className="mt-1 block font-mono text-slate-200">{probeInfo.fingerprint}</span>
                    </p>
                  )}
                  {probeInfo?.auth_tested === false && (
                    <Button variant="secondary" type="button" className="mt-2" disabled={cloudBusy}
                      onClick={() => { void probeHost(probeInfo.hostkey) }}>
                      {t('settings.direct.trustAndTest')}
                    </Button>
                  )}
                </div>
              )}
              {/* FTPS: CA/cert PEM opţional pentru servere self-signed (public, nu e secret) */}
              {directForm.kind === 'ftps' && (
                <Field label={t('settings.direct.ca')} hint={cloud?.direct?.has_ca ? keepHint : t('settings.direct.caHint')}>
                  <textarea value={directForm.ca} spellCheck={false} autoComplete="off" rows={3}
                    onChange={(e) => setDirectForm((f) => ({ ...f, ca: e.target.value }))}
                    className={field + ' font-mono text-xs'} />
                </Field>
              )}

              {passphraseField(directForm.passphrase, (v) => setDirectForm((f) => ({ ...f, passphrase: v })))}
              {keepAndTx(directForm.keep, (n) => setDirectForm((f) => ({ ...f, keep: n })),
                directForm.include_transcripts, (v) => setDirectForm((f) => ({ ...f, include_transcripts: v })))}
              {reauthField(directForm.current_password, (v) => setDirectForm((f) => ({ ...f, current_password: v })),
                t('settings.backup.reauthChannelHint'))}
              {actionRow(true)}
            </form>
          )}
        </div>
      </SettingsSection>

      {/* copiile de pe server (făcute de program): descărcare criptată, verificare, ştergere */}
      <SettingsSection title={t('settings.backup.storedTitle')} hidden={!vis('backupAuto')}
        description={bkStatus ? t('settings.backup.storedDesc', { days: bkStatus.retention_days }) : undefined}>
        <p className="text-xs text-slate-500" data-testid="restore-verified">
          {bkStatus?.restore_verified_at
            ? t('settings.backup.lastVerified', { when: fmtTs(bkStatus.restore_verified_at) })
            : t('settings.backup.neverVerified')}
        </p>
        {bkStatus && bkStatus.backups.length === 0 && (
          <p className="mt-2 text-xs text-slate-500">{t('settings.backup.storedEmpty')}</p>
        )}
        {bkStatus && bkStatus.backups.length > 0 && (
          <ul className="mt-2 space-y-1">
            {bkStatus.backups.map((b) => (
              <li key={b.name} className="flex flex-wrap items-center justify-between gap-2 rounded-md bg-ink-800 px-3 py-2 text-sm">
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-slate-300" title={b.name}>
                  {b.name}
                  <span className="ml-2 text-slate-500">{(b.size / 1024).toFixed(0)} KB</span>
                </span>
                <span className="flex shrink-0 items-center gap-1">
                  <Button variant="ghost" size="sm" type="button" className="wt-touch" disabled={bkBusy} onClick={() => { void verifyStored(b.name) }}>
                    {t('settings.backup.verify')}
                  </Button>
                  <Button variant="ghost" size="sm" type="button" className="wt-touch" onClick={() => { void downloadStored(b.name) }}>
                    {t('settings.download')}
                  </Button>
                  <Button variant="ghost" size="sm" type="button" className="wt-touch" onClick={() => { void deleteStored(b.name) }}>
                    {t('settings.delete')}
                  </Button>
                </span>
              </li>
            ))}
          </ul>
        )}
        <div className="mt-2 flex flex-wrap items-center gap-2">{status(storedMsg, storedErr)}</div>
      </SettingsSection>

      {/* export manual: fiecare secret îşi spune numele (audit M8) */}
      <SettingsSection data-setting-id="backupDownload" hidden={!vis('backupDownload')}
        title={t('settings.backup.downloadTitle')} titleExtra={<HelpTip id="backup" />}
        description={<>
          {t('settings.backup.downloadHintA')} <span className="text-slate-300">{t('settings.backup.encryptedWithPass')}</span> {t('settings.backup.downloadHintB')} <span className="text-slate-300">{t('settings.backup.dontLoseIt')}</span>{t('settings.backup.downloadHintC')}
        </>}
        footer={<>
          <Button variant="primary" type="button" disabled={bkBusy} onClick={() => { void downloadBackupNow() }}>
            {bkBusy ? t('settings.backup.preparing') : t('settings.downloadEncryptedBackup')}
          </Button>
          {status(bkMsg, bkErr)}
        </>}>
        <div className="flex flex-col gap-3">
          <Field label={t('settings.backup.filePass')} hint={t('settings.backup.filePassHint')}>
            <input type="password" value={bkPass} onChange={(e) => setBkPass(e.target.value)}
              autoComplete="new-password" className={field} />
          </Field>
          <Field label={t('settings.backup.confirmPass')}>
            <input type="password" value={bkPass2} onChange={(e) => setBkPass2(e.target.value)}
              autoComplete="new-password" className={field} />
          </Field>
          {reauthField(bkReauth, setBkReauth, t('settings.backup.reauthFileHint'))}
          <Switch checked={bkTx} onChange={setBkTx} label={t('settings.backup.includeTranscripts')} />
        </div>
      </SettingsSection>

      {/* restaurarea: ultima, în zona periculoasă, cu confirmarea ei (ConfirmModal) neschimbată (audit Me3) */}
      <SettingsSection data-setting-id="backupRestore" hidden={!vis('backupRestore')} tone="danger"
        title={t('settings.backup.restoreTitle')} titleExtra={<HelpTip id="backup" />}
        description={<>
          {t('settings.backup.restoreHintA')} <span className="font-mono">.wtbk</span> {t('settings.backup.restoreHintB')}
          <span className="wt-warn"> {t('settings.backup.restoreRestarts')}</span> {t('settings.backup.restoreHintC')}
        </>}
        footer={<>
          <Button variant="danger" type="button" disabled={restoreBusy || !restoreFile}
            aria-describedby={!restoreFile ? 'bk-restore-why' : undefined} onClick={() => { void doRestore() }}>
            {restoreBusy ? t('settings.backup.validating') : t('settings.backup.restoreAndRestart')}
          </Button>
          {!restoreFile && <span id="bk-restore-why" className="text-xs text-slate-500">{t('settings.backup.whyRestore')}</span>}
          {status(restoreMsg, restoreErr)}
        </>}>
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="secondary" type="button" onClick={() => restoreRef.current?.click()}>
              {t('settings.chooseFile')}
            </Button>
            <span className="min-w-0 truncate text-xs text-slate-400">{restoreFile ? restoreFile.name : t('settings.noFileChosen')}</span>
            <input ref={restoreRef} type="file" accept=".wtbk,application/octet-stream" className="hidden"
              onChange={(e) => setRestoreFile(e.target.files?.[0] ?? null)} />
          </div>
          {restoreFile && (
            <p className="text-xs text-slate-400">{restorePreview(restoreFile)}</p>
          )}
          <Field label={t('settings.backup.restorePass')} hint={t('settings.backup.restorePassPlaceholder')}>
            <input type="password" value={restorePass} onChange={(e) => setRestorePass(e.target.value)}
              autoComplete="off" className={field} />
          </Field>
          {reauthField(restoreReauth, setRestoreReauth, t('settings.backup.reauthRestoreHint'))}
        </div>
      </SettingsSection>
    </div>
  )
}
