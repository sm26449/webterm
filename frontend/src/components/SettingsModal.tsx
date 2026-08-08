import { startRegistration } from '@simplewebauthn/browser'
import qrcode from 'qrcode-generator'
import { FormEvent, useEffect, useRef, useState } from 'react'
import { errText, api, ApiError, CommandGuard, WatermarkConfig } from '../lib/api'
import { useI18n } from '../lib/i18n'
import UpdateCommand from './UpdateCommand'
import { LANGS, LANG_ORDER } from '../lang'
import { useFocusTrap } from '../lib/useFocusTrap'
import {
  allSchemes, clearCustomTheme, COLOR_KEYS, currentTermScheme,
  customTheme, parseThemeFile, saveCustomTheme, setTermScheme, termTheme,
} from '../lib/termtheme'
import { useTheme } from '../lib/theme'
import { allTimezones, browserTimezone, fmtTs, getTimezone, setTimezone, timeInZone } from '../lib/tz'
import { KeyIcon } from './Icons'
import { copyText } from '../lib/clipboard'

interface Passkey {
  id: number
  name: string
  created: number
}

export default function SettingsModal(props: {
  email: string | null
  webauthnAvailable: boolean
  initialCat?: 'cont' | 'securitate' | 'aspect' | 'notificari' | 'backup' | 'preferinte'
  onClose: () => void
  onAccountChanged: () => void   // refetch /api/state (refolosit și după salvarea watermark-ului)
}) {
  const [passkeys, setPasskeys] = useState<Passkey[]>([])
  // erori per secțiune, afișate lângă butonul care le-a produs — modalul e lung
  // și scrollabil, o singură eroare la fund ar fi de multe ori în afara ecranului
  const [accountErr, setAccountErr] = useState('')
  const [securityErr, setSecurityErr] = useState('')
  const [smtpErr, setSmtpErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [themePrefValue, , setTheme] = useTheme()
  const [scheme, setScheme] = useState(currentTermScheme())
  // editorul de schemă proprie: pornește de la ce e activ acum (nu de la zero)
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState<Record<string, string>>({})
  const [importErr, setImportErr] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)
  const [srMode, setSrMode] = useState(() => localStorage.getItem('wt_sr') === '1')

  // Watermark (overlay de identitate) — persistat server-side (/api/settings/watermark),
  // aplicat pe workspace + link-uri partajate. Editare locală, salvare explicită.
  const [wm, setWm] = useState<WatermarkConfig>({
    enabled: false, content: '${email} · ${time}', opacity: 0.08, angle: -30, fontSize: 13,
  })
  const [wmMsg, setWmMsg] = useState('')
  useEffect(() => {
    api<WatermarkConfig>('/api/settings/watermark').then(setWm).catch(() => {})
  }, [])
  const saveWatermark = async () => {
    try {
      const saved = await api<WatermarkConfig>('/api/settings/watermark',
        { method: 'POST', body: JSON.stringify(wm) })
      setWm(saved)
      setWmMsg(t('settings.saved'))
      props.onAccountChanged()   // refetch /api/state → overlay-ul live se actualizează
      setTimeout(() => setWmMsg(''), 1500)
    } catch {
      setWmMsg(t('settings.saveError'))
    }
  }

  // Guardrail de comenzi — verificat client-side la Enter (via OSC 133)
  const [guard, setGuard] = useState<CommandGuard>({ enabled: true, rules: [] })
  const [guardMsg, setGuardMsg] = useState('')
  useEffect(() => {
    api<CommandGuard>('/api/settings/command-guard').then(setGuard).catch(() => {})
  }, [])
  const saveGuard = async () => {
    try {
      const saved = await api<CommandGuard>('/api/settings/command-guard',
        { method: 'POST', body: JSON.stringify(guard) })
      setGuard(saved)
      setGuardMsg(t('settings.saved'))
      props.onAccountChanged()   // refetch /api/state → guardrail-ul live se actualizează
      setTimeout(() => setGuardMsg(''), 1500)
    } catch (e) {
      setGuardMsg(errText(e, t) || t('settings.saveError'))
    }
  }
  // categoria activă: modalul nu mai e un scroll lung — arată o secțiune odată
  const { t, lang, setLang } = useI18n()
  const [cat, setCat] = useState<'cont' | 'securitate' | 'audit' | 'aspect' | 'notificari' | 'backup' | 'preferinte'>(props.initialCat ?? 'cont')
  const CATS = [
    { id: 'cont', label: t('settings.cat.account') },
    { id: 'securitate', label: t('settings.cat.security') },
    { id: 'audit', label: t('settings.cat.audit') },
    { id: 'aspect', label: t('settings.cat.appearance') },
    { id: 'notificari', label: t('settings.cat.notifications') },
    { id: 'backup', label: t('settings.cat.backup') },
    { id: 'preferinte', label: t('settings.cat.preferences') },
  ] as const
  // ── Token-uri de automatizare (cron/CI/monitorizare) ──
  type TokenRow = { id: number; name: string; scopes: string; created: number
    expires: number; last_used: number | null; created_by: string; expired: boolean }
  const [tokens, setTokens] = useState<TokenRow[]>([])
  const [newTok, setNewTok] = useState({ name: '', read: true, run: false, days: 90, current_password: '' })
  const [tokPlain, setTokPlain] = useState('')     // valoarea în clar, arătată O SINGURĂ dată
  const [tokErr, setTokErr] = useState('')
  const loadTokens = () => api<TokenRow[]>('/api/tokens').then(setTokens).catch(() => {})

  async function addToken(e: FormEvent) {
    e.preventDefault()
    setTokErr(''); setTokPlain(''); setBusy(true)
    try {
      const scopes = [newTok.read && 'read', newTok.run && 'run'].filter(Boolean) as string[]
      const r = await api<{ token: string; tokens: TokenRow[] }>('/api/tokens', {
        method: 'POST',
        body: JSON.stringify({ name: newTok.name, scopes, days: newTok.days,
                               current_password: newTok.current_password }),
      })
      setTokens(r.tokens); setTokPlain(r.token)
      setNewTok({ name: '', read: true, run: false, days: 90, current_password: '' })
    } catch (e) {
      setTokErr(errText(e, t) || String(e))
    }
    setBusy(false)
  }

  async function revokeToken(tk: TokenRow) {
    if (!window.confirm(t('settings.tokens.revokeConfirm', { name: tk.name }))) return
    try {
      setTokens(await api<TokenRow[]>(`/api/tokens/${tk.id}/revoke`, { method: 'POST' }))
    } catch (e) {
      setTokErr(errText(e, t) || String(e))
    }
  }

  // ── Conturi: mai multe, TOATE cu drepturi depline (fără RBAC — vezi API-ul) ──
  type UserRow = { id: number; email: string; created: number; totp: boolean; passkeys: number; is_self: boolean }
  const [users, setUsers] = useState<UserRow[]>([])
  const [newUser, setNewUser] = useState({ email: '', password: '', current_password: '' })
  const [usersMsg, setUsersMsg] = useState('')
  const [usersErr, setUsersErr] = useState('')
  const loadUsers = () => api<UserRow[]>('/api/users').then(setUsers).catch(() => {})

  async function addUser(e: FormEvent) {
    e.preventDefault()
    setUsersErr(''); setUsersMsg(''); setBusy(true)
    try {
      setUsers(await api<UserRow[]>('/api/users', { method: 'POST', body: JSON.stringify(newUser) }))
      setNewUser({ email: '', password: '', current_password: '' })
      setUsersMsg(t('settings.users.added'))
    } catch (e) {
      setUsersErr(errText(e, t) || String(e))
    }
    setBusy(false)
  }

  async function removeUser(u: UserRow) {
    // ştergerea unui cont taie şi sesiunile lui: e o revocare, nu o ascundere
    const pw = window.prompt(t('settings.users.deleteConfirm', { email: u.email }))
    if (!pw) return
    setUsersErr(''); setUsersMsg('')
    try {
      setUsers(await api<UserRow[]>(`/api/users/${u.id}/delete`,
        { method: 'POST', body: JSON.stringify({ current_password: pw }) }))
      setUsersMsg(t('settings.users.deleted'))
    } catch (e) {
      setUsersErr(errText(e, t) || String(e))
    }
  }

  // ── Backup off-host în cloud (Google Drive / Dropbox), conectat prin OAuth din UI ──
  type CloudProvider = { id: string; label: string; console_url: string; app_type: string }
  type CloudStatus = {
    provider: string; configured: boolean; connected: boolean; has_passphrase: boolean
    account: string; keep: number; include_transcripts: boolean
    last: { ts?: number; ok?: boolean; name?: string; size?: number; error?: string }
    redirect_uri: string; providers: CloudProvider[]
  }
  const [cloud, setCloud] = useState<CloudStatus | null>(null)
  type UpdateInfo = {
    current: string; enabled: boolean; latest?: string
    update_available?: boolean; configurable?: boolean; error?: string
    update_command?: string
  }
  const [upd, setUpd] = useState<UpdateInfo | null>(null)
  // Parola CONTULUI, cerută de operaţiile care scot secrete din instanţă sau o pot prelua.
  // Distinctă de parola de criptare a arhivei: pe aceea o alege cel care descarcă, deci
  // nu dovedeşte nimic. Vezi _require_reauth_for_secret în gateway.
  const [bkReauth, setBkReauth] = useState('')
  const [signReauth, setSignReauth] = useState('')
  const [updBusy, setUpdBusy] = useState(false)
  const [cloudForm, setCloudForm] = useState({
    provider: 'gdrive', client_id: '', client_secret: '', passphrase: '',
    keep: 14, include_transcripts: false, current_password: '',
  })
  const [cloudMsg, setCloudMsg] = useState('')
  const [cloudErr, setCloudErr] = useState('')
  const [cloudBusy, setCloudBusy] = useState(false)
  const [cloudHelp, setCloudHelp] = useState(false)
  const [copied, setCopied] = useState(false)

  const loadCloud = () =>
    api<CloudStatus>('/api/backup/cloud').then((s) => {
      setCloud(s)
      setCloudForm((f) => ({
        ...f, provider: s.provider || f.provider, keep: s.keep || f.keep,
        include_transcripts: s.include_transcripts,
      }))
    }).catch(() => {})

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

  // ── Jurnal de audit (cine/ce/când/de la ce IP pe fiecare acțiune care schimbă ceva) ──
  type AuditEntry = {
    ts: number; actor: string; ip: string; method: string; path: string
    status: number; detail: string
  }
  const [audit, setAudit] = useState<AuditEntry[] | null>(null)
  const [auditQ, setAuditQ] = useState('')
  const [auditFailed, setAuditFailed] = useState(false)
  const [auditBusy, setAuditBusy] = useState(false)
  const [auditEnd, setAuditEnd] = useState(false)   // ultima pagină primită era incompletă
  const [auditDays, setAuditDays] = useState(0)
  const AUDIT_PAGE = 100

  // `reset` = filtre noi (pornim de la cel mai recent); altfel paginăm în trecut de la
  // ts-ul ultimei linii — offset-ul ar sări rânduri când apar acțiuni noi între cereri
  async function loadAudit(reset: boolean) {
    setAuditBusy(true)
    try {
      const last = audit && audit.length ? audit[audit.length - 1] : null
      const before = reset || !last ? 0 : last.ts
      const qs = new URLSearchParams({ limit: String(AUDIT_PAGE) })
      if (before) qs.set('before', String(before))
      if (auditQ.trim()) qs.set('q', auditQ.trim())
      if (auditFailed) qs.set('failed_only', 'true')
      const r = await api<{ entries: AuditEntry[]; retention_days: number }>(`/api/audit?${qs}`)
      setAuditDays(r.retention_days)
      setAuditEnd(r.entries.length < AUDIT_PAGE)
      setAudit(reset ? r.entries : [...(audit ?? []), ...r.entries])
    } catch { /* jurnalul e informativ — o eroare nu blochează Setările */ }
    setAuditBusy(false)
  }

  // praguri de alertă pe resurse
  const [thresholds, setThresholds] = useState({ cpu: 90, mem: 90, disk: 90 })
  const [alertMsg, setAlertMsg] = useState('')
  const loadThresholds = () =>
    api<{ cpu: number; mem: number; disk: number }>('/api/settings/alerts')
      .then(setThresholds)
      .catch(() => {})
  async function saveThresholds() {
    setAlertMsg(''); setSmtpErr(''); setBusy(true)
    try {
      await api('/api/settings/alerts', { method: 'POST', body: JSON.stringify(thresholds) })
      setAlertMsg(t('settings.thresholdsSaved'))
    } catch (err) {
      setSmtpErr(errText(err, t) || t('settings.error'))
    } finally { setBusy(false) }
  }

  const openEditor = () => {
    const base = customTheme() ?? termTheme(scheme)
    setDraft(Object.fromEntries(COLOR_KEYS.map((k) => [k, (base as Record<string, string>)[k] ?? '#000000'])))
    setEditing(true)
  }
  const applyDraft = (next: Record<string, string>) => {
    setDraft(next)
    // preview LIVE în toate terminalele deschise (mecanismul wt-termscheme)
    saveCustomTheme({ ...next, cursorAccent: next.background })
    setTermScheme('custom')
    setScheme('custom')
  }
  const importTheme = async (file: File) => {
    setImportErr('')
    try {
      const theme = parseThemeFile(file.name, await file.text())
      saveCustomTheme(theme)
      setTermScheme('custom')
      setScheme('custom')
      setDraft(Object.fromEntries(COLOR_KEYS.map((k) => [k, (theme as Record<string, string>)[k] ?? '#000000'])))
      setEditing(true)
    } catch (e) {
      setImportErr(errText(e, t) || t('settings.importFailed'))
    }
  }
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)

  // cont
  const [curPw, setCurPw] = useState('')
  const [newEmail, setNewEmail] = useState(props.email ?? '')
  const [newPw, setNewPw] = useState('')
  const [accountMsg, setAccountMsg] = useState('')

  // 2FA (TOTP)
  const [totpEnabled, setTotpEnabled] = useState(false)
  const [recoveryLeft, setRecoveryLeft] = useState(0)
  const [enroll, setEnroll] = useState<{ secret: string; uri: string } | null>(null)
  const [enrollPw, setEnrollPw] = useState('')   // M1: re-auth pt. înrolarea 2FA (setup + activate)
  const [activateCode, setActivateCode] = useState('')
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null)
  const [pendingAction, setPendingAction] = useState<'disable' | 'regen' | null>(null)
  const [actionPw, setActionPw] = useState('')

  const loadTotp = () =>
    api<{ enabled: boolean; recovery_remaining: number }>('/api/totp/status')
      .then((s) => { setTotpEnabled(s.enabled); setRecoveryLeft(s.recovery_remaining) })
      .catch(() => {})

  // SMTP (alerte pe email)
  const [smtp, setSmtp] = useState({
    host: '', port: 587, user: '', password: '', from_addr: '', to_addr: '', starttls: true,
    webhook: '',
  })
  const [smtpHasPw, setSmtpHasPw] = useState(false)
  const [smtpMsg, setSmtpMsg] = useState('')
  const [smtpTesting, setSmtpTesting] = useState(false)

  const loadSmtp = () =>
    api<any>('/api/settings/smtp').then((c) => {
      setSmtp({ host: c.host || '', port: c.port || 587, user: c.user || '', password: '',
        from_addr: c.from_addr || '', to_addr: c.to_addr || '', starttls: c.starttls,
        webhook: c.webhook || '' })
      setSmtpHasPw(c.has_password)
    }).catch(() => {})

  async function saveSmtp() {
    setSmtpMsg(''); setSmtpErr(''); setBusy(true)
    try {
      await api('/api/settings/smtp', { method: 'POST', body: JSON.stringify(smtp) })
      setSmtp((s) => ({ ...s, password: '' }))
      await loadSmtp()
      setSmtpMsg(t('settings.smtp.saved'))
    } catch (err) {
      setSmtpErr(errText(err, t) || t('settings.error'))
    } finally { setBusy(false) }
  }

  async function testSmtp() {
    setSmtpMsg(''); setSmtpErr(''); setSmtpTesting(true)
    try {
      // salvează ÎNTÂI ce e în formular: altfel testul rulează pe configurația
      // veche și fluxul natural „completez → testez" testează altceva
      await api('/api/settings/smtp', { method: 'POST', body: JSON.stringify(smtp) })
      setSmtp((s) => ({ ...s, password: '' }))
      await loadSmtp()
      await api('/api/settings/smtp/test', { method: 'POST' })
      setSmtpMsg(t('settings.smtp.testSent'))
    } catch (err) {
      setSmtpErr(errText(err, t) || t('settings.error'))
    } finally { setSmtpTesting(false) }
  }

  // Port forwarding: domeniu configurabil
  type FwdCfg = {
    domain: string; app_domain: string; is_custom: boolean
    server_ip: string; dns_ip: string; dns_ok: boolean; cert_ok: boolean
  }
  const [fwd, setFwd] = useState<FwdCfg | null>(null)
  const [fwdDomain, setFwdDomain] = useState('')
  const [fwdMsg, setFwdMsg] = useState('')
  const [fwdErr, setFwdErr] = useState('')
  const [fwdBusy, setFwdBusy] = useState(false)
  const loadFwd = () =>
    api<FwdCfg>('/api/settings/forward').then((c) => { setFwd(c); setFwdDomain(c.domain) }).catch(() => {})
  async function saveFwd() {
    setFwdBusy(true); setFwdMsg(''); setFwdErr('')
    try {
      const c = await api<FwdCfg>('/api/settings/forward', {
        method: 'POST', body: JSON.stringify({ domain: fwdDomain.trim() }),
      })
      setFwd(c); setFwdDomain(c.domain); setFwdMsg(t('settings.forward.saved'))
    } catch (e) {
      setFwdErr(errText(e, t) || t('settings.error'))
    } finally { setFwdBusy(false) }
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

  // Descărcare de blob (endpoint-urile întorc octeți, nu JSON → fetch brut).
  async function downloadBlob(path: string, body: unknown, fallbackName: string) {
    const res = await fetch(path, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    })
    if (!res.ok) {
      let detail = res.statusText
      try { detail = (await res.json()).detail ?? detail } catch { /* non-JSON */ }
      throw new ApiError(res.status, detail)
    }
    const cd = res.headers.get('Content-Disposition') || ''
    const m = cd.match(/filename="([^"]+)"/)
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = m?.[1] || fallbackName
    document.body.appendChild(a); a.click(); a.remove()
    URL.revokeObjectURL(url)
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

  // ── Cheie de semnare a flotei ──
  type SignStatus = { exists: boolean; encrypted: boolean; unlocked: boolean; pubkey: string | null }
  const [sign, setSign] = useState<SignStatus | null>(null)
  const [signPass, setSignPass] = useState('')
  const [signPass2, setSignPass2] = useState('')
  const [signUnlockPass, setSignUnlockPass] = useState('')
  const [signMsg, setSignMsg] = useState('')
  const [signErr, setSignErr] = useState('')
  const [signBusy, setSignBusy] = useState(false)
  const [signMode, setSignMode] = useState<'gen' | 'import'>('gen')
  const [signPem, setSignPem] = useState('')            // conținutul PEM la import
  const [signPemName, setSignPemName] = useState('')
  const [signImpLoadPass, setSignImpLoadPass] = useState('')
  const [signImpStorePass, setSignImpStorePass] = useState('')
  const signPemRef = useRef<HTMLInputElement>(null)
  const loadSigning = () => api<SignStatus>('/api/signing/status').then(setSign).catch(() => {})

  async function importSigningKey() {
    setSignErr(''); setSignMsg('')
    if (!signPem.trim()) { setSignErr(t('settings.sign.chooseKeyFile')); return }
    if (signImpStorePass && signImpStorePass.length < 8) { setSignErr(t('settings.sign.storePassMin8')); return }
    if (!confirm(t('settings.sign.importConfirm'))) return
    setSignBusy(true)
    try {
      const s = await api<SignStatus>('/api/signing/import', {
        method: 'POST',
        body: JSON.stringify({ pem: signPem, load_passphrase: signImpLoadPass,
                               store_passphrase: signImpStorePass, current_password: signReauth }),
      })
      setSign(s); setSignPem(''); setSignPemName(''); setSignImpLoadPass(''); setSignImpStorePass(''); setSignReauth('')
      setSignMsg(t('settings.sign.imported'))
      props.onAccountChanged()
    } catch (e) { setSignErr(errText(e, t) || t('settings.importFailed')) } finally { setSignBusy(false) }
  }

  async function genSigningKey() {
    setSignErr(''); setSignMsg('')
    if (signPass && signPass.length < 8) { setSignErr(t('settings.sign.keyPassMin8')); return }
    if (signPass !== signPass2) { setSignErr(t('settings.passMismatch')); return }
    if (!confirm(t('settings.sign.genConfirm'))) return
    setSignBusy(true)
    try {
      const s = await api<SignStatus>('/api/signing/generate',
        { method: 'POST', body: JSON.stringify({ passphrase: signPass, current_password: signReauth }) })
      setSign(s); setSignPass(''); setSignPass2('')
      setSignMsg(t('settings.sign.generated'))
      props.onAccountChanged()
    } catch (e) { setSignErr(errText(e, t) || t('settings.sign.genFailed')) } finally { setSignBusy(false) }
  }
  async function unlockSigning() {
    setSignErr(''); setSignMsg(''); setSignBusy(true)
    try {
      const s = await api<SignStatus>('/api/signing/unlock', { method: 'POST', body: JSON.stringify({ passphrase: signUnlockPass }) })
      setSign(s); setSignUnlockPass(''); setSignMsg(t('settings.sign.unlocked'))
      props.onAccountChanged()
    } catch (e) { setSignErr(errText(e, t) || t('settings.sign.unlockFailed')) } finally { setSignBusy(false) }
  }
  async function lockSigning() {
    setSignErr(''); setSignMsg('')
    try { const s = await api<SignStatus>('/api/signing/lock', { method: 'POST' }); setSign(s); props.onAccountChanged() }
    catch (e) { setSignErr(errText(e, t) || t('settings.error')) }
  }
  async function downloadSigningKey() {
    setSignErr(''); setSignMsg('')
    const pass = prompt(t('settings.sign.backupPassPrompt'))
    if (pass === null) return
    if (pass.length < 8) { setSignErr(t('settings.passMin8')); return }
    setSignBusy(true)
    try {
      const acct = prompt(t('settings.reauthPrompt'))
      if (acct === null) { setSignBusy(false); return }
      await downloadBlob('/api/signing/backup', { passphrase: pass, current_password: acct },
        'webterm-signing-key.wtbk')
      setSignMsg(t('settings.sign.backupDownloaded'))
    } catch (e) { setSignErr(errText(e, t) || t('settings.downloadFailed')) } finally { setSignBusy(false) }
  }

  // fus orar
  const [tz, setTz] = useState(getTimezone())
  const [clock, setClock] = useState(timeInZone(getTimezone()))
  useEffect(() => {
    const t = setInterval(() => setClock(timeInZone(tz)), 1000)
    return () => clearInterval(t)
  }, [tz])

  const load = () =>
    api<Passkey[]>('/api/webauthn/credentials').then(setPasskeys).catch(() => {})

  useEffect(() => {
    load()
    loadTotp()
    loadSmtp()
    loadThresholds()
    loadFwd()
    loadBackup()
    loadSigning()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // vizitarea secțiunii Backup „vede" notificarea (punctul de pe rotița Setări) → o
  // stinge, nu doar la descărcare (altfel rămânea aprinsă dacă ștergeai fără să descarci)
  useEffect(() => {
    if (cat === 'preferinte' && upd === null) api<UpdateInfo>('/api/version').then(setUpd).catch(() => {})
    if (cat === 'cont' && users.length === 0) loadUsers()
    if (cat === 'securitate' && tokens.length === 0) loadTokens()
    if (cat === 'backup') { markBackupSeen(); if (cloud === null) loadCloud() }
    // jurnalul se încarcă LENEȘ (la deschiderea secțiunii): e singura listă din modal care
    // poate avea mii de rânduri, n-are rost s-o cerem la fiecare deschidere de Setări
    if (cat === 'audit' && audit === null) loadAudit(true)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cat])

  async function startEnroll() {
    setSecurityErr('')
    setRecoveryCodes(null)
    // M1: înrolarea 2FA e schimbare de credențiale — cere parola (ca un cookie furat să nu
    // poată înrola un TOTP atacator). O ținem pentru pasul de activare din acelaşi flux.
    const password = prompt(t('settings.totp.enrollPrompt'))
    if (password === null) return
    try {
      const r = await api<{ secret: string; otpauth_uri: string }>('/api/totp/setup', {
        method: 'POST',
        body: JSON.stringify({ current_password: password }),
      })
      setEnrollPw(password)
      setEnroll({ secret: r.secret, uri: r.otpauth_uri })
    } catch (err) {
      setSecurityErr(errText(err, t) || t('settings.error'))
    }
  }

  async function confirmEnroll() {
    setSecurityErr('')
    setBusy(true)
    try {
      const r = await api<{ recovery_codes: string[] }>('/api/totp/activate', {
        method: 'POST',
        body: JSON.stringify({ code: activateCode.trim(), current_password: enrollPw }),
      })
      setRecoveryCodes(r.recovery_codes)
      setEnroll(null)
      setActivateCode('')
      setEnrollPw('')
      await loadTotp()
    } catch (err) {
      setSecurityErr(errText(err, t) || t('settings.error'))
    } finally {
      setBusy(false)
    }
  }

  async function runPendingAction() {
    setSecurityErr('')
    setBusy(true)
    try {
      if (pendingAction === 'disable') {
        await api('/api/totp/disable', {
          method: 'POST',
          body: JSON.stringify({ current_password: actionPw }),
        })
        setRecoveryCodes(null)
      } else if (pendingAction === 'regen') {
        const r = await api<{ recovery_codes: string[] }>('/api/totp/recovery-codes', {
          method: 'POST',
          body: JSON.stringify({ current_password: actionPw }),
        })
        setRecoveryCodes(r.recovery_codes)
      }
      setPendingAction(null)
      setActionPw('')
      await loadTotp()
    } catch (err) {
      setSecurityErr(errText(err, t) || t('settings.error'))
    } finally {
      setBusy(false)
    }
  }

  function qrDataUrl(text: string): string {
    const qr = qrcode(0, 'M')
    qr.addData(text)
    qr.make()
    return qr.createDataURL(5, 12)
  }

  async function saveAccount(e: FormEvent) {
    e.preventDefault()
    setAccountErr('')
    setAccountMsg('')
    setBusy(true)
    try {
      const r = await api<{ email: string }>('/api/account', {
        method: 'POST',
        body: JSON.stringify({
          current_password: curPw,
          email: newEmail,
          new_password: newPw || undefined,
        }),
      })
      setAccountMsg(t('settings.accountUpdated'))
      setCurPw('')
      setNewPw('')
      props.onAccountChanged()
      void r
    } catch (err) {
      setAccountErr(errText(err, t) || t('settings.error'))
    } finally {
      setBusy(false)
    }
  }

  function chooseTz(value: string) {
    setTz(value)
    setTimezone(value)
    setClock(timeInZone(value))
  }

  async function addPasskey() {
    setSecurityErr('')
    // numele se cere ÎNAINTE de ceremonia WebAuthn: după ce credentialul e
    // creat, Cancel la prompt nu mai poate anula nimic — ajungea înregistrat
    // cu numele generic „passkey"
    const name = prompt(t('settings.passkeyNamePrompt'))
    if (name === null) return
    // M1: înrolarea unui passkey e o schimbare de credențiale — cerem parola contului
    // ca un cookie furat să nu poată adăuga un factor persistent pe ascuns.
    const password = prompt(t('settings.passkeyAddPrompt'))
    if (password === null) return
    setBusy(true)
    try {
      const options = await api<any>('/api/webauthn/register/options', { method: 'POST' })
      const credential = await startRegistration({ optionsJSON: options })
      await api('/api/webauthn/register/verify', {
        method: 'POST',
        body: JSON.stringify({ credential, name: name.trim() || 'passkey', password }),
      })
      load()
    } catch (err) {
      if (err instanceof Error && err.name !== 'NotAllowedError') setSecurityErr(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function remove(id: number) {
    // M1: scoaterea unui factor rezistent la phishing e schimbare de credențiale — cere parola.
    const password = prompt(t('settings.passkeyRemovePrompt'))
    if (password === null) return
    try {
      await api(`/api/webauthn/credentials/${id}`, {
        method: 'DELETE',
        body: JSON.stringify({ password }),
      })
    } catch (err) {
      setSecurityErr(errText(err, t) || t('settings.deleteFailed'))
    }
    load()
  }

  const field =
    'w-full rounded-lg bg-ink-800 px-3 py-2 text-sm text-slate-200 placeholder-slate-500 ring-1 ring-ink-700 focus:ring-sky-500'
  const heading = 'mt-6 text-[13px] font-semibold uppercase tracking-wide text-slate-400'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-label={t('settings.title')}
        className="glass flex h-[92vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl sm:h-[88vh] lg:max-w-4xl xl:max-w-5xl">
        {/* antet fix */}
        <div className="flex items-center justify-between border-b border-ink-800 px-5 py-3">
          <h2 className="text-lg font-semibold">{t('settings.title')}</h2>
          <button onClick={props.onClose} aria-label={t('settings.close')} className="wt-touch grid place-items-center rounded-md px-2 py-1 text-slate-400 hover:bg-ink-800">
            ✕
          </button>
        </div>

        <div className="flex min-h-0 flex-1 flex-col sm:flex-row">
          {/* rail de categorii: coloană pe desktop, bandă orizontală pe mobil */}
          <nav aria-label={t('settings.categoriesNav')}
            className="flex shrink-0 gap-1 overflow-x-auto border-b border-ink-800 p-2 sm:w-44 lg:w-52 sm:flex-col sm:overflow-x-visible sm:border-b-0 sm:border-r">
            {CATS.map((c) => (
              <button
                key={c.id}
                onClick={() => setCat(c.id)}
                aria-current={cat === c.id ? 'true' : undefined}
                className={`wt-touch shrink-0 rounded-lg px-3 py-2 text-left text-sm sm:w-full ${
                  cat === c.id ? 'bg-sky-600 text-white' : 'text-slate-300 hover:bg-ink-800'
                }`}
              >
                {c.label}
              </button>
            ))}
          </nav>

          {/* conținut: doar categoria activă, scrollabil */}
          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
            {/* coloană de lectură: peste ~70ch textul devine greu de urmărit;
                secţiunile cu liste (audit, backup, conturi) folosesc toată lăţimea */}
            <div className={cat === 'audit' || cat === 'backup' ? '' : 'max-w-3xl'}>

        {cat === 'cont' && (<div>
        {/* ── Cont ── */}
        <h3 className={heading + ' !mt-0'}>{t('settings.account')}</h3>
        <form onSubmit={saveAccount} className="mt-2 flex flex-col gap-2">
          <input
            type="email"
            value={newEmail}
            onChange={(e) => setNewEmail(e.target.value)}
            placeholder={t('settings.email')}
            aria-label={t('settings.email')}
            autoComplete="username"
            className={field}
          />
          <input
            type="password"
            value={newPw}
            onChange={(e) => setNewPw(e.target.value)}
            placeholder={t('settings.newPasswordPlaceholder')}
            aria-label={t('settings.newPassword')}
            autoComplete="new-password"
            className={field}
          />
          <input
            type="password"
            required
            value={curPw}
            onChange={(e) => setCurPw(e.target.value)}
            placeholder={t('settings.currentPasswordConfirm')}
            aria-label={t('settings.currentPassword')}
            autoComplete="current-password"
            className={field}
          />
          <div className="flex items-center gap-3">
            <button
              disabled={busy || !curPw}
              className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50"
            >
              {t('settings.saveAccount')}
            </button>
            {accountMsg && <span className="text-sm wt-good">{accountMsg}</span>}
            {accountErr && <span className="text-sm wt-danger">{accountErr}</span>}
          </div>
        </form>

        {/* ── Conturi (toate cu drepturi depline) ── */}
        <h3 className={heading}>{t('settings.users.title')}</h3>
        <p className="mt-1 text-xs text-slate-500">{t('settings.users.hint')}</p>
        <ul className="mt-2 flex flex-col gap-1">
          {users.map((u) => (
            <li key={u.id} className="flex items-center gap-2 rounded-lg bg-ink-800/60 px-3 py-2 text-sm ring-1 ring-ink-700">
              <span className="min-w-0 flex-1 truncate text-slate-200">{u.email}</span>
              {u.is_self && <span className="shrink-0 rounded bg-sky-600/20 px-1.5 py-0.5 text-[11px] wt-accent">{t('settings.users.you')}</span>}
              {u.totp && <span className="shrink-0 text-[11px] text-slate-500">2FA</span>}
              {u.passkeys > 0 && <span className="shrink-0 text-[11px] text-slate-500">{t('settings.users.passkeys', { n: u.passkeys })}</span>}
              {!u.is_self && users.length > 1 && (
                <button onClick={() => removeUser(u)} className="shrink-0 text-xs wt-danger hover:underline">
                  {t('settings.delete')}
                </button>
              )}
            </li>
          ))}
        </ul>
        <form onSubmit={addUser} className="mt-3 flex flex-col gap-2">
          <div className="flex flex-col gap-2 sm:flex-row">
            <input type="email" value={newUser.email} autoComplete="off"
              onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
              placeholder={t('settings.users.emailPlaceholder')} aria-label={t('settings.email')} className={field} />
            <input type="password" value={newUser.password} autoComplete="new-password"
              onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
              placeholder={t('settings.users.passwordPlaceholder')} aria-label={t('settings.newPassword')} className={field} />
          </div>
          <input type="password" value={newUser.current_password} autoComplete="current-password"
            onChange={(e) => setNewUser({ ...newUser, current_password: e.target.value })}
            placeholder={t('settings.currentPasswordConfirm')} aria-label={t('settings.currentPassword')} className={field} />
          <div className="flex items-center gap-3">
            <button type="submit" disabled={busy || !newUser.current_password}
              className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50">
              {t('settings.users.add')}
            </button>
            {usersMsg && <span className="text-sm wt-good">{usersMsg}</span>}
            {usersErr && <span className="text-sm wt-danger">{usersErr}</span>}
          </div>
        </form>
        </div>)}

        {cat === 'preferinte' && (<div>
        {/* ── Fus orar ── */}
        <h3 className={heading + ' !mt-0'}>{t('settings.timezone')}</h3>
        <p className="mt-1 text-xs text-slate-500">
          {t('settings.timezoneHintA')} <code className="font-mono text-slate-400">TZ</code>{t('settings.timezoneHintB')}
        </p>
        <div className="mt-2 flex items-center gap-2">
          <select value={tz} onChange={(e) => chooseTz(e.target.value)} aria-label={t('settings.timezone')} className={field}>
            {allTimezones().map((z) => (
              <option key={z} value={z}>
                {z}
              </option>
            ))}
          </select>
        </div>
        <div className="mt-2 flex items-center justify-between text-sm">
          <span className="font-mono tabular-nums text-slate-300">{clock}</span>
          <button
            onClick={() => chooseTz(browserTimezone())}
            className="wt-link text-xs"
          >
            {t('settings.useDeviceTimezone', { tz: browserTimezone() })}
          </button>
        </div>

        {/* ── Accesibilitate (mutată lângă Fus orar, în Preferințe) ── */}
        <h3 className={heading}>{t('settings.accessibility')}</h3>
        <label className="mt-2 flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={srMode}
            onChange={(e) => {
              setSrMode(e.target.checked)
              localStorage.setItem('wt_sr', e.target.checked ? '1' : '0')
            }}
            className="mt-0.5 h-4 w-4 rounded accent-sky-600"
          />
          <span>
            {t('settings.screenReaderMode')}
            <span className="mt-0.5 block text-xs text-slate-500">
              {t('settings.screenReaderHintA')} <code className="font-mono">Ctrl+M</code> {t('settings.screenReaderHintB')}
            </span>
          </span>
        </label>

        {/* ── Verificare de versiune ──
            Singura conexiune pe care gateway-ul o inițiază singur spre exterior, deci
            se declară explicit și se poate opri de aici. Cu `WEBTERM_UPDATE_CHECK=0`
            e oprită din mediu și comutatorul dispare — mediul bate setarea. */}
        <h3 className={heading}>{t('settings.update.title')}</h3>
        {upd?.configurable === false ? (
          <p className="mt-2 text-xs text-slate-500">{t('settings.update.disabledByEnv')}</p>
        ) : (
          <label className="mt-2 flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={!!upd?.enabled}
              disabled={upd === null}
              onChange={async (e) => {
                const enabled = e.target.checked
                setUpd((u) => (u ? { ...u, enabled } : u))
                try {
                  setUpd(await api<UpdateInfo>('/api/version/check',
                    { method: 'POST', body: JSON.stringify({ enabled }) }))
                } catch { /* rămâne starea optimistă; reîncercarea e o re-deschidere */ }
              }}
              className="mt-0.5 h-4 w-4 rounded accent-sky-600"
            />
            <span>
              {t('settings.update.label')}
              <span className="mt-0.5 block text-xs text-slate-500">{t('settings.update.hint')}</span>
              {upd?.enabled && upd.update_available && (
                <span className="mt-1 block text-xs wt-warn">
                  {t('status.updateAvailable', { version: upd.latest ?? '' })}
                </span>
              )}
              {upd?.enabled && upd.update_available === false && (
                <span className="mt-1 block text-xs wt-good">{t('status.upToDate')}</span>
              )}
              {upd?.enabled && upd.error && (
                <span className="mt-1 block text-xs text-slate-500">{t('settings.update.unreachable')}</span>
              )}
            </span>
          </label>
        )}
        {upd?.enabled && (
          <button
            type="button"
            onClick={async () => {
              setUpdBusy(true)
              try { setUpd(await api<UpdateInfo>('/api/version/refresh', { method: 'POST' })) }
              catch { /* mesajul de eroare vine din câmpul `error` al răspunsului următor */ }
              finally { setUpdBusy(false) }
            }}
            disabled={updBusy}
            className="mt-2 rounded-lg border border-ink-700 px-3 py-1.5 text-xs text-slate-300 hover:bg-ink-800 disabled:opacity-50"
          >
            {updBusy ? t('settings.update.checking') : t('settings.update.checkNow')}
          </button>
        )}
        {upd?.update_command && (
          <div className="mt-3">
            <p className="text-xs text-slate-500">{t('settings.update.howTo')}</p>
            <UpdateCommand command={upd.update_command} />
          </div>
        )}
        </div>)}

        {cat === 'aspect' && (<div>
        {/* ── Temă ── */}
        <h3 className={heading + ' !mt-0'}>{t('settings.language')}</h3>
        <div className="mt-2 flex flex-wrap gap-2">
          {LANG_ORDER.map((code) => (
            <button
              key={code}
              onClick={() => setLang(code)}
              className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm ring-1 transition ${
                lang === code
                  ? 'bg-sky-600/20 wt-accent ring-sky-500/40'
                  : 'bg-ink-800 text-slate-300 ring-ink-700 hover:bg-ink-700'
              }`}
            >
              <span className="text-base leading-none">{LANGS[code].meta.flag}</span> {LANGS[code].meta.name}
            </button>
          ))}
        </div>
        <p className="mt-1 text-[12px] text-slate-500">{t('settings.languageHint')}</p>

        <h3 className={heading}>{t('settings.theme')}</h3>
        <div className="mt-2 flex gap-2">
          {([
            ['macos', 'Aurora'],
            ['dark', 'Midnight'],
            ['auto', t('settings.themeAuto')],
          ] as const).map(([value, label]) => (
            <button
              key={value}
              onClick={() => setTheme(value)}
              className={`rounded-lg px-3 py-1.5 text-sm ring-1 ${
                themePrefValue === value
                  ? 'bg-sky-600 text-white ring-sky-600'
                  : 'bg-ink-800 text-slate-300 ring-ink-700 hover:bg-ink-700'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* ── Schema de culori a terminalului ── */}
        <h3 className={heading}>{t('settings.termColors')}</h3>
        <div className="mt-2 flex flex-wrap gap-2">
          {allSchemes().map((s) => (
            <button
              key={s.id}
              onClick={() => { setTermScheme(s.id); setScheme(s.id) }}
              className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-sm ring-1 ${
                scheme === s.id
                  ? 'bg-sky-600 text-white ring-sky-600'
                  : 'bg-ink-800 text-slate-300 ring-ink-700 hover:bg-ink-700'
              }`}
            >
              <span className="flex gap-0.5" aria-hidden="true">
                {[s.theme.red, s.theme.green, s.theme.blue, s.theme.magenta].map((c, i) => (
                  <span key={i} className="h-3 w-1.5 rounded-sm" style={{ background: c }} />
                ))}
              </span>
              {s.id === 'custom' ? t('settings.customSchemeName') : s.name}
            </button>
          ))}
        </div>

        {/* schemă proprie: editor + import iTerm2/VS Code */}
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <button
            onClick={openEditor}
            className="rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700"
          >
            {customTheme() ? t('settings.editMyScheme') : t('settings.customScheme')}
          </button>
          <button
            onClick={() => fileRef.current?.click()}
            className="rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700"
            title={t('settings.importThemeTitle')}
          >
            {t('settings.importTheme')}
          </button>
          <input
            ref={fileRef}
            type="file"
            accept=".itermcolors,.json,application/json,text/xml"
            className="hidden"
            onChange={(e) => e.target.files?.[0] && importTheme(e.target.files[0])}
          />
          {customTheme() && (
            <button
              onClick={() => {
                clearCustomTheme()
                setTermScheme('webterm-dark')
                setScheme('webterm-dark')
                setEditing(false)
              }}
              className="rounded-lg px-2 py-1.5 text-xs wt-danger hover:bg-ink-800"
            >
              {t('settings.deleteMyScheme')}
            </button>
          )}
        </div>
        <p className="mt-1 text-xs text-slate-500">
          {t('settings.importThemeHintA')}<code className="font-mono">.itermcolors</code>{t('settings.importThemeHintB')} <span className="font-mono">iTerm2-Color-Schemes</span> {t('settings.importThemeHintC')}
        </p>
        {importErr && <div className="mt-1 text-sm wt-danger">{importErr}</div>}

        {editing && (
          <div className="mt-3 rounded-xl border border-ink-700 p-3">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-sm font-medium text-slate-300">{t('settings.mySchemeLive')}</span>
              <button onClick={() => setEditing(false)} className="text-xs text-slate-400 hover:text-slate-200">
                {t('settings.done')}
              </button>
            </div>
            <div className="grid grid-cols-2 gap-x-3 gap-y-1.5 sm:grid-cols-3">
              {COLOR_KEYS.map((k) => (
                <label key={k} className="flex items-center gap-2 text-xs text-slate-400">
                  <input
                    type="color"
                    value={draft[k] ?? '#000000'}
                    aria-label={t('color.' + k)}
                    onChange={(e) => applyDraft({ ...draft, [k]: e.target.value })}
                    className="h-6 w-8 shrink-0 cursor-pointer rounded border border-ink-700 bg-transparent"
                  />
                  <span className="truncate">{t('color.' + k)}</span>
                </label>
              ))}
            </div>
          </div>
        )}

        {/* ── Watermark (overlay de identitate) ── */}
        <h3 className={heading}>{t('settings.watermark')}</h3>
        <label className="mt-2 flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={wm.enabled}
            onChange={(e) => setWm({ ...wm, enabled: e.target.checked })}
            className="mt-0.5 h-4 w-4 rounded accent-sky-600"
          />
          <span>
            {t('settings.watermarkToggle')}
            <span className="mt-0.5 block text-xs text-slate-500">
              {t('settings.watermarkHint')} <code className="font-mono">{'${email}'}</code>{' '}
              <code className="font-mono">{'${host}'}</code> <code className="font-mono">{'${date}'}</code>{' '}
              <code className="font-mono">{'${time}'}</code>.
            </span>
          </span>
        </label>
        {wm.enabled && (
          <div className="mt-3 space-y-3">
            <label className="block text-xs text-slate-400">
              {t('settings.text')}
              <input
                type="text"
                value={wm.content}
                maxLength={200}
                onChange={(e) => setWm({ ...wm, content: e.target.value })}
                className="mt-1 w-full rounded-lg border border-ink-700 bg-ink-900 px-2.5 py-1.5 font-mono text-sm text-slate-200 focus:border-sky-500 focus:outline-none"
              />
            </label>
            <div className="grid grid-cols-3 gap-3">
              <label className="block text-xs text-slate-400">
                {t('settings.opacity')} <span className="text-slate-500">{wm.opacity.toFixed(2)}</span>
                <input type="range" min={0.02} max={0.5} step={0.01} value={wm.opacity}
                  onChange={(e) => setWm({ ...wm, opacity: parseFloat(e.target.value) })}
                  className="mt-1 w-full accent-sky-600" />
              </label>
              <label className="block text-xs text-slate-400">
                {t('settings.angle')} <span className="text-slate-500">{wm.angle}°</span>
                <input type="range" min={-90} max={90} step={5} value={wm.angle}
                  onChange={(e) => setWm({ ...wm, angle: parseInt(e.target.value, 10) })}
                  className="mt-1 w-full accent-sky-600" />
              </label>
              <label className="block text-xs text-slate-400">
                {t('settings.size')} <span className="text-slate-500">{wm.fontSize}px</span>
                <input type="range" min={8} max={40} step={1} value={wm.fontSize}
                  onChange={(e) => setWm({ ...wm, fontSize: parseInt(e.target.value, 10) })}
                  className="mt-1 w-full accent-sky-600" />
              </label>
            </div>
          </div>
        )}
        <div className="mt-3 flex items-center gap-3">
          <button
            onClick={saveWatermark}
            className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500"
          >
            {t('settings.saveWatermark')}
          </button>
          {wmMsg && <span className="text-xs text-slate-400">{wmMsg}</span>}
        </div>

        </div>)}

        {cat === 'securitate' && (<div>
        {/* ── Cheie de semnare a flotei ── */}
        <h3 className={heading + ' !mt-0'}>{t('settings.signingKey')}</h3>
        <p className="mt-1 text-xs text-slate-500">
          {t('settings.signHintA')} <span className="text-slate-300">{t('settings.signHintYourKey')}</span>{t('settings.signHintB')} <span className="text-slate-300">{t('settings.signHintBeforeEnroll')}</span>{t('settings.signHintC')}
        </p>
        {sign === null ? (
          <div className="mt-2 text-xs text-slate-500">{t('settings.loading')}</div>
        ) : !sign.exists ? (
          <div className="mt-2 flex flex-col gap-2">
            <div className="rounded-lg bg-amber-500/10 p-2.5 text-xs wt-warn ring-1 ring-amber-500/25">
              {t('settings.sign.noKeyYet')}
            </div>
            <div className="flex gap-1 text-sm">
              {([['gen', t('settings.sign.genNewKey')], ['import', t('settings.sign.importExistingKey')]] as const).map(([m, label]) => (
                <button key={m} onClick={() => { setSignMode(m); setSignErr('') }}
                  className={`rounded-lg px-3 py-1.5 ring-1 ${signMode === m
                    ? 'bg-sky-600 text-white ring-sky-600' : 'bg-ink-800 text-slate-300 ring-ink-700 hover:bg-ink-700'}`}>
                  {label}
                </button>
              ))}
            </div>
            {signMode === 'gen' ? (
              <>
                <input type="password" value={signPass} onChange={(e) => setSignPass(e.target.value)}
                  placeholder={t('settings.sign.keyPassPlaceholder')} aria-label={t('settings.sign.keyPass')}
                  autoComplete="new-password" className={field} />
                <input type="password" value={signReauth} onChange={(e) => setSignReauth(e.target.value)}
                  placeholder={t('settings.reauthPlaceholder')} aria-label={t('settings.reauthLabel')}
                  autoComplete="current-password" className={field} />
                <input type="password" value={signPass2} onChange={(e) => setSignPass2(e.target.value)}
                  placeholder={t('settings.sign.confirmPassIfSet')} aria-label={t('settings.sign.confirmKeyPass')}
                  autoComplete="new-password" className={field} />
                <p className="text-[11px] text-slate-500">
                  {t('settings.sign.storageHintA')} <span className="text-slate-300">{t('settings.sign.storageEncrypted')}</span> {t('settings.sign.storageHintB')} <span className="wt-warn">{t('settings.sign.storageInClear')}</span>{t('settings.sign.storageHintC')}
                  <code className="px-1">/data</code> {t('settings.sign.storageHintD')} <span className="text-slate-300">{t('settings.sign.storageWholeFleet')}</span>.
                </p>
                <div>
                  <button disabled={signBusy} onClick={genSigningKey}
                    className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50">
                    {signBusy ? t('settings.generating') : t('settings.sign.genFleetKey')}
                  </button>
                </div>
              </>
            ) : (
              <>
                <p className="text-[11px] text-slate-500">
                  {t('settings.sign.importHintA')} <span className="text-slate-300">{t('settings.sign.importHintAlreadySigned')}</span>{t('settings.sign.importHintB')} <span className="text-slate-300">{t('settings.sign.importHintNoReenroll')}</span>.
                </p>
                <div className="flex items-center gap-2">
                  <button onClick={() => signPemRef.current?.click()}
                    className="rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700">
                    {t('settings.sign.choosePemFile')}
                  </button>
                  <span className="min-w-0 truncate text-xs text-slate-400">{signPemName || t('settings.noFile')}</span>
                  <input ref={signPemRef} type="file" accept=".pem,.key,application/x-pem-file" className="hidden"
                    onChange={async (e) => {
                      const f = e.target.files?.[0]
                      if (f) { setSignPem(await f.text()); setSignPemName(f.name); setSignErr('') }
                    }} />
                </div>
                <input type="password" value={signImpLoadPass} onChange={(e) => setSignImpLoadPass(e.target.value)}
                  placeholder={t('settings.sign.pemPassPlaceholder')} aria-label={t('settings.sign.pemPass')} autoComplete="off" className={field} />
                <input type="password" value={signReauth} onChange={(e) => setSignReauth(e.target.value)}
                  placeholder={t('settings.reauthPlaceholder')} aria-label={t('settings.reauthLabel')}
                  autoComplete="current-password" className={field} />
                <input type="password" value={signImpStorePass} onChange={(e) => setSignImpStorePass(e.target.value)}
                  placeholder={t('settings.sign.storePassPlaceholder')} aria-label={t('settings.sign.storePass')}
                  autoComplete="new-password" className={field} />
                <div>
                  <button disabled={signBusy || !signPem} onClick={importSigningKey}
                    className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50">
                    {signBusy ? t('settings.importing') : t('settings.sign.importKey')}
                  </button>
                </div>
              </>
            )}
          </div>
        ) : (
          <div className="mt-2 flex flex-col gap-2">
            <div className="flex items-center gap-2 text-sm">
              <span className="wt-good">{t('settings.sign.keyPresent')}</span>
              {sign.encrypted && (sign.unlocked
                ? <span className="text-slate-500">{t('settings.sign.encryptedUnlocked')}</span>
                : <span className="wt-warn">{t('settings.sign.encryptedLocked')}</span>)}
              {!sign.encrypted && <span className="text-slate-500">{t('settings.sign.inClearOnServer')}</span>}
            </div>
            {sign.pubkey && (
              <div className="font-mono text-[11px] text-slate-500 break-all">
                {t('settings.sign.fingerprint')} {sign.pubkey.slice(0, 16)}…{sign.pubkey.slice(-8)}
              </div>
            )}
            {/* Întrebarea pe care şi-o pune oricine modifică agentul: „trebuie să semnez ceva?".
                Răspunsul e nu, dar nicăieri nu scria — iar tăcerea aici costă timp pierdut. */}
            <p className="text-[11px] text-slate-500">{t('settings.sign.selfSigns')}</p>
            {sign.encrypted && !sign.unlocked && (
              <div className="flex gap-2">
                <input type="password" value={signUnlockPass} onChange={(e) => setSignUnlockPass(e.target.value)}
                  placeholder={t('settings.sign.keyPassword')} aria-label={t('settings.sign.keyPassword')} autoComplete="off" className={field} />
                <button disabled={signBusy} onClick={unlockSigning}
                  className="shrink-0 rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50">
                  {t('settings.sign.unlock')}
                </button>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              <button onClick={downloadSigningKey} disabled={signBusy}
                className="rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700 disabled:opacity-50">
                {t('settings.downloadEncryptedBackup')}
              </button>
              {sign.encrypted && sign.unlocked && (
                <button onClick={lockSigning}
                  className="rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700">
                  {t('settings.sign.lock')}
                </button>
              )}
            </div>
            {sign.encrypted && sign.unlocked && (
              <p className="text-[11px] text-slate-500">
                {t('settings.sign.unlockedWarning')}
              </p>
            )}
          </div>
        )}
        {signMsg && <div className="mt-2 text-sm wt-good">{signMsg}</div>}
        {signErr && <div className="mt-2 text-sm wt-danger">{signErr}</div>}

        {/* ── Passkeys ── */}
        <h3 className={heading}>{t('settings.passkeys')}</h3>
        <p className="mt-1 text-xs text-slate-500">
          {props.webauthnAvailable
            ? t('settings.passkeysAvailable')
            : t('settings.passkeysUnavailable')}
        </p>
        <div className="mt-2 space-y-1">
          {passkeys.map((p) => (
            <div key={p.id} className="flex items-center justify-between rounded-lg bg-ink-800 px-3 py-2 text-sm">
              <span className="inline-flex items-center gap-2">
                <KeyIcon /> {p.name}
              </span>
              <button onClick={() => remove(p.id)} className="text-xs wt-danger hover:underline">
                {t('settings.delete')}
              </button>
            </div>
          ))}
          {passkeys.length === 0 && <div className="text-xs text-slate-500">{t('settings.noPasskeys')}</div>}
        </div>
        <button
          onClick={addPasskey}
          disabled={busy || !props.webauthnAvailable || !window.PublicKeyCredential}
          className="mt-3 rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50"
        >
          {t('settings.addPasskey')}
        </button>
        {securityErr && <div className="mt-2 text-sm wt-danger">{securityErr}</div>}
        {/* ── 2FA (TOTP) ── */}
        <h3 className={heading}>{t('settings.totp.title')}</h3>
        <p className="mt-1 text-xs text-slate-500">
          {t('settings.totp.hint')}
        </p>

        {totpEnabled && !recoveryCodes && pendingAction === null && (
          <div className="mt-2 space-y-2">
            <div className="flex items-center gap-2 text-sm">
              <span className="wt-good">{t('settings.totp.active')}</span>
              <span className="text-slate-500">{t('settings.totp.recoveryLeft', { n: recoveryLeft })}</span>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => { setPendingAction('regen'); setActionPw('') }}
                className="rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700"
              >
                {t('settings.totp.regen')}
              </button>
              <button
                onClick={() => { setPendingAction('disable'); setActionPw('') }}
                className="rounded-lg bg-ink-800 px-3 py-1.5 text-sm wt-danger ring-1 ring-ink-700 hover:bg-ink-700"
              >
                {t('settings.totp.disable')}
              </button>
            </div>
          </div>
        )}

        {pendingAction !== null && (
          <div className="mt-2 space-y-2">
            <p className="text-xs text-slate-400">
              {pendingAction === 'disable' ? t('settings.confirmDisableWithPass') : t('settings.confirmWithPass')}
            </p>
            <input
              type="password"
              autoFocus
              value={actionPw}
              onChange={(e) => setActionPw(e.target.value)}
              placeholder={t('settings.currentPassword')}
              aria-label={t('settings.currentPassword')}
              autoComplete="current-password"
              className={field}
            />
            <div className="flex gap-2">
              <button
                disabled={busy || !actionPw}
                onClick={runPendingAction}
                className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50"
              >
                {t('settings.confirm')}
              </button>
              <button
                onClick={() => { setPendingAction(null); setActionPw('') }}
                className="rounded-lg px-3 py-1.5 text-sm text-slate-400 hover:bg-ink-800"
              >
                {t('settings.cancel')}
              </button>
            </div>
          </div>
        )}

        {!totpEnabled && !enroll && !recoveryCodes && (
          <button
            onClick={startEnroll}
            className="mt-2 rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700"
          >
            {t('settings.totp.enable')}
          </button>
        )}

        {enroll && (
          <div className="mt-3 space-y-3">
            <p className="text-xs text-slate-400">
              {t('settings.totp.step1')}
            </p>
            <div className="flex flex-col items-center gap-2">
              <img
                src={qrDataUrl(enroll.uri)}
                alt={t('settings.totp.qrAlt')}
                className="rounded-lg bg-white p-2"
                width={180}
                height={180}
              />
              <code className="select-all break-all rounded bg-ink-800 px-2 py-1 font-mono text-xs text-slate-300">
                {enroll.secret}
              </code>
            </div>
            <p className="text-xs text-slate-400">{t('settings.totp.step2')}</p>
            <input
              inputMode="numeric"
              autoComplete="one-time-code"
              value={activateCode}
              onChange={(e) => setActivateCode(e.target.value)}
              placeholder={t('settings.totp.code6')}
              aria-label={t('settings.totp.code6')}
              className={field}
            />
            <div className="flex gap-2">
              <button
                disabled={busy || !activateCode.trim()}
                onClick={confirmEnroll}
                className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50"
              >
                {t('settings.totp.confirmActivate')}
              </button>
              <button
                onClick={() => { setEnroll(null); setActivateCode('') }}
                className="rounded-lg px-3 py-1.5 text-sm text-slate-400 hover:bg-ink-800"
              >
                {t('settings.cancel')}
              </button>
            </div>
          </div>
        )}

        {recoveryCodes && (
          <div className="mt-3 rounded-lg bg-amber-500/10 p-3 ring-1 ring-amber-500/25">
            <p className="text-xs font-medium wt-warn">
              {t('settings.totp.recoveryWarning')}
            </p>
            <div className="mt-2 grid grid-cols-2 gap-1 font-mono text-sm text-slate-200">
              {recoveryCodes.map((c) => (
                <span key={c} className="select-all rounded bg-ink-900 px-2 py-1 text-center">{c}</span>
              ))}
            </div>
            <button
              onClick={() => setRecoveryCodes(null)}
              className="mt-3 rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700"
            >
              {t('settings.totp.savedThem')}
            </button>
          </div>
        )}

        {/* ── Token-uri de automatizare ── */}
        <h3 className={heading}>{t('settings.tokens.title')}</h3>
        <p className="mt-1 text-xs text-slate-500">{t('settings.tokens.hint')}</p>
        {tokPlain && (
          <div className="mt-2 rounded-lg bg-emerald-500/10 p-3 ring-1 ring-emerald-500/30">
            <p className="text-xs text-emerald-300">{t('settings.tokens.copyNow')}</p>
            <code className="mt-1 block break-all rounded bg-ink-900 px-2 py-1 font-mono text-xs text-slate-200">{tokPlain}</code>
          </div>
        )}
        <ul className="mt-2 flex flex-col gap-1">
          {tokens.map((tk) => (
            <li key={tk.id} className="flex items-center gap-2 rounded-lg bg-ink-800/60 px-3 py-2 text-sm ring-1 ring-ink-700">
              <span className="min-w-0 flex-1 truncate text-slate-200">{tk.name}</span>
              <span className="shrink-0 font-mono text-[11px] text-slate-500">{tk.scopes}</span>
              <span className={`shrink-0 text-[11px] ${tk.expired ? 'wt-danger' : 'text-slate-500'}`}>
                {tk.expired ? t('settings.tokens.expired')
                  : t('settings.tokens.expires', { date: fmtTs(tk.expires, 'date') })}
              </span>
              <span className="shrink-0 text-[11px] text-slate-600">
                {tk.last_used ? t('settings.tokens.lastUsed', { when: fmtTs(tk.last_used, 'date') })
                  : t('settings.tokens.neverUsed')}
              </span>
              <button onClick={() => revokeToken(tk)} className="shrink-0 text-xs wt-danger hover:underline">
                {t('settings.tokens.revoke')}
              </button>
            </li>
          ))}
        </ul>
        <form onSubmit={addToken} className="mt-3 flex flex-col gap-2">
          <div className="flex flex-col gap-2 sm:flex-row">
            <input value={newTok.name} onChange={(e) => setNewTok({ ...newTok, name: e.target.value })}
              placeholder={t('settings.tokens.namePlaceholder')} aria-label={t('settings.tokens.name')} className={field} />
            <label className="flex items-center gap-2 text-sm text-slate-400">
              {t('settings.tokens.days')}
              <input type="number" min={1} max={365} value={newTok.days}
                onChange={(e) => setNewTok({ ...newTok, days: Number(e.target.value) })}
                aria-label={t('settings.tokens.days')} className={field + ' w-20'} />
            </label>
          </div>
          <div className="flex flex-wrap items-center gap-4 text-sm text-slate-400">
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={newTok.read}
                onChange={(e) => setNewTok({ ...newTok, read: e.target.checked })} />
              {t('settings.tokens.scopeRead')}
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={newTok.run}
                onChange={(e) => setNewTok({ ...newTok, run: e.target.checked })} />
              {t('settings.tokens.scopeRun')}
            </label>
          </div>
          <input type="password" value={newTok.current_password} autoComplete="current-password"
            onChange={(e) => setNewTok({ ...newTok, current_password: e.target.value })}
            placeholder={t('settings.currentPasswordConfirm')} aria-label={t('settings.currentPassword')} className={field} />
          <div className="flex items-center gap-3">
            <button type="submit" disabled={busy || !newTok.current_password || !newTok.name}
              className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50">
              {t('settings.tokens.create')}
            </button>
            {tokErr && <span className="text-sm wt-danger">{tokErr}</span>}
          </div>
        </form>

        {/* ── Guardrail de comenzi ── */}
        <h3 className={heading}>{t('settings.guardrail')}</h3>
        <label className="mt-2 flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={guard.enabled}
            onChange={(e) => setGuard({ ...guard, enabled: e.target.checked })}
            className="mt-0.5 h-4 w-4 rounded accent-sky-600"
          />
          <span>
            {t('settings.guardrailToggle')}
            <span className="mt-0.5 block text-xs text-slate-500">
              {t('settings.guardrailHint')}
            </span>
          </span>
        </label>
        {guard.enabled && (
          <div className="mt-3 space-y-2">
            {guard.rules.map((r, i) => (
              <div key={i} className="flex items-center gap-2">
                <input
                  type="text"
                  value={r.pattern}
                  spellCheck={false}
                  placeholder={t('settings.guardrailRegexPlaceholder')}
                  onChange={(e) => setGuard({ ...guard, rules: guard.rules.map((x, j) => j === i ? { ...x, pattern: e.target.value } : x) })}
                  className="min-w-0 flex-1 rounded-lg border border-ink-700 bg-ink-900 px-2.5 py-1.5 font-mono text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
                />
                <select
                  value={r.action}
                  aria-label={t('settings.guardrailActionFor', { pattern: r.pattern || String(i + 1) })}
                  onChange={(e) => setGuard({ ...guard, rules: guard.rules.map((x, j) => j === i ? { ...x, action: e.target.value as 'confirm' | 'block' } : x) })}
                  className="shrink-0 rounded-lg border border-ink-700 bg-ink-900 px-2 py-1.5 text-xs text-slate-200"
                >
                  <option value="confirm">{t('settings.guardrailConfirm')}</option>
                  <option value="block">{t('settings.guardrailBlock')}</option>
                </select>
                <button
                  onClick={() => setGuard({ ...guard, rules: guard.rules.filter((_, j) => j !== i) })}
                  aria-label={t('settings.deleteRule')}
                  className="shrink-0 rounded-md px-2 py-1 text-slate-500 hover:bg-ink-800 hover:text-rose-300"
                >✕</button>
              </div>
            ))}
            <button
              onClick={() => setGuard({ ...guard, rules: [...guard.rules, { pattern: '', action: 'confirm' }] })}
              className="text-xs wt-link hover:underline"
            >{t('settings.addRule')}</button>
          </div>
        )}
        <div className="mt-3 flex items-center gap-3">
          <button
            onClick={saveGuard}
            className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500"
          >{t('settings.saveGuardrail')}</button>
          {guardMsg && <span className="text-xs text-slate-400">{guardMsg}</span>}
        </div>
        </div>)}

        {cat === 'audit' && (<div>
        {/* ── Jurnal de audit ── */}
        <h3 className={heading + ' !mt-0'}>{t('settings.audit.title')}</h3>
        <p className="mt-1 text-xs text-slate-500">{t('settings.audit.hint')}</p>

        <div className="mt-3 flex flex-wrap items-center gap-2">
          <input
            value={auditQ}
            onChange={(e) => setAuditQ(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') loadAudit(true) }}
            placeholder={t('settings.audit.searchPlaceholder')}
            aria-label={t('settings.audit.searchAria')}
            spellCheck={false}
            className={field + ' min-w-40 flex-1'}
          />
          <label className="flex items-center gap-2 text-xs text-slate-400">
            <input type="checkbox" checked={auditFailed}
              onChange={(e) => { setAuditFailed(e.target.checked) }} />
            {t('settings.audit.failedOnly')}
          </label>
          <button onClick={() => loadAudit(true)} disabled={auditBusy}
            className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-500 disabled:opacity-50"
          >{t('settings.audit.filter')}</button>
        </div>

        <ul className="mt-3 flex flex-col gap-1">
          {(audit ?? []).map((e, i) => (
            <li key={`${e.ts}-${i}`}
              className="rounded-lg bg-ink-800/60 px-3 py-2 text-xs ring-1 ring-ink-700">
              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                <span className="font-mono tabular-nums text-slate-400">
                  {fmtTs(e.ts)}
                </span>
                {/* respins ≠ reușit: la audit, eșecurile sunt cele mai interesante */}
                <span className={`font-mono ${e.status >= 400 ? 'wt-danger' : 'wt-good'}`}>
                  {e.status}
                </span>
                <span className="font-mono text-slate-300">{e.method} {e.path}</span>
              </div>
              <div className="mt-0.5 flex flex-wrap gap-x-3 text-slate-500">
                <span>{e.actor || t('settings.audit.anonymous')}</span>
                {e.ip && <span className="font-mono">{e.ip}</span>}
                {e.detail && <span className="font-mono text-slate-400">{e.detail}</span>}
              </div>
            </li>
          ))}
        </ul>

        {audit !== null && audit.length === 0 && (
          <p className="mt-3 text-xs text-slate-500">{t('settings.audit.empty')}</p>
        )}
        <div className="mt-3 flex items-center gap-3">
          {!auditEnd && audit !== null && audit.length > 0 && (
            <button onClick={() => loadAudit(false)} disabled={auditBusy}
              className="text-xs wt-link hover:underline disabled:opacity-50"
            >{auditBusy ? t('settings.audit.loading') : t('settings.audit.more')}</button>
          )}
          {auditDays > 0 && (
            <span className="text-xs text-slate-500">{t('settings.audit.retention', { days: auditDays })}</span>
          )}
        </div>
        </div>)}

        {cat === 'notificari' && (<div>
        {/* ── Port forwarding (domeniu) ── */}
        <h3 className={heading}>{t('settings.forward.title')}</h3>
        <p className="mt-1 text-xs text-slate-500">
          {t('settings.forward.hintA')} <span className="font-mono">{t('settings.forward.subdomain')}</span>{t('settings.forward.hintB')} <span className="font-mono">{t('settings.forward.exampleDomain')}</span>{t('settings.forward.hintC')} <span className="font-mono">.env</span>{t('settings.forward.hintD')}
        </p>
        <div className="mt-2 flex flex-col gap-2">
          <div className="flex gap-2">
            <input value={fwdDomain} onChange={(e) => setFwdDomain(e.target.value)}
              placeholder={t('settings.forward.inputPlaceholder')} aria-label={t('settings.forward.ariaLabel')} spellCheck={false}
              className={`${field} font-mono`} />
            <button disabled={fwdBusy} onClick={saveFwd}
              className="shrink-0 rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50">
              {t('settings.save')}
            </button>
            <button disabled={fwdBusy} onClick={() => { setFwdMsg(''); setFwdErr(''); loadFwd() }}
              className="shrink-0 rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700 disabled:opacity-50">
              {t('settings.recheck')}
            </button>
          </div>
          {fwdMsg && <span className="text-sm wt-good">{fwdMsg}</span>}
          {fwdErr && <span className="text-sm wt-danger">{fwdErr}</span>}
          {fwd && (
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
              <span className="flex items-center gap-1.5">
                <span className={`h-2 w-2 rounded-full ${fwd.dns_ok ? 'bg-emerald-500' : 'bg-rose-500'}`} />
                {t('settings.forward.dnsWildcard')} {fwd.dns_ok
                  ? <span className="font-mono text-slate-400">*.{fwd.domain} → {fwd.dns_ip}</span>
                  : <span className="text-slate-500">{t('settings.forward.notResolving')}</span>}
              </span>
              <span className="flex items-center gap-1.5">
                <span className={`h-2 w-2 rounded-full ${fwd.cert_ok ? 'bg-emerald-500' : 'bg-amber-500'}`} />
                {t('settings.forward.certificate')} {fwd.cert_ok ? <span className="text-slate-400">{t('settings.forward.certActive')}</span> : <span className="text-slate-500">{t('settings.forward.certPending')}</span>}
              </span>
            </div>
          )}
          {fwd && fwd.is_custom && !(fwd.dns_ok && fwd.cert_ok) && (
            <div className="rounded-lg border border-ink-700 bg-ink-800/50 p-3 text-xs text-slate-400">
              <p className="mb-1.5 font-medium text-slate-300">{t('settings.forward.toActivateA')} <span className="font-mono">{fwd.domain}</span> {t('settings.forward.toActivateB')}</p>
              <ol className="ml-4 list-decimal space-y-1">
                <li>{t('settings.forward.step1Label')} <span className="font-mono wt-link">*.{fwd.domain}</span> → <span className="font-mono">A {fwd.server_ip || t('settings.forward.ipServerPlaceholder')}</span> (DNS-only)</li>
                <li>{t('settings.forward.step2In')} <span className="font-mono">/opt/webterm/.env</span>: <span className="font-mono wt-link">FORWARD_DOMAIN={fwd.domain}</span> {t('settings.forward.step2TokenA')} <span className="font-mono">.env</span> {t('settings.forward.step2TokenB')}</li>
                <li>Redeploy: <span className="font-mono">cd /opt/webterm &amp;&amp; ./deploy.sh</span> {t('settings.forward.step3Desc')}</li>
              </ol>
            </div>
          )}
        </div>

        {/* ── Alerte pe email (SMTP) ── */}
        <h3 className={heading}>{t('settings.smtp.title')}</h3>
        <p className="mt-1 text-xs text-slate-500">
          {t('settings.smtp.hint')}
        </p>
        <div className="mt-2 flex flex-col gap-2">
          <div className="flex gap-2">
            <input value={smtp.host} onChange={(e) => setSmtp({ ...smtp, host: e.target.value })}
              placeholder={t('settings.smtp.hostPlaceholder')} aria-label={t('settings.smtp.host')} className={field} />
            <input type="number" value={smtp.port} onChange={(e) => setSmtp({ ...smtp, port: +e.target.value })}
              placeholder={t('settings.smtp.portPlaceholder')} aria-label={t('settings.smtp.port')} className={`${field} w-24`} />
          </div>
          <input value={smtp.user} onChange={(e) => setSmtp({ ...smtp, user: e.target.value })}
            placeholder={t('settings.smtp.user')} aria-label={t('settings.smtp.user')} autoComplete="off" className={field} />
          <input type="password" value={smtp.password}
            onChange={(e) => setSmtp({ ...smtp, password: e.target.value })}
            placeholder={smtpHasPw ? t('settings.smtp.passwordSetPlaceholder') : t('settings.smtp.passwordPlaceholder')}
            aria-label={t('settings.smtp.password')} autoComplete="off" className={field} />
          <input value={smtp.from_addr} onChange={(e) => setSmtp({ ...smtp, from_addr: e.target.value })}
            placeholder={t('settings.smtp.from')} aria-label={t('settings.smtp.from')} className={field} />
          <input value={smtp.to_addr} onChange={(e) => setSmtp({ ...smtp, to_addr: e.target.value })}
            placeholder={t('settings.smtp.toPlaceholder')} aria-label={t('settings.smtp.to')} className={field} />
          <label className="flex items-center gap-2 text-sm text-slate-400">
            <input type="checkbox" checked={smtp.starttls}
              onChange={(e) => setSmtp({ ...smtp, starttls: e.target.checked })} />
            {t('settings.smtp.starttls')}
          </label>
          {/* webhook: aceleaşi alerte, dar unde le vezi imediat. Independent de SMTP —
              cine are doar chat nu trebuie să ţină un server de mail. */}
          <input value={smtp.webhook} onChange={(e) => setSmtp({ ...smtp, webhook: e.target.value })}
            placeholder={t('settings.smtp.webhookPlaceholder')} aria-label={t('settings.smtp.webhook')}
            spellCheck={false} className={field} />
          <p className="text-xs text-slate-500">{t('settings.smtp.webhookHint')}</p>
          <div className="flex items-center gap-2">
            <button disabled={busy} onClick={saveSmtp}
              className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50">
              {t('settings.save')}
            </button>
            <button disabled={smtpTesting} onClick={testSmtp}
              className="rounded-lg bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700 disabled:opacity-50">
              {smtpTesting ? t('settings.smtp.sending') : t('settings.smtp.sendTest')}
            </button>
            {smtpMsg && <span className="text-sm wt-good">{smtpMsg}</span>}
            {smtpErr && <span className="text-sm wt-danger">{smtpErr}</span>}
          </div>
        </div>

        {/* ── Alerte pe resurse ── */}
        <h3 className={heading}>{t('settings.alerts.title')}</h3>
        <p className="mt-1 text-xs text-slate-500">
          {t('settings.alerts.hint')}
        </p>
        <div className="mt-2 flex flex-wrap items-center gap-3">
          {([['cpu', 'CPU'], ['mem', 'RAM'], ['disk', t('settings.alerts.disk')]] as const).map(([k, label]) => (
            <label key={k} className="flex items-center gap-2 text-sm text-slate-300">
              <span className="w-10 text-slate-400">{label}</span>
              <input
                type="number"
                min={0}
                max={100}
                value={thresholds[k]}
                aria-label={t('settings.alerts.thresholdAria', { label })}
                onChange={(e) => setThresholds({ ...thresholds, [k]: Math.max(0, Math.min(100, +e.target.value)) })}
                className={`${field} w-20`}
              />
              <span className="text-slate-500">%</span>
            </label>
          ))}
          <button
            disabled={busy}
            onClick={saveThresholds}
            className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-sky-700 disabled:opacity-50"
          >
            {t('settings.alerts.saveThresholds')}
          </button>
          {alertMsg && <span className="text-sm wt-good">{alertMsg}</span>}
        </div>
        </div>)}

        {cat === 'backup' && (<div>
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

        {/* pasul 1: ce trebuie creat la provider — instrucțiunile stau lângă câmpuri,
            nu în documentație, ca să nu ceară alt tab */}
        <div className="mt-3 flex gap-2">
          {(cloud?.providers ?? []).map((p) => (
            <button key={p.id} type="button"
              onClick={() => setCloudForm((f) => ({ ...f, provider: p.id }))}
              className={`wt-touch rounded-lg px-3 py-1.5 text-sm ${
                cloudForm.provider === p.id ? 'bg-sky-600 text-white' : 'bg-ink-800 text-slate-300 hover:bg-ink-700'}`}
            >{p.label}</button>
          ))}
          <button type="button" onClick={() => setCloudHelp(!cloudHelp)}
            className="text-xs wt-link hover:underline">
            {cloudHelp ? t('settings.cloud.hideSteps') : t('settings.cloud.showSteps')}
          </button>
        </div>

        {cloudHelp && (() => {
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

        {/* pasul 2: credențialele aplicației + parola de criptare */}
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
        </div>)}
            </div>

          </div>
        </div>
      </div>
    </div>
  )
}
