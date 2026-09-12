import { startRegistration } from '@simplewebauthn/browser'
import qrcode from 'qrcode-generator'
import { FormEvent, useEffect, useRef, useState } from 'react'
import { errText, api, ApiError, CommandGuard } from '../lib/api'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'
import { fmtTs } from '../lib/tz'
import { KeyIcon } from './Icons'
import { copyText } from '../lib/clipboard'
import { downloadBlob, field, heading } from './settings/ui'
import AuditTab from './settings/AuditTab'
import PreferencesTab from './settings/PreferencesTab'
import AccountTab from './settings/AccountTab'
import AppearanceTab from './settings/AppearanceTab'
import NotificationsTab from './settings/NotificationsTab'
import BackupTab from './settings/BackupTab'

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
  const [securityErr, setSecurityErr] = useState('')
  const [busy, setBusy] = useState(false)
  // Aspect (limbă, temă, schemă de culori, watermark) a fost extras în ./settings/AppearanceTab.

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
  const { t } = useI18n()
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
  const [tokCopied, setTokCopied] = useState(false)
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

  // ── Token-uri de înrolare DE GRUP (onboarding la scară de flotă) ──
  type GroupRow = { id: number; name: string; created: number; expires: number
    max_uses: number; uses: number; folder: string; require_2fa: boolean
    revoked: boolean; expired: boolean }
  // Crearea token-urilor de grup s-a mutat în fluxul de onboarding (AddHostModal → „Mai multe
  // maşini"); aici rămâne doar GESTIUNEA credenţialei: listare + revocare.
  const [groups, setGroups] = useState<GroupRow[]>([])
  const [groupErr, setGroupErr] = useState('')
  const loadGroups = () => api<GroupRow[]>('/api/enroll-groups').then(setGroups).catch(() => {})

  async function revokeGroup(g: GroupRow) {
    if (!window.confirm(t('settings.enrollGroups.revokeConfirm', { name: g.name }))) return
    try {
      setGroups(await api<GroupRow[]>(`/api/enroll-groups/${g.id}/revoke`, { method: 'POST' }))
    } catch (e) {
      setGroupErr(errText(e, t) || String(e))
    }
  }

  // Conturile + schimbarea de cont au fost extrase în ./settings/AccountTab.

  // Re-auth de securitate pentru backupul cheii de semnare (signing). Parola contului,
  // distinctă de parola de criptare a arhivei. Backup/restore + cloud au fost extrase în
  // ./settings/BackupTab (împreună cu bkReauth-ul lor).
  const [signReauth, setSignReauth] = useState('')

  // ── Jurnal de audit (cine/ce/când/de la ce IP pe fiecare acțiune care schimbă ceva) ──
  // Jurnalul de audit a fost extras în ./settings/AuditTab (tab de sine stătător).

  // Notificări (SMTP/webhook, port-forward domain, praguri) au fost extrase în
  // ./settings/NotificationsTab.

  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)

  // Dispozitivele conectate. Lipsea calea de mijloc între „schimb parola" (omoară tot,
  // inclusiv sesiunea curentă) şi „intru pe server prin SSH".
  type WebSess = { id: number; label: string; created: number; last_seen: number
                   expires: number; new_device: boolean; current: boolean }
  const [devices, setDevices] = useState<WebSess[] | null>(null)
  const loadDevices = () => api<WebSess[]>('/api/account/sessions').then(setDevices).catch(() => setDevices([]))

  // 2FA (TOTP)
  const [totpEnabled, setTotpEnabled] = useState(false)
  const [recoveryLeft, setRecoveryLeft] = useState(0)
  const [enroll, setEnroll] = useState<{ secret: string; uri: string } | null>(null)
  const [enrollPw, setEnrollPw] = useState('')   // M1: re-auth pt. înrolarea 2FA (setup + activate)
  const [activateCode, setActivateCode] = useState('')
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null)
  const [pendingAction, setPendingAction] = useState<'disable' | 'regen' | null>(null)
  const [actionPw, setActionPw] = useState('')

  // „Un singur passkey + hosturi care cer 2FA" e singura combinaţie din care nu te poţi
  // întoarce din interfaţă: pierzi dispozitivul, iar step-up-ul refuză parola cât timp mai
  // există un passkey înrolat. Ieşirea rămâne `app.admin` de pe server — un lucru pe care
  // vrei să-l afli înainte, nu în seara în care s-a întâmplat.
  const [lockoutRisk, setLockoutRisk] = useState(false)
  const loadTotp = () =>
    api<{ enabled: boolean; recovery_remaining: number; single_passkey_risk?: boolean }>('/api/totp/status')
      .then((s) => {
        setTotpEnabled(s.enabled); setRecoveryLeft(s.recovery_remaining)
        setLockoutRisk(!!s.single_passkey_risk)
      })
      .catch(() => {})

  // SMTP + port-forward domain au fost extrase în ./settings/NotificationsTab.

  // Backup / restore (arhivă, backup automat, copii stocate, cloud OAuth + SFTP/FTPS direct) au
  // fost extrase în ./settings/BackupTab. `downloadBlob` e acum partajat din ./settings/ui.

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
  const load = () =>
    api<Passkey[]>('/api/webauthn/credentials').then(setPasskeys).catch(() => {})

  useEffect(() => {
    load()
    loadTotp()
    loadSigning()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // listele din Securitate se încarcă LENEȘ (la deschiderea secțiunii). Backup-ul (+ stingerea
  // notificării) se încarcă singur la montarea BackupTab.
  useEffect(() => {
    if (cat === 'securitate' && tokens.length === 0) loadTokens()
    if (cat === 'securitate' && groups.length === 0) loadGroups()
    if (cat === 'securitate' && devices === null) loadDevices()
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
      await withSecondFactor((extra) => api('/api/webauthn/register/verify', {
        method: 'POST',
        body: JSON.stringify({ credential, name: name.trim() || 'passkey', password, ...extra }),
      }))
      load()
    } catch (err) {
      if (err instanceof Error && err.name !== 'NotAllowedError') setSecurityErr(err.message)
    } finally {
      setBusy(false)
    }
  }

  /* Al doilea factor la schimbarea setului de passkey-uri. Îl cerem REACTIV, după refuzul
     serverului: starea locală „am TOTP activ" poate fi veche (activat în alt tab, dezactivat
     de pe server), iar serverul e oricum singurul care decide. O singură reîncercare — dacă
     şi codul e greşit, mesajul serverului e ce trebuie să vadă omul. */
  async function withSecondFactor<T>(send: (extra: object) => Promise<T>): Promise<T> {
    try {
      return await send({})
    } catch (err) {
      if (!(err instanceof ApiError)) throw err
      const key = err.code === 'passkey.totpRequired' ? 'totp_code'
        : err.code === 'account.codeRequired' ? 'email_code' : ''
      if (!key) throw err
      const code = prompt(key === 'totp_code'
        ? t('settings.passkeyCodePrompt')
        : errText(err, t))
      if (code === null) throw err
      return await send({ [key]: code.trim() })
    }
  }

  async function remove(id: number) {
    // M1: scoaterea unui factor rezistent la phishing e schimbare de credențiale — cere parola.
    const password = prompt(t('settings.passkeyRemovePrompt'))
    if (password === null) return
    try {
      await withSecondFactor((extra) => api(`/api/webauthn/credentials/${id}`, {
        method: 'DELETE',
        body: JSON.stringify({ password, ...extra }),
      }))
    } catch (err) {
      setSecurityErr(errText(err, t) || t('settings.deleteFailed'))
    }
    load()
  }

  // `field` / `heading` vin din ./settings/ui (partajate cu tab-urile extrase)

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

        {cat === 'cont' && <AccountTab email={props.email} onAccountChanged={props.onAccountChanged} />}

        {cat === 'preferinte' && <PreferencesTab />}

        {cat === 'aspect' && <AppearanceTab onAccountChanged={props.onAccountChanged} />}

        {cat === 'securitate' && (<div>
        {/* ── Dispozitive conectate ── */}
        <h3 className={heading + ' !mt-0'}>{t('settings.devices')}</h3>
        <p className="mt-1 text-xs text-slate-500">{t('settings.devicesHint')}</p>
        {devices === null ? (
          <div className="mt-2 text-xs text-slate-500">{t('settings.loading')}</div>
        ) : devices.length === 0 ? (
          <div className="mt-2 text-xs text-slate-500">{t('settings.devicesNone')}</div>
        ) : (
          <div className="mt-2 divide-y divide-ink-800 rounded-lg ring-1 ring-ink-700">
            {devices.map((d) => (
              <div key={d.id} className="flex items-center gap-3 px-3 py-2 text-sm">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-slate-200">{d.label}</span>
                    {d.current && (
                      <span className="shrink-0 rounded bg-sky-500/15 px-1.5 text-[10px] text-sky-300">
                        {t('settings.deviceThis')}
                      </span>
                    )}
                    {d.new_device && !d.current && (
                      <span title={t('session.deviceNewTitle')}
                        className="shrink-0 rounded bg-amber-500/15 px-1.5 text-[10px] text-amber-400">
                        {t('session.deviceNew')}
                      </span>
                    )}
                  </div>
                  <div className="mt-0.5 text-[11px] text-slate-500">
                    {t('settings.deviceSeen', { when: fmtTs(d.last_seen || d.created) })}
                  </div>
                </div>
                {!d.current && (
                  <button
                    onClick={async () => {
                      await api(`/api/account/sessions/${d.id}`, { method: 'DELETE' }).catch(() => {})
                      loadDevices()
                    }}
                    className="shrink-0 rounded-md px-2 py-1 text-xs text-rose-400 ring-1 ring-ink-700 hover:bg-ink-800"
                  >{t('settings.deviceRevoke')}</button>
                )}
              </div>
            ))}
          </div>
        )}
        {devices && devices.length > 1 && (
          <button
            onClick={async () => {
              if (!confirm(t('settings.devicesRevokeOthersConfirm'))) return
              await api('/api/account/sessions/revoke-others', { method: 'POST' }).catch(() => {})
              loadDevices()
            }}
            className="mt-2 rounded-lg px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800"
          >{t('settings.devicesRevokeOthers')}</button>
        )}

        {/* ── Cheie de semnare a flotei ── */}
        <h3 className={heading}>{t('settings.signingKey')}</h3>
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
          {lockoutRisk && (
            <div className="rounded-lg bg-amber-500/10 p-2.5 text-xs wt-warn ring-1 ring-amber-500/25">
              {t('settings.singlePasskeyWarning')}
            </div>
          )}
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
          <div role="status" aria-live="polite" className="mt-2 rounded-lg bg-emerald-500/10 p-3 ring-1 ring-emerald-500/30">
            <p className="text-xs text-emerald-300">{t('settings.tokens.copyNow')}</p>
            <div className="mt-1 flex items-center gap-2">
              <code className="min-w-0 flex-1 break-all rounded bg-ink-900 px-2 py-1 font-mono text-xs text-slate-200">{tokPlain}</code>
              <button type="button" onClick={() => copyText(tokPlain).then((okc) => { if (okc) { setTokCopied(true); setTimeout(() => setTokCopied(false), 1500) } })}
                className="shrink-0 text-xs wt-link hover:underline">
                {tokCopied ? t('settings.cloud.copied') : t('settings.cloud.copy')}
              </button>
            </div>
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

        {/* ── Token-uri de înrolare DE GRUP (onboarding la scară) ── */}
        <h3 className={heading}>{t('settings.enrollGroups.title')}</h3>
        <p className="mt-1 text-xs text-slate-500">{t('settings.enrollGroups.hint')}</p>
        {/* crearea trăieşte în fluxul de onboarding (+ host → „Mai multe maşini"); aici e doar
            gestiunea credenţialei (listă + revocare), plus un pointer ca s-o găseşti. */}
        <p className="mt-1 text-xs text-slate-500">{t('settings.enrollGroups.createHint')}</p>
        {groups.length === 0 && (
          <p className="mt-2 text-xs text-slate-600">{t('settings.enrollGroups.none')}</p>
        )}
        {groupErr && <p className="mt-2 text-sm wt-danger">{groupErr}</p>}
        <ul className="mt-2 flex flex-col gap-1">
          {groups.map((g) => (
            <li key={g.id} className="flex items-center gap-2 rounded-lg bg-ink-800/60 px-3 py-2 text-sm ring-1 ring-ink-700">
              <span className="min-w-0 flex-1 truncate text-slate-200">{g.name}
                {g.folder && <span className="ml-1 text-[11px] text-slate-500"><span aria-hidden="true">→ </span>{g.folder}</span>}
                {g.require_2fa ? (
                  <span className="ml-1 text-[11px] text-amber-400" title={t('settings.enrollGroups.require2fa')}>
                    2FA<span className="sr-only"> — {t('settings.enrollGroups.require2fa')}</span>
                  </span>
                ) : null}
              </span>
              <span className="shrink-0 text-[11px] text-slate-500">
                {t('settings.enrollGroups.uses', { n: g.uses, max: g.max_uses || '∞' })}
              </span>
              <span className={`shrink-0 text-[11px] ${g.revoked || g.expired ? 'wt-danger' : 'text-slate-500'}`}>
                {g.revoked ? t('settings.enrollGroups.revoked')
                  : g.expired ? t('settings.tokens.expired')
                    : t('settings.tokens.expires', { date: fmtTs(g.expires, 'date') })}
              </span>
              {!g.revoked && (
                <button onClick={() => revokeGroup(g)} className="shrink-0 text-xs wt-danger hover:underline">
                  {t('settings.tokens.revoke')}
                </button>
              )}
            </li>
          ))}
        </ul>

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

        {cat === 'audit' && <AuditTab />}

        {cat === 'notificari' && <NotificationsTab />}

        {cat === 'backup' && <BackupTab onAccountChanged={props.onAccountChanged} />}
            </div>

          </div>
        </div>
      </div>
    </div>
  )
}
