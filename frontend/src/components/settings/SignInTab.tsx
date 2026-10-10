import { startRegistration } from '@simplewebauthn/browser'
import qrcode from 'qrcode-generator'
import { useEffect, useState } from 'react'
import { errText, api, Host, withSecondFactor as withSecondFactorT } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { useConfirm } from '../../lib/confirm'
import { fmtTs } from '../../lib/tz'
import { KeyIcon } from '../Icons'
import { copyText } from '../../lib/clipboard'
import { field, heading } from './ui'
import { askSecret } from '../../lib/secretPrompt'
import LoadFailed from '../LoadFailed'
import type { LoadState } from '../../lib/loadable'
import { Button, ErrorState } from '../ui'

interface Passkey {
  id: number
  name: string
  created: number
}

// Autentificare şi 2FA: dispozitivele conectate, passkeys şi 2FA (TOTP) — felul în care intri TU
// în cont. Desprins (3.5.9) din fostul SecurityTab, care amesteca asta cu cheia de semnare,
// token-urile şi guardrail-ul (acelea sunt acum în InfrastructureTab). Logica secţiunilor e mutată
// ca atare; tab-ul îşi ţine starea şi încarcă tot la montare (= la deschiderea secţiunii).
export default function SignInTab(props: { webauthnAvailable: boolean }) {
  const { t } = useI18n()
  // confirm()/prompt() native → dialoguri proprii (vezi lib/confirm.tsx: de ce)
  const { confirm, promptText } = useConfirm()
  const [passkeys, setPasskeys] = useState<Passkey[]>([])
  // U03: „Niciun passkey înregistrat" pe un fetch PICAT linişteşte exact omul care verifică dacă
  // are o a doua cale de intrare. Încărcarea are stările ei: loading / ok / error (+ Reîncearcă).
  const [pkState, setPkState] = useState<LoadState>({ status: 'loading' })
  // erori per secțiune, afișate lângă butonul care le-a produs — modalul e lung
  // și scrollabil, o singură eroare la fund ar fi de multe ori în afara ecranului
  const [securityErr, setSecurityErr] = useState('')
  const [pkMsg, setPkMsg] = useState('')
  const [removingPk, setRemovingPk] = useState<number | null>(null)
  // erorile 2FA lângă secţiunea 2FA (înainte apăreau sub butonul „Adaugă passkey")
  const [totpErr, setTotpErr] = useState('')
  const [busy, setBusy] = useState(false)

  // Dispozitivele conectate. Lipsea calea de mijloc între „schimb parola" (omoară tot,
  // inclusiv sesiunea curentă) şi „intru pe server prin SSH".
  type WebSess = { id: number; label: string; created: number; last_seen: number
                   expires: number; new_device: boolean; current: boolean }
  const [devices, setDevices] = useState<WebSess[] | null>(null)
  // eşecul de încărcare are starea lui: „niciun alt dispozitiv" pe un fetch picat ar linişti
  // exact omul care verifică dacă cineva i-a furat sesiunea
  const [devicesErr, setDevicesErr] = useState<string | null>(null)
  const loadDevices = () => api<WebSess[]>('/api/account/sessions')
    .then((r) => { setDevicesErr(null); setDevices(r) })
    .catch((e) => { setDevicesErr(errText(e, t)); setDevices([]) })
  // Revocările (U03): înainte eroarea era înghiţită — o deconectare EŞUATĂ arăta exact ca una reuşită
  // (lista se reîncărca, dispozitivul rămânea, nimeni nu spunea de ce). Acum: buton ocupat pe rând,
  // eroarea într-o regiune `alert` permanentă, confirmarea DOAR după răspunsul reuşit al serverului.
  const [revoking, setRevoking] = useState<number | 'others' | null>(null)
  const [devMsg, setDevMsg] = useState('')
  const [devErr, setDevErr] = useState('')
  async function revokeDevice(target: number | 'others') {
    if (revoking !== null) return
    setRevoking(target); setDevMsg(''); setDevErr('')
    try {
      if (target === 'others') await api('/api/account/sessions/revoke-others', { method: 'POST' })
      else await api(`/api/account/sessions/${target}`, { method: 'DELETE' })
      setDevMsg(target === 'others' ? t('settings.devicesRevokedOthers') : t('settings.deviceRevoked'))
    } catch (e) {
      setDevErr(errText(e, t) || t('settings.deviceRevokeFailed'))
    } finally {
      setRevoking(null)
      loadDevices()
    }
  }

  // 2FA (TOTP)
  const [totpEnabled, setTotpEnabled] = useState(false)
  const [recoveryLeft, setRecoveryLeft] = useState(0)
  const [enroll, setEnroll] = useState<{ secret: string; uri: string } | null>(null)
  const [enrollPw, setEnrollPw] = useState('')   // M1: re-auth pt. înrolarea 2FA (setup + activate)
  const [activateCode, setActivateCode] = useState('')
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null)
  const [codesCopied, setCodesCopied] = useState(false)
  const [pendingAction, setPendingAction] = useState<'disable' | 'regen' | null>(null)
  const [actionPw, setActionPw] = useState('')

  // „Un singur passkey + hosturi care cer 2FA" e singura combinaţie din care nu te poţi
  // întoarce din interfaţă: pierzi dispozitivul, iar step-up-ul refuză parola cât timp mai
  // există un passkey înrolat. Ieşirea rămâne `app.admin` de pe server — un lucru pe care
  // vrei să-l afli înainte, nu în seara în care s-a întâmplat.
  const [lockoutRisk, setLockoutRisk] = useState(false)
  // starea 2FA necunoscută ≠ „2FA dezactivat": pe un fetch picat NU oferim „Activează 2FA"
  const [totpState, setTotpState] = useState<LoadState>({ status: 'loading' })
  const loadTotp = () =>
    api<{ enabled: boolean; recovery_remaining: number; single_passkey_risk?: boolean }>('/api/totp/status')
      .then((s) => {
        setTotpEnabled(s.enabled); setRecoveryLeft(s.recovery_remaining)
        setLockoutRisk(!!s.single_passkey_risk)
        setTotpState({ status: 'ok' })
      })
      .catch((e) => setTotpState({ status: 'error', error: errText(e, t) }))

  const load = () =>
    api<Passkey[]>('/api/webauthn/credentials')
      .then((r) => { setPasskeys(r); setPkState({ status: 'ok' }) })
      .catch((e) => setPkState({ status: 'error', error: errText(e, t) }))

  // tot ce ţine de autentificare se încarcă la montarea tab-ului (= la deschiderea secţiunii)
  useEffect(() => {
    load()
    loadTotp()
    loadDevices()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function startEnroll() {
    setTotpErr('')
    setRecoveryCodes(null)
    // M1: înrolarea 2FA e schimbare de credențiale — cere parola (ca un cookie furat să nu
    // poată înrola un TOTP atacator). O ținem pentru pasul de activare din acelaşi flux.
    const password = await askSecret(t('settings.totp.enrollPrompt'))
    if (password === null) return
    try {
      const r = await api<{ secret: string; otpauth_uri: string }>('/api/totp/setup', {
        method: 'POST',
        body: JSON.stringify({ current_password: password }),
      })
      setEnrollPw(password)
      setEnroll({ secret: r.secret, uri: r.otpauth_uri })
    } catch (err) {
      setTotpErr(errText(err, t) || t('settings.error'))
    }
  }

  async function confirmEnroll() {
    setTotpErr('')
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
      setTotpErr(errText(err, t) || t('settings.error'))
    } finally {
      setBusy(false)
    }
  }

  async function runPendingAction() {
    setTotpErr('')
    setBusy(true)
    try {
      // Ambele cer al doilea factor (second_gate): dezactivarea 2FA şi regenerarea codurilor de
      // recuperare (codurile noi SUNT un al doilea factor). withSecondFactor cere codul şi reîncearcă.
      if (pendingAction === 'disable') {
        await withSecondFactor((extra) => api('/api/totp/disable', {
          method: 'POST',
          body: JSON.stringify({ current_password: actionPw, ...extra }),
        }))
        setRecoveryCodes(null)
      } else if (pendingAction === 'regen') {
        const r = await withSecondFactor((extra) => api<{ recovery_codes: string[] }>('/api/totp/recovery-codes', {
          method: 'POST',
          body: JSON.stringify({ current_password: actionPw, ...extra }),
        }))
        setRecoveryCodes(r.recovery_codes)
      }
      setPendingAction(null)
      setActionPw('')
      await loadTotp()
    } catch (err) {
      setTotpErr(errText(err, t) || t('settings.error'))
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
    setSecurityErr(''); setPkMsg('')
    // numele se cere ÎNAINTE de ceremonia WebAuthn: după ce credentialul e
    // creat, Cancel la prompt nu mai poate anula nimic — ajungea înregistrat
    // cu numele generic „passkey"
    const name = await promptText({
      title: t('security.passkeyNameTitle'), message: t('settings.passkeyNamePrompt'),
      label: t('security.passkeyNameLabel'),
    })
    if (name === null) return
    // M1: înrolarea unui passkey e o schimbare de credențiale — cerem parola contului
    // ca un cookie furat să nu poată adăuga un factor persistent pe ascuns.
    const password = await askSecret(t('settings.passkeyAddPrompt'))
    if (password === null) return
    setBusy(true)
    try {
      const options = await api<any>('/api/webauthn/register/options', { method: 'POST' })
      const credential = await startRegistration({ optionsJSON: options })
      await withSecondFactor((extra) => api('/api/webauthn/register/verify', {
        method: 'POST',
        body: JSON.stringify({ credential, name: name.trim() || 'passkey', password, ...extra }),
      }))
      setPkMsg(t('settings.passkeyAdded'))
      load()
    } catch (err) {
      if (err instanceof Error && err.name !== 'NotAllowedError') setSecurityErr(err.message)
    } finally {
      setBusy(false)
    }
  }

  // Al doilea factor reactiv — logica a fost extrasă în lib/api.ts când auditul intern a
  // extins second_gate şi la operaţiile de cont (AccountTab o foloseşte şi el acum).
  const withSecondFactor = <T,>(send: (extra: object) => Promise<T>) => withSecondFactorT(t, send)

  async function remove(id: number) {
    // Consecinţa întâi. Ultimul passkey: hosturile cu 2FA cad pe următoarea treaptă a scării de
    // step-up (TOTP dacă e activ, altfel parola). Penultimul: rămâi cu unul singur — dacă vreun
    // host cere 2FA, refolosim avertismentul de blocare (`singlePasskeyWarning`).
    if (passkeys.length === 1) {
      if (!(await confirm({
        title: t('settings.lastPasskeyTitle'),
        message: totpEnabled ? t('settings.lastPasskeyWarnTotp') : t('settings.lastPasskeyWarnPassword'),
        danger: true, confirmLabel: t('settings.delete'),
      }))) return
    } else if (passkeys.length === 2) {
      // fail-SAFE: dacă lista de hosturi nu se poate încărca, NU presupunem „niciun host cu 2FA"
      // (înainte, o eroare devenea listă goală şi sărea avertismentul de blocare exact când nu ştiam) — îl arătăm
      const hosts = await api<Host[]>('/api/hosts').catch(() => null)
      if ((hosts === null || hosts.some((h) => h.require_2fa)) && !(await confirm({
        title: t('settings.lastPasskeyTitle'), message: t('settings.singlePasskeyWarning'),
        danger: true, confirmLabel: t('settings.delete'),
      }))) return
    }
    // M1: scoaterea unui factor rezistent la phishing e schimbare de credențiale — cere parola.
    const password = await askSecret(t('settings.passkeyRemovePrompt'))
    if (password === null) return
    setSecurityErr(''); setPkMsg(''); setRemovingPk(id)
    try {
      await withSecondFactor((extra) => api(`/api/webauthn/credentials/${id}`, {
        method: 'DELETE',
        body: JSON.stringify({ password, ...extra }),
      }))
      setPkMsg(t('settings.passkeyRemoved'))   // DOAR după răspunsul reuşit
    } catch (err) {
      setSecurityErr(errText(err, t) || t('settings.deleteFailed'))
    } finally {
      setRemovingPk(null)
    }
    load()
  }

  return (
    <div>
      <section data-setting-id="devices">
        {/* ── Dispozitive conectate ── */}
        <h3 className={heading + ' !mt-0'}>{t('settings.devices')}</h3>
        <p className="mt-1 text-xs text-slate-500">{t('settings.devicesHint')}</p>
        {devices === null ? (
          <div className="mt-2 text-xs text-slate-500">{t('settings.loading')}</div>
        ) : devicesErr !== null ? (
          <div className="mt-2 rounded-md ring-1 ring-ink-700">
            <LoadFailed compact message={devicesErr} onRetry={() => { setDevices(null); loadDevices() }} />
          </div>
        ) : devices.length === 0 ? (
          <div className="mt-2 text-xs text-slate-500">{t('settings.devicesNone')}</div>
        ) : (
          <div className="mt-2 divide-y divide-ink-800 rounded-md ring-1 ring-ink-700">
            {devices.map((d) => (
              <div key={d.id} className="flex items-center gap-3 px-3 py-2 text-sm">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-slate-200">{d.label}</span>
                    {d.current && (
                      <span className="wt-accent shrink-0 rounded-md bg-sky-500/15 px-1.5 text-2xs">
                        {t('settings.deviceThis')}
                      </span>
                    )}
                    {d.new_device && !d.current && (
                      <span title={t('session.deviceNewTitle')}
                        className="wt-warn shrink-0 rounded-md bg-amber-500/15 px-1.5 text-2xs">
                        {t('session.deviceNew')}
                      </span>
                    )}
                  </div>
                  <div className="mt-0.5 text-2xs text-slate-500">
                    {t('settings.deviceSeen', { when: fmtTs(d.last_seen || d.created) })}
                  </div>
                </div>
                {!d.current && (
                  <Button variant="secondary" size="sm" type="button" className="shrink-0"
                    loading={revoking === d.id} disabled={revoking !== null}
                    aria-label={t('settings.deviceRevokeAria', { device: d.label })}
                    onClick={() => { void revokeDevice(d.id) }}
                  >{t('settings.deviceRevoke')}</Button>
                )}
              </div>
            ))}
          </div>
        )}
        {devices && devicesErr === null && devices.length > 1 && (
          <Button variant="secondary" type="button" className="mt-2"
            loading={revoking === 'others'} disabled={revoking !== null}
            onClick={async () => {
              if (!(await confirm({
                title: t('security.signOutOthersTitle'), message: t('settings.devicesRevokeOthersConfirm'),
                danger: true, confirmLabel: t('security.signOut'),
              }))) return
              await revokeDevice('others')
            }}
          >{t('settings.devicesRevokeOthers')}</Button>
        )}
        {/* regiuni live montate permanent: confirmarea `status`, eroarea `alert` (rămâne până la
            următoarea acţiune — nu un toast care dispare înainte să-l citeşti) */}
        <p role="status" className={devMsg ? 'mt-2 text-sm wt-good' : 'sr-only'}>{devMsg}</p>
        <p role="alert" className={devErr ? 'mt-2 text-sm wt-danger' : 'sr-only'}>{devErr}</p>
      </section>

      <section data-setting-id="passkeys">
        {/* ── Passkeys ── */}
        <h3 className={heading}>{t('settings.passkeys')}</h3>
        <p className="mt-1 text-xs text-slate-500">
          {props.webauthnAvailable
            ? t('settings.passkeysAvailable')
            : t('settings.passkeysUnavailable')}
        </p>
        <div className="mt-2 space-y-1">
          {pkState.status === 'loading' && passkeys.length === 0 && (
            <div className="text-xs text-slate-500">{t('settings.loading')}</div>
          )}
          {pkState.status === 'error' && (
            <div className="rounded-md ring-1 ring-ink-700">
              <ErrorState compact title={t('settings.passkeysLoadFailed')} message={pkState.error}
                onRetry={() => { setPkState({ status: 'loading' }); load() }} />
            </div>
          )}
          {pkState.status !== 'error' && passkeys.map((p) => (
            <div key={p.id} className="flex items-center justify-between rounded-md bg-ink-800 px-3 py-2 text-sm">
              <span className="inline-flex items-center gap-2">
                <KeyIcon /> {p.name}
              </span>
              <Button variant="secondary" size="sm" type="button"
                loading={removingPk === p.id} disabled={removingPk !== null || busy}
                aria-label={t('settings.passkeyDeleteAria', { name: p.name })}
                onClick={() => { void remove(p.id) }}>
                {t('settings.delete')}
              </Button>
            </div>
          ))}
          {pkState.status === 'ok' && passkeys.length === 0 && <div className="text-xs text-slate-500">{t('settings.noPasskeys')}</div>}
          {lockoutRisk && (
            <div className="rounded-md bg-amber-500/10 p-2.5 text-xs wt-warn ring-1 ring-amber-500/25">
              {t('settings.singlePasskeyWarning')}
            </div>
          )}
        </div>
        <Button variant="primary"
          onClick={addPasskey}
          disabled={busy || !props.webauthnAvailable || !window.PublicKeyCredential} className="mt-3">
          {t('settings.addPasskey')}
        </Button>
        <p role="status" className={pkMsg ? 'mt-2 text-sm wt-good' : 'sr-only'}>{pkMsg}</p>
        <p role="alert" className={securityErr ? 'mt-2 text-sm wt-danger' : 'sr-only'}>{securityErr}</p>
      </section>

      <section data-setting-id="totp">
        {/* ── 2FA (TOTP) ── */}
        <h3 className={heading}>{t('settings.totp.title')}</h3>
        <p className="mt-1 text-xs text-slate-500">
          {t('settings.totp.hint')}
        </p>
        {totpState.status === 'loading' && !recoveryCodes && (
          <div className="mt-2 text-xs text-slate-500">{t('settings.loading')}</div>
        )}
        {totpState.status === 'error' && (
          <div className="mt-2 rounded-md ring-1 ring-ink-700">
            <ErrorState compact title={t('settings.totp.loadFailed')} message={totpState.error}
              onRetry={() => { setTotpState({ status: 'loading' }); loadTotp() }} />
          </div>
        )}

        {totpState.status === 'ok' && totpEnabled && !recoveryCodes && pendingAction === null && (
          <div className="mt-2 space-y-2">
            <div className="flex items-center gap-2 text-sm">
              <span className="wt-good">{t('settings.totp.active')}</span>
              <span className="text-slate-500">{t('settings.totp.recoveryLeft', { n: recoveryLeft })}</span>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => { setPendingAction('regen'); setActionPw('') }}
                className="rounded-md bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700"
              >
                {t('settings.totp.regen')}
              </button>
              <button
                onClick={async () => {
                  // consecinţa ÎNAINTE de parolă: scara de step-up e passkey → SSO → TOTP → parolă,
                  // deci fără passkey hosturile cu 2FA rămân doar pe parolă (niciun al doilea factor)
                  if (!(await confirm({
                    title: t('settings.totpDisableTitle'),
                    message: passkeys.length === 0 ? t('settings.totpDisableWarnNoPasskey') : t('settings.totpDisableWarn'),
                    danger: true, confirmLabel: t('settings.totp.disable'),
                  }))) return
                  setPendingAction('disable'); setActionPw('')
                }}
                className="rounded-md bg-ink-800 px-3 py-1.5 text-sm wt-danger ring-1 ring-ink-700 hover:bg-ink-700"
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
              <Button variant="primary"
                disabled={busy || !actionPw}
                onClick={runPendingAction}>
                {t('settings.confirm')}
              </Button>
              <button
                onClick={() => { setPendingAction(null); setActionPw('') }}
                className="rounded-md px-3 py-1.5 text-sm text-slate-400 hover:bg-ink-800"
              >
                {t('settings.cancel')}
              </button>
            </div>
          </div>
        )}

        {totpState.status === 'ok' && !totpEnabled && !enroll && !recoveryCodes && (
          <Button variant="primary"
            onClick={startEnroll} className="mt-2">
            {t('settings.totp.enable')}
          </Button>
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
                className="rounded-md bg-white p-2"
                width={180}
                height={180}
              />
              <code className="select-all break-all rounded-md bg-ink-800 px-2 py-1 font-mono text-xs text-slate-300">
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
              <Button variant="primary"
                disabled={busy || !activateCode.trim()}
                onClick={confirmEnroll}>
                {t('settings.totp.confirmActivate')}
              </Button>
              <button
                onClick={() => { setEnroll(null); setActivateCode('') }}
                className="rounded-md px-3 py-1.5 text-sm text-slate-400 hover:bg-ink-800"
              >
                {t('settings.cancel')}
              </button>
            </div>
          </div>
        )}

        {recoveryCodes && (
          <div className="mt-3 rounded-md bg-amber-500/10 p-3 ring-1 ring-amber-500/25">
            <p className="text-xs font-medium wt-warn">
              {t('settings.totp.recoveryWarning')}
            </p>
            <div className="mt-2 grid grid-cols-2 gap-1 font-mono text-sm text-slate-200">
              {recoveryCodes.map((c) => (
                <span key={c} className="select-all rounded-md bg-ink-900 px-2 py-1 text-center">{c}</span>
              ))}
            </div>
            {/* Copy + .txt: altfel singura cale era selecţia manuală, cod cu cod */}
            <div className="mt-3 flex flex-wrap gap-2">
              <button type="button"
                onClick={() => copyText(recoveryCodes.join('\n')).then((okc) => { if (okc) { setCodesCopied(true); setTimeout(() => setCodesCopied(false), 1500) } })}
                className="rounded-md bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700">
                {codesCopied ? t('settings.cloud.copied') : t('settings.totp.copyCodes')}
              </button>
              <button type="button"
                onClick={() => {
                  const blob = new Blob([recoveryCodes.join('\n') + '\n'], { type: 'text/plain' })
                  const url = URL.createObjectURL(blob)
                  const a = document.createElement('a')
                  a.href = url; a.download = 'webterm-recovery-codes.txt'
                  document.body.appendChild(a); a.click(); a.remove()
                  setTimeout(() => URL.revokeObjectURL(url), 1000)
                }}
                className="rounded-md bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700">
                {t('settings.totp.downloadCodes')}
              </button>
              <button
                onClick={() => setRecoveryCodes(null)}
                className="rounded-md bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700"
              >
                {t('settings.totp.savedThem')}
              </button>
            </div>
          </div>
        )}
        <p role="alert" className={totpErr ? 'mt-2 text-sm wt-danger' : 'sr-only'}>{totpErr}</p>
      </section>
    </div>
  )
}
