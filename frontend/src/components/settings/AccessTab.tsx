import { FormEvent, useEffect, useRef, useState } from 'react'
import { errText, api, Host, withSecondFactor as withSecondFactorT } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { roleBody, roleLabel, ROLE_KEYS, RolesCatalogue, roleValue, ScopeKind, scopeLabel, useSectionVisible } from '../../lib/perms'
import { tokenCap, type TokenRow } from '../../lib/usersAdmin'
import { RETURN_ACCESS, ScopePicker, scopeOk, useAccessReauth, useSelfRow } from './users/shared'
import { useConfirm } from '../../lib/confirm'
import { fmtTs } from '../../lib/tz'
import { ArrowRightIcon } from '../Icons'
import { copyText } from '../../lib/clipboard'
import { downloadBlob, field } from './ui'
import { askSecret } from '../../lib/secretPrompt'
import HelpTip from '../HelpTip'
import { Badge, Button, ErrorState, Field, SegmentedControl, SettingsSection } from '../ui'
import SectionLoading from './SectionLoading'
import { canSave, type LoadState } from '../../lib/loadable'
import NotLoaded from './NotLoaded'

// Acces şi automatizare: cheia de semnare a agenţilor, token-urile de automatizare şi înrolarea în
// bloc (token-uri de grup) — credenţialele prin care maşinile şi scripturile ajung la instanţă.
// Desprins (3.5.9) din fostul SecurityTab ca „Infrastructure & tokens"; în 3.7.1 (auditul UX Setări
// C2) acel sertar de 7 subiecte s-a spart în trei tab-uri, cu logica mutată ca atare: guardrail-ul şi
// politica cheilor de deploy în SecurityPolicyTab, certificatele şi domeniul de forward în NetworkTab.
export default function AccessTab(props: { onAccountChanged: () => void }) {
  const { t } = useI18n()
  const vis = useSectionVisible()   // 3.6: secţiunile fără permisiunea globală nu apar
  // confirm() nativ → dialog propriu (vezi lib/confirm.tsx: de ce)
  const { confirm } = useConfirm()
  const [busy, setBusy] = useState(false)

  // ── Token-uri de automatizare (cron/CI/monitorizare) ──
  // 3.6.10: plafon de rol + scope. Implicit cel mai mic: Viewer peste toate hosturile (fără `run`).
  // Rolurile custom apar doar dacă le poţi citi (/api/roles cere users.manage sau roles.manage).
  const emptyTok = { name: '', read: true, run: false, days: 90, current_password: '',
    role: 'viewer', scope_kind: 'all' as ScopeKind, scope_value: '' }
  const [tokens, setTokens] = useState<TokenRow[]>([])
  const [newTok, setNewTok] = useState(emptyTok)
  const [tokHosts, setTokHosts] = useState<Host[]>([])
  const [tokRoles, setTokRoles] = useState<RolesCatalogue | null>(null)
  const tokHostName = (id: number) => tokHosts.find((h) => h.id === id)?.name
  const roleRuns = (v: string): boolean => {
    if (!v) return true                                    // fără plafon: doar scope-urile decid
    if (!v.startsWith('id:')) return v !== 'viewer'
    return !!tokRoles?.custom.find((r) => roleValue(r) === v)?.perms.includes('run')
  }
  const [tokPlain, setTokPlain] = useState('')     // valoarea în clar, arătată O SINGURĂ dată
  const [tokCopied, setTokCopied] = useState(false)
  const [tokErr, setTokErr] = useState('')
  // RB-03 (3.6.18): /api/tokens trece prin aceeaşi poartă ca o schimbare de acces (parola contului
  // sau, pentru un cont SSO fără parolă, grant passkey / fereastra SSO account-scope), deci planul
  // vine din rândul propriu: câmpul de parolă apare doar când e de folos
  const tokMe = useSelfRow()
  const { plan: tokPlan, reauth: tokReauth } = useAccessReauth(tokMe, { returnTo: RETURN_ACCESS })
  // U04: „niciun token" pe un fetch picat ar ascunde exact credenţiala pe care o cauţi
  const [tokState, setTokState] = useState<LoadState>({ status: 'loading' })
  const loadTokens = () => {
    api<Host[]>('/api/hosts').then(setTokHosts).catch(() => setTokHosts([]))
    api<RolesCatalogue>('/api/roles').then(setTokRoles).catch(() => setTokRoles(null))
    setTokState({ status: 'loading' })
    api<TokenRow[]>('/api/tokens')
      .then((r) => { setTokens(r); setTokState({ status: 'ok' }) })
      .catch((e) => setTokState({ status: 'error', error: errText(e, t) }))
  }

  async function addToken(e: FormEvent) {
    e.preventDefault()
    setTokErr(''); setTokPlain(''); setBusy(true)
    try {
      const scopes = [newTok.read && 'read', newTok.run && 'run'].filter(Boolean) as string[]
      // second_gate: un token e o credenţială persistentă → dacă serverul cere al doilea factor,
      // withSecondFactor cere codul şi reîncearcă (ca la înrolarea unui passkey).
      const r = await tokReauth(t('access.reauth.addToken', { name: newTok.name }),
        (cred) => withSecondFactor((extra) => api<{ token: string; tokens: TokenRow[] }>('/api/tokens', {
          method: 'POST',
          body: JSON.stringify({ name: newTok.name, scopes, days: newTok.days,
                                 ...(newTok.role ? { ...roleBody(newTok.role), scope_kind: newTok.scope_kind,
                                   scope_value: newTok.scope_kind === 'all' ? '' : newTok.scope_value.trim() } : {}),
                                 ...cred, ...extra }),
        })), newTok.current_password)
      if (r === null) { setBusy(false); return }
      setTokens(r.tokens); setTokPlain(r.token)
      setNewTok(emptyTok)
    } catch (e) {
      setTokErr(errText(e, t) || String(e))
    }
    setBusy(false)
  }

  async function revokeToken(tk: TokenRow) {
    if (!(await confirm({
      title: t('security.revokeTokenTitle'), message: t('settings.tokens.revokeConfirm', { name: tk.name }),
      danger: true, confirmLabel: t('security.revoke'),
    }))) return
    try {
      setTokens(await api<TokenRow[]>(`/api/tokens/${tk.id}/revoke`, { method: 'POST' }))
    } catch (e) {
      setTokErr(errText(e, t) || String(e))
    }
  }

  // ── Token-uri de înrolare DE GRUP (onboarding la scară de flotă) ──
  type GroupRow = { id: number; name: string; created: number; expires: number
    max_uses: number; uses: number; folder: string; require_2fa: boolean
    revoked: boolean; expired: boolean; creator_gone?: boolean }
  // Crearea token-urilor de grup s-a mutat în fluxul de onboarding (AddHostModal → „Mai multe
  // maşini"); aici rămâne doar GESTIUNEA credenţialei: listare + revocare.
  const [groups, setGroups] = useState<GroupRow[]>([])
  const [groupErr, setGroupErr] = useState('')
  const [groupState, setGroupState] = useState<LoadState>({ status: 'loading' })
  const loadGroups = () => {
    setGroupState({ status: 'loading' })
    api<GroupRow[]>('/api/enroll-groups')
      .then((r) => { setGroups(r); setGroupState({ status: 'ok' }) })
      .catch((e) => setGroupState({ status: 'error', error: errText(e, t) }))
  }

  async function revokeGroup(g: GroupRow) {
    if (!(await confirm({
      title: t('security.revokeGroupTitle'), message: t('settings.enrollGroups.revokeConfirm', { name: g.name }),
      danger: true, confirmLabel: t('security.revoke'),
    }))) return
    try {
      setGroups(await api<GroupRow[]>(`/api/enroll-groups/${g.id}/revoke`, { method: 'POST' }))
    } catch (e) {
      setGroupErr(errText(e, t) || String(e))
    }
  }

  // Re-auth de securitate pentru backupul cheii de semnare (signing). Parola contului,
  // distinctă de parola de criptare a arhivei.
  const [signReauth, setSignReauth] = useState('')

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
  // un fetch picat lăsa „loading…" pentru totdeauna — acum eroarea cu Reîncearcă
  const [signLoadErr, setSignLoadErr] = useState<string | null>(null)
  const loadSigning = () => {
    setSignLoadErr(null)
    api<SignStatus>('/api/signing/status')
      .then((s) => setSign(s))
      .catch((e) => setSignLoadErr(errText(e, t)))
  }

  async function importSigningKey() {
    setSignErr(''); setSignMsg('')
    if (!signPem.trim()) { setSignErr(t('settings.sign.chooseKeyFile')); return }
    if (signImpStorePass && signImpStorePass.length < 8) { setSignErr(t('settings.sign.storePassMin8')); return }
    if (!(await confirm({
      title: t('security.importKeyTitle'), message: t('settings.sign.importConfirm'),
      confirmLabel: t('security.import'),
    }))) return
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
    if (!(await confirm({
      title: t('security.genKeyTitle'), message: t('settings.sign.genConfirm'),
      confirmLabel: t('security.generate'),
    }))) return
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
    const pass = await askSecret(t('settings.sign.backupPassPrompt'))
    if (pass === null) return
    if (pass.length < 8) { setSignErr(t('settings.passMin8')); return }
    setSignBusy(true)
    try {
      const acct = await askSecret(t('settings.reauthPrompt'))
      if (acct === null) { setSignBusy(false); return }
      await downloadBlob('/api/signing/backup', { passphrase: pass, current_password: acct },
        'webterm-signing-key.wtbk')
      setSignMsg(t('settings.sign.backupDownloaded'))
    } catch (e) { setSignErr(errText(e, t) || t('settings.downloadFailed')) } finally { setSignBusy(false) }
  }

  // tot ce ţine de acces se încarcă la montarea tab-ului (= la deschiderea secţiunii)
  useEffect(() => {
    loadSigning()
    loadTokens()
    loadGroups()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Al doilea factor reactiv — logica a fost extrasă în lib/api.ts când auditul intern a
  // extins second_gate şi la operaţiile de cont (AccountTab o foloseşte şi el acum).
  const withSecondFactor = <T,>(send: (extra: object) => Promise<T>) => withSecondFactorT(t, send)

  // 3.7.1 (audit UX Setări M8/Me1/Me3/Me4): secţiuni-card cu etichete vizibile; fiecare secret e
  // numit explicit (parola cheii ≠ parola ta EverShell); motivul unui buton dezactivat stă lângă el.
  const tokWhy = !newTok.name ? t('settings.tokens.whyName')
    : tokPlan === 'password' && !newTok.current_password ? t('settings.tokens.whyPassword')
    : !!newTok.role && !scopeOk(newTok.scope_kind, newTok.scope_value) ? t('settings.tokens.whyScope') : ''
  return (
    <div className="flex flex-col gap-4">
      {/* ── Cheie de semnare a flotei ── */}
      <SettingsSection data-setting-id="signingKey" hidden={!vis('signingKey')} instanceWide
        title={t('settings.signingKey')} titleExtra={<HelpTip id="signingKey" />}
        description={t('settings.signingKeyDesc')}>
        {sign === null && signLoadErr !== null ? (
          <div className="rounded-md ring-1 ring-ink-700">
            <ErrorState compact title={t('settings.notLoaded')} message={signLoadErr} onRetry={loadSigning} />
          </div>
        ) : sign === null ? (
          <SectionLoading />
        ) : !sign.exists ? (
          <div className="flex flex-col gap-3">
            <div className="rounded-md bg-amber-500/10 p-2.5 text-xs wt-warn ring-1 ring-amber-500/25">
              {t('settings.sign.noKeyYet')}
            </div>
            {/* 3.7.1 (audit UX Setări M7): alegere, nu acţiune — fără umplerea butonului primar */}
            <SegmentedControl label={t('settings.signingKey')} value={signMode} className="self-start"
              onChange={(m) => { setSignMode(m); setSignErr('') }}
              options={[{ value: 'gen', label: t('settings.sign.genNewKey') }, { value: 'import', label: t('settings.sign.importExistingKey') }]} />
            {signMode === 'gen' ? (
              <>
                <Field label={t('settings.sign.keyPass')} hint={t('settings.sign.keyPassHint')}>
                  <input type="password" value={signPass} onChange={(e) => setSignPass(e.target.value)}
                    autoComplete="new-password" className={field} />
                </Field>
                <Field label={t('settings.sign.confirmKeyPass')}>
                  <input type="password" value={signPass2} onChange={(e) => setSignPass2(e.target.value)}
                    autoComplete="new-password" className={field} />
                </Field>
                <Field label={t('settings.backup.yourPassword')}>
                  <input type="password" value={signReauth} onChange={(e) => setSignReauth(e.target.value)}
                    autoComplete="current-password" className={field} />
                </Field>
                <p className="text-xs text-slate-500">{t('settings.sign.storageHint')}</p>
                <div>
                  <Button variant="primary" type="button" loading={signBusy} onClick={genSigningKey}>
                    {t('settings.sign.genFleetKey')}
                  </Button>
                </div>
              </>
            ) : (
              <>
                <p className="text-xs text-slate-500">{t('settings.sign.importHint')}</p>
                <div className="flex items-center gap-2">
                  <Button type="button" variant="secondary" onClick={() => signPemRef.current?.click()}>
                    {t('settings.sign.choosePemFile')}
                  </Button>
                  <span className="min-w-0 truncate text-xs text-slate-400">{signPemName || t('settings.noFile')}</span>
                  <input ref={signPemRef} type="file" accept=".pem,.key,application/x-pem-file" className="hidden"
                    aria-label={t('settings.sign.choosePemFile')}
                    onChange={async (e) => {
                      const f = e.target.files?.[0]
                      if (f) { setSignPem(await f.text()); setSignPemName(f.name); setSignErr('') }
                    }} />
                </div>
                <Field label={t('settings.sign.pemPass')} hint={t('settings.sign.pemPassHint')}>
                  <input type="password" value={signImpLoadPass} onChange={(e) => setSignImpLoadPass(e.target.value)}
                    autoComplete="off" className={field} />
                </Field>
                <Field label={t('settings.sign.storePass')} hint={t('settings.sign.storePassHint')}>
                  <input type="password" value={signImpStorePass} onChange={(e) => setSignImpStorePass(e.target.value)}
                    autoComplete="new-password" className={field} />
                </Field>
                <Field label={t('settings.backup.yourPassword')}>
                  <input type="password" value={signReauth} onChange={(e) => setSignReauth(e.target.value)}
                    autoComplete="current-password" className={field} />
                </Field>
                <div className="flex flex-wrap items-center gap-2">
                  <Button variant="primary" type="button" loading={signBusy} disabled={!signPem} onClick={importSigningKey}
                    aria-describedby={!signPem ? 'sign-import-why' : undefined}>
                    {t('settings.sign.importKey')}
                  </Button>
                  {!signPem && <span id="sign-import-why" className="text-xs text-slate-500">{t('settings.sign.chooseKeyFile')}</span>}
                </div>
              </>
            )}
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <Badge tone="ok" size="md">{t('settings.sign.keyPresent')}</Badge>
              {sign.encrypted && (sign.unlocked
                ? <Badge tone="neutral" size="md">{t('settings.sign.encryptedUnlocked')}</Badge>
                : <Badge tone="warn" size="md">{t('settings.sign.encryptedLocked')}</Badge>)}
            </div>
            {/* 3.7.1 (audit UX Setări Me3): cheia în clar pe server e un RISC, nu o stare neutră — ton de
                avertisment şi, lângă ea, ce poţi face acum (o copie criptată, offline). Criptarea pe loc a
                cheii existente nu are rută în gateway (importul refuză cât timp există o cheie). */}
            {!sign.encrypted && (
              <div className="rounded-md bg-amber-500/10 p-2.5 text-xs wt-warn ring-1 ring-amber-500/25" data-sign-inclear>
                {t('settings.sign.inClearWarning')}
              </div>
            )}
            {sign.pubkey && (
              <div className="font-mono text-2xs text-slate-500 break-all">
                {t('settings.sign.fingerprint')} {sign.pubkey.slice(0, 16)}…{sign.pubkey.slice(-8)}
              </div>
            )}
            {/* Întrebarea pe care şi-o pune oricine modifică agentul: „trebuie să semnez ceva?".
                Răspunsul e nu, dar nicăieri nu scria — iar tăcerea aici costă timp pierdut. */}
            <p className="text-xs text-slate-500">{t('settings.sign.selfSigns')}</p>
            {sign.encrypted && !sign.unlocked && (
              <div className="flex flex-wrap items-end gap-2">
                <Field label={t('settings.sign.keyPassword')} className="min-w-0 flex-1">
                  <input type="password" value={signUnlockPass} onChange={(e) => setSignUnlockPass(e.target.value)}
                    autoComplete="off" className={field} />
                </Field>
                <Button variant="primary" type="button" loading={signBusy} onClick={unlockSigning} className="shrink-0">
                  {t('settings.sign.unlock')}
                </Button>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              {/* 3.7.1 (audit UX Setări M3): numele spune CE se descarcă — nu „backup criptat", ca exportul
                  copiei de siguranţă din Backup, care e alt fişier, cu altă parolă */}
              <Button type="button" variant="secondary" loading={signBusy} onClick={downloadSigningKey}>
                {t('settings.sign.downloadKey')}
              </Button>
              {sign.encrypted && sign.unlocked && (
                <Button type="button" variant="secondary" onClick={lockSigning}>
                  {t('settings.sign.lock')}
                </Button>
              )}
            </div>
            {sign.encrypted && sign.unlocked && (
              <p className="text-xs text-slate-500">
                {t('settings.sign.unlockedWarning')}
              </p>
            )}
          </div>
        )}
        <span role="status" className={signMsg ? 'mt-2 block text-sm wt-good' : 'sr-only'}>{signMsg}</span>
        <span role="alert" className={signErr ? 'mt-2 block text-sm wt-danger' : 'sr-only'}>{signErr}</span>
      </SettingsSection>

      {/* ── Token-uri de automatizare ── */}
      <SettingsSection data-setting-id="tokens" hidden={!vis('tokens')} instanceWide
        title={t('settings.tokens.title')} titleExtra={<HelpTip id="tokens" />}
        description={t('settings.tokens.hint')}>
        {tokPlain && (
          <div role="status" aria-live="polite" className="mb-2 rounded-md bg-emerald-500/10 p-3 ring-1 ring-emerald-500/30">
            <p className="wt-good text-xs">{t('settings.tokens.copyNow')}</p>
            <div className="mt-1 flex items-center gap-2">
              <code className="min-w-0 flex-1 break-all rounded-md bg-ink-900 px-2 py-1 font-mono text-xs text-slate-200">{tokPlain}</code>
              <Button type="button" variant="secondary" size="sm" className="shrink-0"
                onClick={() => copyText(tokPlain).then((okc) => { if (okc) { setTokCopied(true); setTimeout(() => setTokCopied(false), 1500) } })}>
                {tokCopied ? t('settings.cloud.copied') : t('settings.cloud.copy')}
              </Button>
            </div>
          </div>
        )}
        <NotLoaded state={tokState} onRetry={loadTokens} />
        <ul className="flex flex-col gap-1">
          {canSave(tokState) && tokens.map((tk) => (
            <li key={tk.id} className="flex flex-wrap items-center gap-2 rounded-md bg-ink-800/60 px-3 py-2 text-sm ring-1 ring-ink-700">
              <span className="min-w-0 flex-1 truncate text-slate-200">{tk.name}</span>
              <span className="shrink-0 font-mono text-2xs text-slate-500">{tk.scopes}</span>
              {(() => {
                const cap = tokenCap(tk)
                return (
                  <span className="hidden shrink-0 text-2xs text-slate-400 sm:inline" data-token-cap>
                    {cap ? t('roles.chip', { role: roleLabel({ role: cap.role, role_name: cap.role_name }, t),
                      scope: scopeLabel(cap, tokHostName, t) }) : t('settings.tokens.noCap')}
                  </span>
                )
              })()}
              <span className={`shrink-0 text-2xs ${tk.expired ? 'wt-danger' : 'text-slate-500'}`}>
                {tk.expired ? t('settings.tokens.expired')
                  : t('settings.tokens.expires', { date: fmtTs(tk.expires, 'date') })}
              </span>
              <span className="shrink-0 text-2xs text-slate-500">
                {tk.last_used ? t('settings.tokens.lastUsed', { when: fmtTs(tk.last_used, 'date') })
                  : t('settings.tokens.neverUsed')}
              </span>
              <Button type="button" variant="danger" size="sm" className="shrink-0" onClick={() => revokeToken(tk)}
                aria-label={t('settings.tokens.revokeAria', { name: tk.name })}>
                {t('settings.tokens.revoke')}
              </Button>
            </li>
          ))}
        </ul>
        <form onSubmit={addToken} className="mt-4 flex flex-col gap-3 border-t border-ink-700/70 pt-3"
          aria-label={t('settings.tokens.newTitle')}>
          <h4 className="text-sm font-medium text-slate-200">{t('settings.tokens.newTitle')}</h4>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start">
            <Field label={t('settings.tokens.name')} hint={t('settings.tokens.nameHint')} className="min-w-0 flex-1">
              <input value={newTok.name} onChange={(e) => setNewTok({ ...newTok, name: e.target.value })}
                placeholder={t('settings.tokens.namePlaceholder')} className={field} />
            </Field>
            <Field label={t('settings.tokens.days')} className="sm:w-32">
              <input type="number" min={1} max={365} value={newTok.days}
                onChange={(e) => setNewTok({ ...newTok, days: Number(e.target.value) })}
                className={field} />
            </Field>
          </div>
          {/* bife, nu comutatoare: fac parte dintr-un formular trimis cu „Create token" */}
          <fieldset className="flex flex-col gap-1">
            <legend className="text-sm font-medium text-slate-300">{t('settings.tokens.scopes')}</legend>
            <div className="flex flex-wrap items-center gap-4 text-sm text-slate-300">
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
          </fieldset>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start">
            <Field label={t('settings.tokens.role')} className="sm:w-56">
              <select value={newTok.role} className={field} data-token-role
                onChange={(e) => setNewTok({ ...newTok, role: e.target.value })}>
                {ROLE_KEYS.filter((k) => k !== 'owner').map((k) => <option key={k} value={k}>{t('roles.role.' + k)}</option>)}
                {(tokRoles?.custom ?? []).map((r) => <option key={r.id} value={roleValue(r)}>{r.name}</option>)}
                <option value="">{t('settings.tokens.roleNone')}</option>
              </select>
            </Field>
            {newTok.role && (
              <div className="min-w-0 flex-1">
                <ScopePicker idPrefix="token" kind={newTok.scope_kind} value={newTok.scope_value} hosts={tokHosts}
                  onChange={(k, v) => setNewTok({ ...newTok, scope_kind: k, scope_value: v })} />
              </div>
            )}
          </div>
          <p className="text-xs text-slate-500">{t('settings.tokens.roleHint')}</p>
          {newTok.run && !roleRuns(newTok.role) && (
            <p className="text-xs text-warn" data-token-run-warning>{t('settings.tokens.runNeedsRole')}</p>
          )}
          {tokPlan === 'password' && (
            <Field label={t('settings.backup.yourPassword')}>
              <input type="password" value={newTok.current_password} autoComplete="current-password"
                onChange={(e) => setNewTok({ ...newTok, current_password: e.target.value })} className={field} />
            </Field>
          )}
          <div className="flex flex-wrap items-center gap-3">
            <Button variant="primary" type="submit" loading={busy} disabled={!!tokWhy}
              aria-describedby={tokWhy ? 'tok-create-why' : undefined}>
              {t('settings.tokens.create')}
            </Button>
            {tokWhy && <span id="tok-create-why" className="text-xs text-slate-500">{tokWhy}</span>}
            <span role="alert" className={tokErr ? 'text-sm wt-danger' : 'sr-only'}>{tokErr}</span>
          </div>
        </form>
      </SettingsSection>

      {/* ── Token-uri de înrolare DE GRUP (onboarding la scară) ── */}
      <SettingsSection data-setting-id="enrollGroups" hidden={!vis('enrollGroups')} instanceWide
        title={t('settings.enrollGroups.title')} titleExtra={<HelpTip id="enrollGroups" />}
        description={t('settings.enrollGroups.hint')}>
        {/* crearea trăieşte în fluxul de onboarding (+ host → „Mai multe maşini"); aici e doar
            gestiunea credenţialei (listă + revocare), plus un pointer ca s-o găseşti. */}
        <p className="text-xs text-slate-500">{t('settings.enrollGroups.createHint')}</p>
        <NotLoaded state={groupState} onRetry={loadGroups} />
        {canSave(groupState) && groups.length === 0 && (
          <p className="mt-2 text-xs text-slate-500">{t('settings.enrollGroups.none')}</p>
        )}
        <p role="alert" className={groupErr ? 'mt-2 text-sm wt-danger' : 'sr-only'}>{groupErr}</p>
        <ul className="mt-2 flex flex-col gap-1">
          {canSave(groupState) && groups.map((g) => (
            <li key={g.id} className="flex flex-wrap items-center gap-2 rounded-md bg-ink-800/60 px-3 py-2 text-sm ring-1 ring-ink-700">
              <span className="min-w-0 flex-1 truncate text-slate-200">{g.name}
                {g.folder && <span className="ml-1 inline-flex items-center gap-0.5 text-2xs text-slate-500"><ArrowRightIcon size={10} />{g.folder}</span>}
                {g.require_2fa ? (
                  <span className="wt-warn ml-1 text-2xs" title={t('settings.enrollGroups.require2fa')}>
                    2FA<span className="sr-only"> — {t('settings.enrollGroups.require2fa')}</span>
                  </span>
                ) : null}
                {g.creator_gone && !g.revoked && !g.expired ? (
                  <span className="wt-warn ml-1 text-2xs" title={t('settings.enrollGroups.creatorGoneHint')}>
                    {t('settings.enrollGroups.creatorGone')}<span className="sr-only"> — {t('settings.enrollGroups.creatorGoneHint')}</span>
                  </span>
                ) : null}
              </span>
              <span className="shrink-0 text-2xs text-slate-500">
                {t('settings.enrollGroups.uses', { n: g.uses, max: g.max_uses || '∞' })}
              </span>
              <span className={`shrink-0 text-2xs ${g.revoked || g.expired ? 'wt-danger' : 'text-slate-500'}`}>
                {g.revoked ? t('settings.enrollGroups.revoked')
                  : g.expired ? t('settings.tokens.expired')
                    : t('settings.tokens.expires', { date: fmtTs(g.expires, 'date') })}
              </span>
              {!g.revoked && (
                <Button type="button" variant="danger" size="sm" className="shrink-0" onClick={() => revokeGroup(g)}
                  aria-label={t('settings.tokens.revokeAria', { name: g.name })}>
                  {t('settings.tokens.revoke')}
                </Button>
              )}
            </li>
          ))}
        </ul>
      </SettingsSection>
    </div>
  )
}
