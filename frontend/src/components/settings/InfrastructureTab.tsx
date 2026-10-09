import { FormEvent, useEffect, useRef, useState } from 'react'
import { errText, api, CommandGuard, DeployKeyPolicy, withSecondFactor as withSecondFactorT } from '../../lib/api'
import { useI18n } from '../../lib/i18n'
import { useSectionVisible } from '../../lib/perms'
import { useConfirm } from '../../lib/confirm'
import { fmtTs } from '../../lib/tz'
import { ArrowRightIcon, CloseIcon } from '../Icons'
import { copyText } from '../../lib/clipboard'
import { downloadBlob, field, heading } from './ui'
import { askSecret } from '../../lib/secretPrompt'
import HelpTip from '../HelpTip'
import { Button } from '../ui'

// Infrastructură şi tokenuri: cheia de semnare a agenţilor, token-urile de automatizare, înrolarea
// în bloc (token-uri de grup), politica cheilor de deploy şi guardrail-ul de comenzi — setări care
// privesc flota şi integrările, nu contul tău. Desprins (3.5.9) din fostul SecurityTab; logica
// secţiunilor e mutată ca atare (passkeys/2FA/dispozitive sunt în SignInTab).
export default function InfrastructureTab(props: { onAccountChanged: () => void }) {
  const { t } = useI18n()
  const vis = useSectionVisible()   // 3.6: secţiunile fără permisiunea globală nu apar
  // confirm() nativ → dialog propriu (vezi lib/confirm.tsx: de ce)
  const { confirm } = useConfirm()
  const [busy, setBusy] = useState(false)

  // Guardrail de comenzi — verificat client-side la Enter (via OSC 133)
  const [guard, setGuard] = useState<CommandGuard>({ enabled: true, rules: [] })
  const [guardMsg, setGuardMsg] = useState('')
  const saveGuard = async () => {
    // Serverul validează cu `re` din Python, terminalul potriveşte cu RegExp din JS: un pattern
    // valid doar în Python (ex. `(?P<n>…)`, `\Z`) trecea la salvare şi era apoi SĂRIT tăcut în
    // terminal. Îl refuzăm aici, numindu-l, ca regula să se comporte la fel peste tot.
    for (const r of guard?.rules ?? []) {
      try { new RegExp(r.pattern, 'i') } catch {
        setGuardMsg(t('settings.guardJsInvalid', { pattern: r.pattern }))
        return
      }
    }
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

  // ── Politica cheilor de deploy (opţională): 2FA pe surse + numai chei restricţionate ──
  const [dkPolicy, setDkPolicy] = useState<DeployKeyPolicy>({ require_2fa_source: false, require_restrict: false })
  const [dkPolicyMsg, setDkPolicyMsg] = useState('')
  const saveDkPolicy = async (next: DeployKeyPolicy) => {
    setDkPolicy(next)
    try {
      await api<DeployKeyPolicy>('/api/settings/deploy-key-policy', { method: 'POST', body: JSON.stringify(next) })
      setDkPolicyMsg(t('settings.saved')); setTimeout(() => setDkPolicyMsg(''), 1500)
    } catch (e) { setDkPolicyMsg(errText(e, t) || t('settings.saveError')) }
  }

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
      // second_gate: un token e o credenţială persistentă → dacă serverul cere al doilea factor,
      // withSecondFactor cere codul şi reîncearcă (ca la înrolarea unui passkey).
      const r = await withSecondFactor((extra) => api<{ token: string; tokens: TokenRow[] }>('/api/tokens', {
        method: 'POST',
        body: JSON.stringify({ name: newTok.name, scopes, days: newTok.days,
                               current_password: newTok.current_password, ...extra }),
      }))
      setTokens(r.tokens); setTokPlain(r.token)
      setNewTok({ name: '', read: true, run: false, days: 90, current_password: '' })
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
    revoked: boolean; expired: boolean }
  // Crearea token-urilor de grup s-a mutat în fluxul de onboarding (AddHostModal → „Mai multe
  // maşini"); aici rămâne doar GESTIUNEA credenţialei: listare + revocare.
  const [groups, setGroups] = useState<GroupRow[]>([])
  const [groupErr, setGroupErr] = useState('')
  const loadGroups = () => api<GroupRow[]>('/api/enroll-groups').then(setGroups).catch(() => {})

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
  const loadSigning = () => api<SignStatus>('/api/signing/status').then(setSign).catch(() => {})

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

  // tot ce ţine de infrastructură se încarcă la montarea tab-ului (= la deschiderea secţiunii)
  useEffect(() => {
    loadSigning()
    loadTokens()
    loadGroups()
    api<CommandGuard>('/api/settings/command-guard').then(setGuard).catch(() => {})
    api<DeployKeyPolicy>('/api/settings/deploy-key-policy').then(setDkPolicy).catch(() => {})
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Al doilea factor reactiv — logica a fost extrasă în lib/api.ts când auditul intern a
  // extins second_gate şi la operaţiile de cont (AccountTab o foloseşte şi el acum).
  const withSecondFactor = <T,>(send: (extra: object) => Promise<T>) => withSecondFactorT(t, send)

  return (
    <div>
      <section data-setting-id="signingKey" hidden={!vis('signingKey')}>
        {/* ── Cheie de semnare a flotei ── */}
        <h3 className={heading + ' !mt-0 flex items-center gap-2'}>{t('settings.signingKey')}<HelpTip id="signingKey" /></h3>
        <p className="mt-1 text-xs text-slate-500">
          {t('settings.signHintA')} <span className="text-slate-300">{t('settings.signHintYourKey')}</span>{t('settings.signHintB')} <span className="text-slate-300">{t('settings.signHintBeforeEnroll')}</span>{t('settings.signHintC')}
        </p>
        {sign === null ? (
          <div className="mt-2 text-xs text-slate-500">{t('settings.loading')}</div>
        ) : !sign.exists ? (
          <div className="mt-2 flex flex-col gap-2">
            <div className="rounded-md bg-amber-500/10 p-2.5 text-xs wt-warn ring-1 ring-amber-500/25">
              {t('settings.sign.noKeyYet')}
            </div>
            <div className="flex gap-1 text-sm">
              {([['gen', t('settings.sign.genNewKey')], ['import', t('settings.sign.importExistingKey')]] as const).map(([m, label]) => (
                <button key={m} onClick={() => { setSignMode(m); setSignErr('') }}
                  className={`rounded-md px-3 py-1.5 ring-1 ${signMode === m
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
                <p className="text-2xs text-slate-500">
                  {t('settings.sign.storageHintA')} <span className="text-slate-300">{t('settings.sign.storageEncrypted')}</span> {t('settings.sign.storageHintB')} <span className="wt-warn">{t('settings.sign.storageInClear')}</span>{t('settings.sign.storageHintC')}
                  <code className="px-1">/data</code> {t('settings.sign.storageHintD')} <span className="text-slate-300">{t('settings.sign.storageWholeFleet')}</span>.
                </p>
                <div>
                  <Button variant="primary" disabled={signBusy} onClick={genSigningKey}>
                    {signBusy ? t('settings.generating') : t('settings.sign.genFleetKey')}
                  </Button>
                </div>
              </>
            ) : (
              <>
                <p className="text-2xs text-slate-500">
                  {t('settings.sign.importHintA')} <span className="text-slate-300">{t('settings.sign.importHintAlreadySigned')}</span>{t('settings.sign.importHintB')} <span className="text-slate-300">{t('settings.sign.importHintNoReenroll')}</span>.
                </p>
                <div className="flex items-center gap-2">
                  <button onClick={() => signPemRef.current?.click()}
                    className="rounded-md bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700">
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
                  <Button variant="primary" disabled={signBusy || !signPem} onClick={importSigningKey}>
                    {signBusy ? t('settings.importing') : t('settings.sign.importKey')}
                  </Button>
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
              <div className="font-mono text-2xs text-slate-500 break-all">
                {t('settings.sign.fingerprint')} {sign.pubkey.slice(0, 16)}…{sign.pubkey.slice(-8)}
              </div>
            )}
            {/* Întrebarea pe care şi-o pune oricine modifică agentul: „trebuie să semnez ceva?".
                Răspunsul e nu, dar nicăieri nu scria — iar tăcerea aici costă timp pierdut. */}
            <p className="text-2xs text-slate-500">{t('settings.sign.selfSigns')}</p>
            {sign.encrypted && !sign.unlocked && (
              <div className="flex gap-2">
                <input type="password" value={signUnlockPass} onChange={(e) => setSignUnlockPass(e.target.value)}
                  placeholder={t('settings.sign.keyPassword')} aria-label={t('settings.sign.keyPassword')} autoComplete="off" className={field} />
                <Button variant="primary" disabled={signBusy} onClick={unlockSigning} className="shrink-0">
                  {t('settings.sign.unlock')}
                </Button>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              <button onClick={downloadSigningKey} disabled={signBusy}
                className="rounded-md bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700 disabled:opacity-50">
                {t('settings.downloadEncryptedBackup')}
              </button>
              {sign.encrypted && sign.unlocked && (
                <button onClick={lockSigning}
                  className="rounded-md bg-ink-800 px-3 py-1.5 text-sm text-slate-300 ring-1 ring-ink-700 hover:bg-ink-700">
                  {t('settings.sign.lock')}
                </button>
              )}
            </div>
            {sign.encrypted && sign.unlocked && (
              <p className="text-2xs text-slate-500">
                {t('settings.sign.unlockedWarning')}
              </p>
            )}
          </div>
        )}
        {signMsg && <div className="mt-2 text-sm wt-good">{signMsg}</div>}
        {signErr && <div className="mt-2 text-sm wt-danger">{signErr}</div>}
      </section>

      <section data-setting-id="tokens" hidden={!vis('tokens')}>
        {/* ── Token-uri de automatizare ── */}
        <h3 className={heading + ' flex items-center gap-2'}>{t('settings.tokens.title')}<HelpTip id="tokens" /></h3>
        <p className="mt-1 text-xs text-slate-500">{t('settings.tokens.hint')}</p>
        {tokPlain && (
          <div role="status" aria-live="polite" className="mt-2 rounded-md bg-emerald-500/10 p-3 ring-1 ring-emerald-500/30">
            <p className="wt-good text-xs">{t('settings.tokens.copyNow')}</p>
            <div className="mt-1 flex items-center gap-2">
              <code className="min-w-0 flex-1 break-all rounded-md bg-ink-900 px-2 py-1 font-mono text-xs text-slate-200">{tokPlain}</code>
              <button type="button" onClick={() => copyText(tokPlain).then((okc) => { if (okc) { setTokCopied(true); setTimeout(() => setTokCopied(false), 1500) } })}
                className="shrink-0 text-xs wt-link hover:underline">
                {tokCopied ? t('settings.cloud.copied') : t('settings.cloud.copy')}
              </button>
            </div>
          </div>
        )}
        <ul className="mt-2 flex flex-col gap-1">
          {tokens.map((tk) => (
            <li key={tk.id} className="flex items-center gap-2 rounded-md bg-ink-800/60 px-3 py-2 text-sm ring-1 ring-ink-700">
              <span className="min-w-0 flex-1 truncate text-slate-200">{tk.name}</span>
              <span className="shrink-0 font-mono text-2xs text-slate-500">{tk.scopes}</span>
              <span className={`shrink-0 text-2xs ${tk.expired ? 'wt-danger' : 'text-slate-500'}`}>
                {tk.expired ? t('settings.tokens.expired')
                  : t('settings.tokens.expires', { date: fmtTs(tk.expires, 'date') })}
              </span>
              <span className="shrink-0 text-2xs text-slate-600">
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
            <Button variant="primary" type="submit" disabled={busy || !newTok.current_password || !newTok.name}>
              {t('settings.tokens.create')}
            </Button>
            {tokErr && <span className="text-sm wt-danger">{tokErr}</span>}
          </div>
        </form>
      </section>

      <section data-setting-id="enrollGroups" hidden={!vis('enrollGroups')}>
        {/* ── Token-uri de înrolare DE GRUP (onboarding la scară) ── */}
        <h3 className={heading + ' flex items-center gap-2'}>{t('settings.enrollGroups.title')}<HelpTip id="enrollGroups" /></h3>
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
            <li key={g.id} className="flex items-center gap-2 rounded-md bg-ink-800/60 px-3 py-2 text-sm ring-1 ring-ink-700">
              <span className="min-w-0 flex-1 truncate text-slate-200">{g.name}
                {g.folder && <span className="ml-1 inline-flex items-center gap-0.5 text-2xs text-slate-500"><ArrowRightIcon size={10} />{g.folder}</span>}
                {g.require_2fa ? (
                  <span className="wt-warn ml-1 text-2xs" title={t('settings.enrollGroups.require2fa')}>
                    2FA<span className="sr-only"> — {t('settings.enrollGroups.require2fa')}</span>
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
                <button onClick={() => revokeGroup(g)} className="shrink-0 text-xs wt-danger hover:underline">
                  {t('settings.tokens.revoke')}
                </button>
              )}
            </li>
          ))}
        </ul>
      </section>

      <section data-setting-id="deployKeyPolicy" hidden={!vis('deployKeyPolicy')}>
        {/* ── Politica cheilor de deploy ── */}
        <h3 className={heading + ' flex items-center gap-2'}>{t('settings.dkpolicy.title')}<HelpTip id="deployKeyPolicy" /></h3>
        <p className="mt-1 text-xs text-slate-500">{t('settings.dkpolicy.hint')}</p>
        <label className="mt-2 flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
          <input type="checkbox" checked={dkPolicy.require_2fa_source} className="mt-0.5 h-4 w-4 rounded-md accent-sky-600"
            onChange={(e) => saveDkPolicy({ ...dkPolicy, require_2fa_source: e.target.checked })} />
          <span>{t('settings.dkpolicy.require2fa')}
            <span className="mt-0.5 block text-xs text-slate-500">{t('settings.dkpolicy.require2faHint')}</span></span>
        </label>
        <label className="mt-2 flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
          <input type="checkbox" checked={dkPolicy.require_restrict} className="mt-0.5 h-4 w-4 rounded-md accent-sky-600"
            onChange={(e) => saveDkPolicy({ ...dkPolicy, require_restrict: e.target.checked })} />
          <span>{t('settings.dkpolicy.requireRestrict')}
            <span className="mt-0.5 block text-xs text-slate-500">{t('settings.dkpolicy.requireRestrictHint')}</span></span>
        </label>
        {dkPolicyMsg && <div className="mt-1 text-xs text-slate-500">{dkPolicyMsg}</div>}
      </section>

      <section data-setting-id="guardrail" hidden={!vis('guardrail')}>
        {/* ── Guardrail de comenzi ── */}
        <h3 className={heading + ' flex items-center gap-2'}>{t('settings.guardrail')}<HelpTip id="guardrail" /></h3>
        <label className="mt-2 flex cursor-pointer items-start gap-2.5 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={guard.enabled}
            onChange={(e) => setGuard({ ...guard, enabled: e.target.checked })}
            className="mt-0.5 h-4 w-4 rounded-md accent-sky-600"
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
                  className="min-w-0 flex-1 rounded-md border border-ink-700 bg-ink-900 px-2.5 py-1.5 font-mono text-xs text-slate-200 focus:border-sky-500 focus:outline-none"
                />
                <select
                  value={r.action}
                  aria-label={t('settings.guardrailActionFor', { pattern: r.pattern || String(i + 1) })}
                  onChange={(e) => setGuard({ ...guard, rules: guard.rules.map((x, j) => j === i ? { ...x, action: e.target.value as 'confirm' | 'block' } : x) })}
                  className="shrink-0 rounded-md border border-ink-700 bg-ink-900 px-2 py-1.5 text-xs text-slate-200"
                >
                  <option value="confirm">{t('settings.guardrailConfirm')}</option>
                  <option value="block">{t('settings.guardrailBlock')}</option>
                </select>
                <button
                  onClick={() => setGuard({ ...guard, rules: guard.rules.filter((_, j) => j !== i) })}
                  aria-label={t('settings.deleteRule')}
                  className="shrink-0 rounded-md px-2 py-1 text-slate-500 hover:bg-ink-800 hover:text-danger"
                ><CloseIcon size={14} /></button>
              </div>
            ))}
            <button
              onClick={() => setGuard({ ...guard, rules: [...guard.rules, { pattern: '', action: 'confirm' }] })}
              className="text-xs wt-link hover:underline"
            >{t('settings.addRule')}</button>
          </div>
        )}
        <div className="mt-3 flex items-center gap-3">
          <Button variant="primary"
            onClick={saveGuard}>{t('settings.saveGuardrail')}</Button>
          {guardMsg && <span className="text-xs text-slate-400">{guardMsg}</span>}
        </div>
      </section>
    </div>
  )
}
