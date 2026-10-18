/* RB-03 (audit 2026-10-17): re-autentificarea la o schimbare de acces pentru conturile SSO.
   Tabelul de decizie al lui `withAccessReauth` + cheile de pe pagina de login (FL-07). */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { accessReauthPlan, ApiError, reauthQuestion, SETTINGS_RETURN_KEY, withAccessReauth } from './api'
import { registerSecretPrompt } from './secretPrompt'
import { ssoErrorKey } from '../components/LoginPage'
import en from '../lang/en'
import ro from '../lang/ro'

const cat = (c: unknown) => ((c as { strings?: Record<string, string> }).strings ?? c) as Record<string, string>
const t = (k: string, v?: Record<string, string | number>) => {
  let s = cat(en)[k] ?? k
  for (const [a, b] of Object.entries(v ?? {})) s = s.split('{' + a + '}').join(String(b))
  return s
}
const ssoReauth = () => new ApiError(403, 're-authenticate with SSO or a passkey to change access', 'account.ssoReauth')
const PROMPT = 'Remove Operator from a@x? It takes effect immediately.\n\nConfirm with YOUR password:'

describe('accessReauthPlan: ce îi cerem omului', () => {
  it('fără rând propriu sau cont local → parola (403-ul rămâne plasa)', () => {
    expect(accessReauthPlan(undefined, true)).toBe('password')
    expect(accessReauthPlan(null, true)).toBe('password')
    expect(accessReauthPlan({ sso: false, local_password: true, passkeys: 2 }, true)).toBe('password')
  })
  it('cont SSO cu passkey şi WebAuthn în browser → passkey account-scope', () => {
    expect(accessReauthPlan({ sso: true, local_password: false, passkeys: 1 }, true)).toBe('passkey')
  })
  it('cont SSO fără passkey (sau fără WebAuthn aici) → step-up SSO; parola locală nu contează (serverul o ignoră)', () => {
    expect(accessReauthPlan({ sso: true, local_password: false, passkeys: 0 }, true)).toBe('sso')
    expect(accessReauthPlan({ sso: true, local_password: false, passkeys: 1 }, false)).toBe('sso')
    expect(accessReauthPlan({ sso: true, local_password: true, passkeys: 0 }, true)).toBe('sso')
  })
  it('rută doar-cu-parolă (/api/tokens): parola pentru oricine — nici grantul, nici fereastra SSO nu trec acolo', () => {
    expect(accessReauthPlan({ sso: true, local_password: true, passkeys: 1 }, true, true)).toBe('password')
    expect(accessReauthPlan({ sso: true, local_password: true, passkeys: 0 }, true, true)).toBe('password')
    // SSO-only: câmpul + motivul, nu o promisiune de passkey pe care ruta n-o acceptă (corecţia RB-03)
    expect(accessReauthPlan({ sso: true, local_password: false, passkeys: 1 }, true, true)).toBe('password')
    expect(accessReauthPlan({ sso: true, local_password: false, passkeys: 0 }, true, true)).toBe('password')
    expect(accessReauthPlan({ sso: false, local_password: true }, true, true)).toBe('password')
  })
  it('cont SSO cu TOTP: step-up SSO chiar dacă are passkey (grantul single-use s-ar arde înainte de second_gate)', () => {
    expect(accessReauthPlan({ sso: true, passkeys: 1, totp: true }, true)).toBe('sso')
    expect(accessReauthPlan({ sso: true, passkeys: 0, totp: true }, true)).toBe('sso')
    expect(accessReauthPlan({ sso: true, passkeys: 1, totp: false }, true)).toBe('passkey')
    // TOTP nu schimbă nimic pentru un cont local (parola + second_gate, ca înainte)
    expect(accessReauthPlan({ sso: false, passkeys: 1, totp: true }, true)).toBe('password')
  })
})

describe('reauthQuestion: promptul de parolă devine întrebare', () => {
  it('taie doar ultimul paragraf când e instrucţiunea de parolă', () => {
    expect(reauthQuestion(PROMPT)).toBe('Remove Operator from a@x? It takes effect immediately.')
    expect(reauthQuestion('Delete the role x?')).toBe('Delete the role x?')
    expect(reauthQuestion('Line one.\n\nLine two.')).toBe('Line one.\n\nLine two.')
  })
  it('toate prompturile de confirmare din catalog (en + ro) se termină cu linia de parolă', () => {
    for (const dict of [cat(en), cat(ro)]) {
      for (const k of ['roles.bindings.removeConfirm', 'roles.expiry.permanentConfirm', 'settings.users.deleteConfirm',
        'settings.users.reenableConfirm', 'roles.custom.createConfirm', 'roles.custom.saveConfirm',
        'roles.custom.deleteConfirm', 'roles.sso.addConfirm', 'roles.sso.removeConfirm',
        'access.reauth.addAccount', 'access.reauth.addToken', 'access.reauth.removeLocalPw']) {
        expect(reauthQuestion(dict[k]), k).not.toBe(dict[k])
      }
    }
  })
})

describe('withAccessReauth', () => {
  let asked: string[] = []
  let answer: string | null = 'secret'
  beforeEach(() => {
    asked = []
    answer = 'secret'
    registerSecretPrompt(async (ask) => { asked.push(ask.title); return answer })
  })
  afterEach(() => registerSecretPrompt(null))

  it('cont local: parola prin askSecret, ca înainte; anularea întoarce null fără cerere', async () => {
    const send = vi.fn(async (cred: object) => cred)
    expect(await withAccessReauth(t, PROMPT, send, { me: { sso: false }, webauthn: true })).toEqual({ current_password: 'secret' })
    expect(asked).toEqual([PROMPT])
    answer = null
    expect(await withAccessReauth(t, PROMPT, send, { me: { sso: false } })).toBeNull()
    expect(send).toHaveBeenCalledTimes(1)
  })
  it('parola tastată inline (Add account / token) nu mai deschide promptul', async () => {
    const send = vi.fn(async (cred: object) => cred)
    expect(await withAccessReauth(t, PROMPT, send, { me: null, password: 'typed' })).toEqual({ current_password: 'typed' })
    expect(asked).toEqual([])
  })
  it('cont SSO-only fără passkey: NICIUN prompt de parolă; confirmă, trimite direct (fereastra deschisă după întoarcere)', async () => {
    const confirm = vi.fn(async (_q: string) => true)
    const send = vi.fn(async (cred: object) => ({ ok: true, cred }))
    const r = await withAccessReauth(t, PROMPT, send, { me: { sso: true, passkeys: 0 }, webauthn: true, confirm })
    expect(asked).toEqual([])
    expect(r).toEqual({ ok: true, cred: {} })
    const q = confirm.mock.calls[0][0] as string
    expect(q.startsWith('Remove Operator from a@x? It takes effect immediately.')).toBe(true)
    expect(q.endsWith(t('access.reauth.viaSso'))).toBe(true)
    expect(q).not.toContain('password:')
  })
  it('cont SSO-only: 403 account.ssoReauth → redirect la step-up SSO account-scope, nu text de eroare', async () => {
    const redirect = vi.fn()
    const send = vi.fn(async () => { throw ssoReauth() })
    const r = await withAccessReauth(t, PROMPT, send, { me: { sso: true, passkeys: 0 }, webauthn: true, redirect })
    expect(r).toBeNull()
    expect(redirect).toHaveBeenCalledTimes(1)
    expect(asked).toEqual([])
  })
  it('history.ssoReauth (DELETE /api/history are codul lui) → acelaşi drum SSO (RB-03, 3.6.19)', async () => {
    const redirect = vi.fn()
    const send = vi.fn(async () => { throw new ApiError(403, 're-authenticate with SSO or a passkey to clear the command history', 'history.ssoReauth') })
    const r = await withAccessReauth(t, PROMPT, send, { me: { sso: true, passkeys: 0 }, webauthn: true, redirect })
    expect(r).toBeNull()
    expect(redirect).toHaveBeenCalledTimes(1)
  })

  it('refuzul confirmării opreşte totul (nici cerere, nici redirect)', async () => {
    const send = vi.fn()
    const redirect = vi.fn()
    expect(await withAccessReauth(t, PROMPT, send, { me: { sso: true }, confirm: async () => false, redirect })).toBeNull()
    expect(send).not.toHaveBeenCalled()
    expect(redirect).not.toHaveBeenCalled()
  })
  it('cont SSO cu passkey şi TOTP: fără ceremonie (ar fi irosită) — trimite direct, 403 → SSO', async () => {
    const passkey = vi.fn(async () => 'grant-1')
    const redirect = vi.fn()
    const send = vi.fn(async () => { throw ssoReauth() })
    expect(await withAccessReauth(t, PROMPT, send, { me: { sso: true, passkeys: 1, totp: true }, webauthn: true, passkey, redirect })).toBeNull()
    expect(passkey).not.toHaveBeenCalled()
    expect(send).toHaveBeenCalledWith({})
    expect(redirect).toHaveBeenCalledTimes(1)
  })
  it('înainte de redirect reţine panoul Settings de redeschis (returnTo), ca App să-l refacă la ?stepup=ok', async () => {
    const store = new Map<string, string>()
    vi.stubGlobal('sessionStorage', {
      setItem: (k: string, v: string) => { store.set(k, v) },
      removeItem: (k: string) => { store.delete(k) },
      getItem: (k: string) => store.get(k) ?? null,
    })
    try {
      const redirect = vi.fn()
      const send = vi.fn(async () => { throw ssoReauth() })
      expect(await withAccessReauth(t, PROMPT, send, { me: { sso: true }, redirect, returnTo: { cat: 'utilizatori' } })).toBeNull()
      expect(redirect).toHaveBeenCalledTimes(1)
      expect(JSON.parse(store.get(SETTINGS_RETURN_KEY) ?? 'null')).toEqual({ cat: 'utilizatori' })
      // fără returnTo nu rămâne o ţintă veche în urmă
      expect(await withAccessReauth(t, PROMPT, send, { me: { sso: true }, redirect })).toBeNull()
      expect(store.has(SETTINGS_RETURN_KEY)).toBe(false)
    } finally {
      vi.unstubAllGlobals()
    }
  })
  it('cont SSO cu passkey: ceremonia account-scope → stepup_grant în corp', async () => {
    const passkey = vi.fn(async () => 'grant-1')
    const send = vi.fn(async (cred: object) => cred)
    const r = await withAccessReauth(t, PROMPT, send, { me: { sso: true, passkeys: 1 }, webauthn: true, passkey })
    expect(r).toEqual({ stepup_grant: 'grant-1' })
    expect(asked).toEqual([])
  })
  it('passkey anulată (null) → null; ceremonia eşuată (\'\') → cererea pleacă fără grant şi 403-ul duce la SSO', async () => {
    const send = vi.fn(async () => { throw ssoReauth() })
    const redirect = vi.fn()
    expect(await withAccessReauth(t, PROMPT, send, { me: { sso: true, passkeys: 1 }, webauthn: true, passkey: async () => null, redirect })).toBeNull()
    expect(send).not.toHaveBeenCalled()
    expect(await withAccessReauth(t, PROMPT, send, { me: { sso: true, passkeys: 1 }, webauthn: true, passkey: async () => '', redirect })).toBeNull()
    expect(send).toHaveBeenCalledWith({})
    expect(redirect).toHaveBeenCalledTimes(1)
  })
  it('rând necunoscut + cont de fapt SSO: parola e cerută (ca înainte), dar 403-ul merge la SSO în loc de text', async () => {
    const redirect = vi.fn()
    const send = vi.fn(async () => { throw ssoReauth() })
    expect(await withAccessReauth(t, PROMPT, send, { me: undefined, redirect })).toBeNull()
    expect(asked).toEqual([PROMPT])
    expect(redirect).toHaveBeenCalledTimes(1)
  })
  it('serverul a verificat totuşi o parolă (401 wrongPassword pe plan SSO) → o cerem o singură dată', async () => {
    let n = 0
    const send = vi.fn(async (cred: object) => {
      n++
      if (n === 1) throw new ApiError(401, 'wrong password', 'auth.wrongPassword')
      return cred
    })
    const r = await withAccessReauth(t, PROMPT, send, { me: { sso: true, passkeys: 0 }, webauthn: true })
    expect(r).toEqual({ current_password: 'secret' })
    expect(asked).toEqual([PROMPT])
  })
  it('passwordGate + parola inline (formularul de token): cont SSO cu parolă locală → nicio ceremonie, niciun dialog', async () => {
    const passkey = vi.fn(async () => 'grant-x')
    const confirm = vi.fn(async () => true)
    const send = vi.fn(async (cred: object) => cred)
    const me = { sso: true, local_password: true, passkeys: 1 }
    expect(await withAccessReauth(t, PROMPT, send, { me, webauthn: true, password: 'typed', passwordGate: true, passkey, confirm }))
      .toEqual({ current_password: 'typed' })
    expect(passkey).not.toHaveBeenCalled()
    expect(confirm).not.toHaveBeenCalled()
    expect(asked).toEqual([])
    // SSO-only pe aceeaşi rută: tot parola (câmpul inline), nicio ceremonie care să se termine în 401
    expect(await withAccessReauth(t, PROMPT, send, { me: { sso: true, passkeys: 1 }, webauthn: true, password: 'typed', passwordGate: true, passkey, confirm }))
      .toEqual({ current_password: 'typed' })
    expect(passkey).not.toHaveBeenCalled()
    // acelaşi cont pe o rută cu poarta completă: passkey-ul, ca până acum
    expect(await withAccessReauth(t, PROMPT, send, { me, webauthn: true, passkey, confirm })).toEqual({ stepup_grant: 'grant-x' })
  })
  it('alte erori trec mai departe neatinse (le arată panoul)', async () => {
    const send = vi.fn(async () => { throw new ApiError(409, 'in use', 'role.inUse') })
    await expect(withAccessReauth(t, PROMPT, send, { me: { sso: true } })).rejects.toMatchObject({ code: 'role.inUse' })
  })
})

describe('FL-07: pagina de login la un IdP căzut', () => {
  it('sso_error=unavailable are mesajul lui (break-glass), nu „încearcă din nou sau foloseşte parola"', () => {
    expect(ssoErrorKey('unavailable')).toBe('login.ssoUnavailable')
    expect(ssoErrorKey('disabled')).toBe('login.ssoDisabled')
    expect(ssoErrorKey('denied')).toBe('login.ssoError')
    expect(ssoErrorKey(null)).toBe('login.ssoError')
  })
  it('mesajul numeşte calea de break-glass din docs şi nu pomeneşte parola ca soluţie', () => {
    for (const dict of [cat(en), cat(ro)]) {
      expect(dict['login.ssoUnavailable']).toContain('docs/SSO.md')
      expect(dict['login.ssoUnavailable']).toContain('Break-glass')
      expect(dict['access.reauth.viaSso']).toMatch(/Settings|Setările/)
      expect(dict['login.ssoUnreachable']).toBeTruthy()
    }
  })
})
