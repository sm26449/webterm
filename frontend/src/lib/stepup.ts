/* Ce îi cerem omului la un step-up pe un host (3.5.14).

   Serverul refuză cu un cod stabil (`stepup.passkey` / `stepup.totp` / `stepup.password` /
   `stepup.needsFactor` / `host.needs2faSso`), iar `/api/state` spune dinainte ce factor are
   contul (`stepup_method`). Codul refuzului câştigă (e răspunsul serverului la O cerere
   anume — inclusiv re-auth-ul cu parola pe o ţintă FĂRĂ 2FA la deploy de cheie); fără cod
   (prompt proactiv, înainte de cerere) decidem din metoda contului.

   De ce contează: parola singură NU mai deschide un host 2FA. Un cont fără passkey şi fără
   TOTP primeşte `needsFactor` — UI-ul nu-i mai cere o parolă care oricum ar fi refuzată, ci
   îl trimite la Setări → Autentificare & 2FA. Iar un cont cu TOTP pe un deploy cu WebAuthn
   primeşte direct promptul TOTP, nu o ceremonie passkey sortită eşecului. */

export type StepupMethod = 'passkey' | 'sso' | 'totp' | 'none'
export type StepupPrompt = 'passkey' | 'totp' | 'password' | 'sso' | 'needsFactor'

export function stepupPrompt(
  code: string | undefined | null,
  method: StepupMethod | null | undefined,
  webauthn: boolean,
): StepupPrompt {
  switch (code) {
    case 'stepup.needsFactor': return 'needsFactor'
    case 'stepup.totp': return 'totp'
    case 'stepup.password': return 'password'
    case 'stepup.passkey': return webauthn ? 'passkey' : 'password'
    case 'host.needs2faSso': return 'sso'
  }
  switch (method) {
    case 'passkey': return webauthn ? 'passkey' : 'password'
    case 'totp': return 'totp'
    case 'sso': return 'sso'
    case 'none': return 'needsFactor'
  }
  // gateway mai vechi (fără `stepup_method`): comportamentul de dinainte
  return webauthn ? 'passkey' : 'password'
}

/** Mesajul `locked` de pe WS-ul terminalului poartă (opţional) motivul. `stepup_max` = plafonul
    absolut de 60 min de la factorul care a autorizat terminalul pe un host 2FA. */
export function lockTextKeys(reason: string | undefined | null): { title: string; desc: string } {
  if (reason === 'stepup_max') return { title: 'session.lockedTitleMax', desc: 'session.lockedDescMax' }
  return { title: 'session.lockedTitle', desc: 'session.lockedDesc' }
}

/** Redirect de pagină întreagă la IdP pentru un step-up SSO (acelaşi ca în api() la
    `host.needs2faSso`); întoarcerea restaurează hash-ul curent. */
export function ssoStepupRedirect(hostId: number): void {
  try { sessionStorage.setItem('wt_stepup_return', window.location.hash) } catch { /* */ }
  window.location.href = '/api/oidc/login?intent=stepup&host_id=' + hostId
}
