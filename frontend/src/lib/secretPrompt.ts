/* Prompt pentru secrete (parole de cont, passphrase-uri, coduri 2FA), în locul lui
   window.prompt(): acela afişa parola în CLAR pe ecran — o regresie de shoulder-surfing faţă
   de orice alt câmp de parolă din aplicaţie (toate type="password"). Semnalat de auditul de
   UI/accesibilitate (2026-09-23).

   Acelaşi tipar ca notify/registerToast: App înregistrează gazda (un modal cu input mascat,
   focus-trap, Escape), iar apelanţii — inclusiv cod non-React din lib/ — cheamă `askSecret()`
   şi primesc un Promise. Fără gazdă înregistrată (fereastră popout, teste) cădem înapoi pe
   window.prompt: mai bine un prompt nemascat decât un flux de re-autentificare blocat. */
export type SecretAsk = { title: string; masked: boolean }

let host: ((ask: SecretAsk) => Promise<string | null>) | null = null

export function registerSecretPrompt(fn: ((ask: SecretAsk) => Promise<string | null>) | null): void {
  host = fn
}

/** `masked` implicit true (parole). Codurile scurte cu viaţă de 30s (TOTP/email) pot cere
    `masked: false` — să vezi ce tastezi ajută, iar riscul de umăr e minim. */
export function askSecret(title: string, opts?: { masked?: boolean }): Promise<string | null> {
  const ask: SecretAsk = { title, masked: opts?.masked !== false }
  if (host) return host(ask)
  return Promise.resolve(window.prompt(title))
}
