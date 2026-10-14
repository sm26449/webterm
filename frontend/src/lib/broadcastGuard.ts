import type { CommandGuard, CommandRule } from './api'
import { matchCommandRule } from './commands'

/** Guardrail-ul de comenzi cu broadcast (review independent 3.6.12, M1).

    Un Enter difuzat pleacă în TOATE panourile split-ului, deci comanda verificată trebuie să fie
    cea din fiecare panou-ţintă — iar ea se citeşte din trackerul OSC 133 al panoului, adică din
    ce a ECOU-it deja shell-ul. Două feluri în care trackerul unui panou poate minţi:
      • panoul nu primeşte output (flux pus pe pauză, socket închis, replay în curs) → ce ştim
        despre linia lui e vechi sau lipseşte;
      • tastele tocmai trimise n-au ecou încă (latenţa până la host) → linia citită e cea de
        dinaintea ultimelor taste (ex. ↑ a rechemat o comandă periculoasă pe care n-o vedem încă).
    Ambele = „nu pot verifica" → confirmare explicită (fail-closed), după o scurtă aşteptare a
    ecoului. Fără reguli de guardrail active nu e nimic de verificat. */

/** Ce raportează un panou-ţintă (PaneHandle.state) la momentul unui Enter difuzat. */
export interface PeerState {
  /** tastele NU ajung la host (doar-vizualizare, sesiune încheiată, socket închis, replay în curs):
      Enter-ul acesta nu poate rula nimic acolo */
  inert: boolean
  /** primeşte output live: socket deschis, flux nepauzat, fără replay de istoric în curs */
  live: boolean
  /** shell integration spune „la prompt" (fără ea, guardrail-ul nu poate citi linia — la fel ca
      în panoul de origine, unde Enter trece neverificat) */
  atPrompt: boolean
  /** tot ce i s-a trimis a primit output înapoi (ecou) după trimitere */
  echoed: boolean
  /** comanda tastată acum (OSC 133) sau null */
  pending: string | null
}

export type PeerVerdict =
  | { kind: 'ok' }
  | { kind: 'rule'; rule: CommandRule; cmd: string }
  | { kind: 'wait' }
  | { kind: 'unknown' }

/** cât aşteptăm ecoul tastelor în panourile-ţintă înainte să cerem confirmare (ms) */
export const ECHO_GRACE_MS = 150

export function guardActive(guard: CommandGuard | null | undefined): boolean {
  return !!guard?.enabled && Array.isArray(guard.rules) && guard.rules.length > 0
}

/** Verdictul pentru un Enter difuzat. `prefixFor` transformă linia unui panou înainte de
    verificare (ex. un snippet inserat: linia existentă + prima linie a snippetului).
    `final` = aşteptarea ecoului s-a terminat: un panou încă fără ecou devine `unknown`. */
export function judgePeers(peers: PeerState[], guard: CommandGuard | null | undefined, final: boolean,
  lineOf: (pending: string | null) => string | null = (p) => p): PeerVerdict {
  if (!guardActive(guard)) return { kind: 'ok' }
  const targets = peers.filter((p) => !p.inert)
  // o regulă atinsă câştigă mereu: ştim sigur că linia e periculoasă
  for (const p of targets) {
    const line = lineOf(p.pending)
    const rule = line ? matchCommandRule(line, guard) : null
    if (rule && line) return { kind: 'rule', rule, cmd: line }
  }
  if (targets.some((p) => !p.live)) return { kind: 'unknown' }
  if (targets.some((p) => p.atPrompt && !p.echoed)) return final ? { kind: 'unknown' } : { kind: 'wait' }
  return { kind: 'ok' }
}

/** Liniile unui text care conţine Enter-uri (CR, LF sau CRLF — un paste „cmd\r" execută şi el). */
export function splitLines(text: string): string[] {
  return text.split(/\r\n|\r|\n/)
}

/** Textul conţine un terminator de linie, adică ar EXECUTA ceva într-un shell fără bracketed paste. */
export function submitsLine(text: string): boolean {
  return /[\r\n]/.test(text)
}

/** Un Enter „gol" venit prin onData (IME mobil, keybar, Enter sintetizat), nu prin keydown. */
export function isBareEnter(d: string): boolean {
  return d === '\r' || d === '\n' || d === '\r\n'
}
