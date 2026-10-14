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
  /** `atPrompt` / `pending` sunt de crezut (CommandTracker.lineKnown). false = panou CU shell
      integration, fără comandă în curs, pe ecranul principal, dar după un replay de istoric
      (ataşare, reconectare, reluarea unui panou de telefon) fără prompt live de atunci — sau între
      Enter şi următorul prompt. Atunci „nu e la prompt" NU înseamnă „fără shell integration":
      linia poate fi o comandă rechemată pe care n-o vedem (re-review 3.6.12, M1). */
  known: boolean
  /** numele panoului, arătat în dialogul regulii (titlul sesiunii / hostul) */
  label?: string
}

/** O linie care atinge o regulă, cu panourile în care s-ar rula (aceeaşi linie în mai multe panouri
    apare o singură dată). */
export interface RuleHit {
  rule: CommandRule
  cmd: string
  panes: string[]
}

/** `rule` = cel puţin o linie atinge o regulă şi TOATE panourile-ţintă sunt verificabile:
      `rule`/`cmd` = linia principală (un block dacă există — atunci `hits` = doar blocurile),
      altfel `hits` = TOATE liniile cu `confirm` (dialogul le arată pe toate);
    `wait` / `unknown` poartă confirmările găsite deja (dialogul „nu pot verifica" le arată). */
export type PeerVerdict =
  | { kind: 'ok' }
  | { kind: 'rule'; rule: CommandRule; cmd: string; hits: RuleHit[] }
  | { kind: 'wait'; hits: RuleHit[] }
  | { kind: 'unknown'; hits: RuleHit[] }

/** cât aşteptăm ecoul tastelor în panourile-ţintă înainte să cerem confirmare (ms) */
export const ECHO_GRACE_MS = 150

export function guardActive(guard: CommandGuard | null | undefined): boolean {
  return !!guard?.enabled && Array.isArray(guard.rules) && guard.rules.length > 0
}

/** Verdictul pentru un Enter difuzat. Panoul de ORIGINE e şi el o ţintă (re-review 3.6.12, L-b):
    linia lui se re-citeşte după aşteptarea ecoului, ca a celorlalte. `lineOf` transformă linia unui
    panou înainte de verificare (ex. un snippet inserat: linia existentă + prima linie a snippetului);
    `extra` = liniile următoare ale unui paste / snippet multi-linie, identice în toate panourile.
    `final` = aşteptarea ecoului s-a terminat: un panou încă fără ecou devine `unknown`.

    Ordinea (review final 3.6.12, M): se scanează TOATE ţintele — un `block` oriunde câştigă; o
    confirmare NU ascunde nimic: dacă vreun panou e pe pauză / cu linia necunoscută / fără ecou,
    verdictul e wait → unknown, cu confirmările ataşate. Altfel un `confirm` în origine ar fi trimis
    Enter şi într-un panou al cărui `rm -rf` (block) sau linie veche nu l-am văzut. */
export function judgePeers(peers: PeerState[], guard: CommandGuard | null | undefined, final: boolean,
  lineOf: (pending: string | null) => string | null = (p) => p, extra: string[] = []): PeerVerdict {
  if (!guardActive(guard)) return { kind: 'ok' }
  const targets = peers.filter((p) => !p.inert)
  const blocks: RuleHit[] = []
  const confirms: RuleHit[] = []
  const add = (list: RuleHit[], rule: CommandRule, cmd: string, pane: string) => {
    const h = list.find((x) => x.cmd === cmd && x.rule.pattern === rule.pattern)
    if (!h) list.push({ rule, cmd, panes: [pane] })
    else if (!h.panes.includes(pane)) h.panes.push(pane)
  }
  targets.forEach((p, i) => {
    const pane = p.label ?? String(i + 1)
    const first = lineOf(p.pending)
    for (const raw of [first, ...extra]) {
      const line = raw ? stripControls(raw).trim() : ''
      const rule = line ? matchCommandRule(line, guard) : null
      if (rule) add(rule.action === 'block' ? blocks : confirms, rule, line, pane)
    }
  })
  if (blocks.length) return { kind: 'rule', rule: blocks[0].rule, cmd: blocks[0].cmd, hits: blocks }
  if (targets.some((p) => !p.live)) return { kind: 'unknown', hits: confirms }
  // linie necunoscută (după replay / înainte de prompt) sau taste fără ecou: aşteptăm puţin un
  // prompt / ecou live, apoi confirmare. NU „fără shell integration → ok": vezi PeerState.known.
  if (targets.some((p) => !p.known || (p.atPrompt && !p.echoed))) {
    return final ? { kind: 'unknown', hits: confirms } : { kind: 'wait', hits: confirms }
  }
  if (confirms.length) return { kind: 'rule', rule: confirms[0].rule, cmd: confirms[0].cmd, hits: confirms }
  return { kind: 'ok' }
}

/** Cheia setului de reguli văzut de utilizator într-un dialog (linie + regulă + panouri). */
export function hitsKey(hits: RuleHit[]): string {
  return hits.map((h) => `${h.rule.action}\u0000${h.rule.pattern}\u0000${h.cmd}\u0000${[...h.panes].sort().join('\u0001')}`)
    .sort().join('\u0002')
}

/** „Rulează" dintr-un dialog (regulă SAU „nu pot verifica"): verdictul se reface ACUM, iar Enter-ul
    pleacă doar dacă nu s-a schimbat nimic din ce a văzut utilizatorul (review final 3.6.12, M).
    `seen` = confirmările arătate; `acceptedUnknown` = dialogul era „nu pot verifica" (utilizatorul a
    acceptat explicit panourile neverificabile). Altfel: escaladare (block / dialog nou / unknown). */
export function runDecision(now: PeerVerdict, seen: RuleHit[], acceptedUnknown: boolean): 'send' | 'escalate' {
  if (now.kind === 'ok') return 'send'
  if (now.kind === 'wait') return 'escalate'   // nu se întâmplă cu final=true; defensiv
  if (now.kind === 'rule') {
    if (now.rule.action === 'block') return 'escalate'
    return hitsKey(now.hits) === hitsKey(seen) ? 'send' : 'escalate'
  }
  return acceptedUnknown && hitsKey(now.hits) === hitsKey(seen) ? 'send' : 'escalate'
}

/** Linia de VERIFICAT fără caractere de control: Alt+Enter (`\x1b\r`) e Enter pe linia curentă, nu
    „linie + ESC" (review final 3.6.12, L). Secvenţele ESC (săgeţi, Alt+literă) şi C0/DEL dispar. */
export function stripControls(s: string): string {
  return s.replace(/\x1b(?:\[[0-9;?]*[ -/]*[@-~]|O[\s\S]|[\s\S])?/g, '').replace(/[\x00-\x1f\x7f]/g, '')
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

/** Textul unui chunk de input fără marcajele bracketed paste — doar pentru VERIFICARE (ce se trimite
    rămâne neatins). Un payload care îşi închide singur paste-ul (`\x1b[201~`) ar executa liniile de
    după, deci nu tratăm bracketed paste ca „inert": fail-closed, verificăm toate liniile. */
export function unbracket(d: string): string {
  return d.replace(/\x1b\[20[01]~/g, '')
}
