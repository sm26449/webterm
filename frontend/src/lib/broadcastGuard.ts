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
  /** id-ul stabil al panoului (id-ul sesiunii): cheia de deduplicare şi de comparaţie la „Rulează"
      (verificare 3.6.12, F3 — două panouri fără titlu pe acelaşi host au aceeaşi etichetă) */
  id: string
  /** numele panoului, DOAR pentru afişare în dialog (titlul sesiunii / hostul) */
  label?: string
  /** shell-ul panoului a cerut bracketed paste (DECSET 2004): un TAB între marcajele 200~/201~ e
      text, nu completare (3.6.13). Lipsă = nu (fail-closed: TAB-ul face linia necunoscută). */
  bracketed?: boolean
}

/** O linie care atinge o regulă, cu panourile în care s-ar rula (aceeaşi linie în mai multe panouri
    apare o singură dată). `panes` = id-uri (cheia), `labels` = aceleaşi panouri, de afişat. */
export interface RuleHit {
  rule: CommandRule
  cmd: string
  panes: string[]
  labels: string[]
}

/** `rule` = cel puţin o linie atinge o regulă şi TOATE panourile-ţintă sunt verificabile:
      `rule`/`cmd` = linia principală (un block dacă există — atunci `hits` = doar blocurile),
      altfel `hits` = TOATE liniile cu `confirm` (dialogul le arată pe toate);
    `wait` / `unknown` poartă confirmările găsite deja (dialogul „nu pot verifica" le arată) şi
    id-urile panourilor neverificabile (`unreadable`, verificare 3.6.12 F5: un panou devenit
    neverificabil după deschiderea dialogului escaladează la „Rulează"). */
export type PeerVerdict =
  | { kind: 'ok' }
  | { kind: 'rule'; rule: CommandRule; cmd: string; hits: RuleHit[] }
  | { kind: 'wait'; hits: RuleHit[]; unreadable: string[] }
  | { kind: 'unknown'; hits: RuleHit[]; unreadable: string[] }

/** cât aşteptăm ecoul tastelor în panourile-ţintă înainte să cerem confirmare (ms) */
export const ECHO_GRACE_MS = 150

/** Ecoul STRÂNS (3.6.13) cere ca output-ul de după taste să fi schimbat linia / cursorul. O tastă fără
    efect vizibil (TAB fără completare = doar BEL, Home când cursorul e deja la început) n-ar primi
    niciodată „ecou" → dialog la fiecare Enter. Plasă: după atâta timp de la ultima trimitere,
    tastele sunt „aşezate" — orice ecou ar fi sosit deja (≥ 1 s şi ≥ 4 × RTT-ul măsurat).
    Panourile-ţintă ale unui broadcast cer în plus să fi sosit MĂCAR un output după trimitere
    (regula grosieră din 3.6.12): un host blocat (fără niciun output) rămâne „fără ecou", ca înainte. */
export const ECHO_SETTLE_MIN_MS = 1000
/** plafon (review 3.6.13, L6): un vârf de RTT (tab adormit, reţea blocată) nu întinde fereastra la minute */
export const ECHO_SETTLE_MAX_MS = 5000
export function echoSettleMs(rtt: number | null | undefined): number {
  const r = typeof rtt === 'number' && Number.isFinite(rtt) && rtt > 0 ? rtt : 0
  return Math.min(ECHO_SETTLE_MAX_MS, Math.max(ECHO_SETTLE_MIN_MS, 4 * r))
}

/** Tastele trimise au primit ecou? `strict` = output care a schimbat linia după ultima trimitere;
    `coarse` = orice output după ea; `sinceSend` = ms de la ultima trimitere. `requireOutput`: la
    broadcast (vezi ECHO_SETTLE_MIN_MS) plasa de timp cere şi un output; într-un singur panou, nu —
    acolo 3.6.12 nu aştepta deloc ecoul, iar o tastă fără output n-ar trebui să ceară dialog. */
export function echoSettled(o: { strict: boolean; coarse: boolean; sinceSend: number; rtt: number | null; requireOutput: boolean }): boolean {
  if (o.strict) return true
  if (o.requireOutput && !o.coarse) return false
  return o.sinceSend >= echoSettleMs(o.rtt)
}

export function guardActive(guard: CommandGuard | null | undefined): boolean {
  return !!guard?.enabled && Array.isArray(guard.rules) && guard.rules.length > 0
}

/** Verdictul pentru un Enter difuzat. Panoul de ORIGINE e şi el o ţintă (re-review 3.6.12, L-b):
    linia lui se re-citeşte după aşteptarea ecoului, ca a celorlalte. `lineOf` transformă linia unui
    panou înainte de verificare (ex. un snippet inserat: linia existentă + prima linie a snippetului);
    `extra` = liniile următoare ale unui paste / snippet multi-linie, identice în toate panourile.
    `final` = aşteptarea ecoului s-a terminat: un panou încă fără ecou devine `unknown`.
    `opaque` = input-ul conţine taste de editare (vezi `opaqueInput`): textul verificat nu e cel care
    rulează → `unknown` pentru toate ţintele (după block-uri), ca la un panou neverificabil.

    Ordinea (review final 3.6.12, M): se scanează TOATE ţintele — un `block` oriunde câştigă; o
    confirmare NU ascunde nimic: dacă vreun panou e pe pauză / cu linia necunoscută / fără ecou,
    verdictul e wait → unknown, cu confirmările ataşate. Altfel un `confirm` în origine ar fi trimis
    Enter şi într-un panou al cărui `rm -rf` (block) sau linie veche nu l-am văzut. */
export function judgePeers(peers: PeerState[], guard: CommandGuard | null | undefined, final: boolean,
  lineOf: (pending: string | null) => string | null = (p) => p, extra: string[] = [], opaque = false): PeerVerdict {
  if (!guardActive(guard)) return { kind: 'ok' }
  const targets = peers.filter((p) => !p.inert)
  const labels = paneLabels(targets)
  const blocks: RuleHit[] = []
  const confirms: RuleHit[] = []
  const add = (list: RuleHit[], rule: CommandRule, cmd: string, p: PeerState) => {
    const h = list.find((x) => x.cmd === cmd && x.rule.pattern === rule.pattern)
    if (!h) list.push({ rule, cmd, panes: [p.id], labels: [labels.get(p.id) ?? p.id] })
    else if (!h.panes.includes(p.id)) { h.panes.push(p.id); h.labels.push(labels.get(p.id) ?? p.id) }
  }
  for (const p of targets) {
    const first = lineOf(p.pending)
    for (const raw of [first, ...extra]) {
      const line = raw ? stripControls(raw).trim() : ''
      const rule = line ? matchCommandRule(line, guard) : null
      if (rule) add(rule.action === 'block' ? blocks : confirms, rule, line, p)
    }
  }
  if (blocks.length) return { kind: 'rule', rule: blocks[0].rule, cmd: blocks[0].cmd, hits: blocks }
  if (opaque) return { kind: 'unknown', hits: confirms, unreadable: targets.map((p) => p.id) }
  // linie necunoscută (după replay / înainte de prompt) sau taste fără ecou: aşteptăm puţin un
  // prompt / ecou live, apoi confirmare. NU „fără shell integration → ok": vezi PeerState.known.
  const unseen = targets.filter((p) => !p.live || !p.known || (p.atPrompt && !p.echoed)).map((p) => p.id)
  // un panou pe pauză nu se schimbă aşteptând: unknown imediat, cu TOATE panourile neverificabile (F5)
  if (targets.some((p) => !p.live)) return { kind: 'unknown', hits: confirms, unreadable: unseen }
  if (unseen.length) {
    return final ? { kind: 'unknown', hits: confirms, unreadable: unseen } : { kind: 'wait', hits: confirms, unreadable: unseen }
  }
  if (confirms.length) return { kind: 'rule', rule: confirms[0].rule, cmd: confirms[0].cmd, hits: confirms }
  return { kind: 'ok' }
}

/** Etichetele de afişat: o etichetă purtată de mai multe panouri (două sesiuni fără titlu pe acelaşi
    host) primeşte un sufix scurt din id (verificare 3.6.12, F3). */
export function paneLabels(peers: PeerState[]): Map<string, string> {
  const base = (p: PeerState) => p.label || p.id.slice(0, 8)
  const count = new Map<string, number>()
  for (const p of peers) count.set(base(p), (count.get(base(p)) ?? 0) + 1)
  const out = new Map<string, string>()
  for (const p of peers) {
    const b = base(p)
    out.set(p.id, (count.get(b) ?? 0) > 1 ? `${b} · ${p.id.slice(0, 6)}` : b)
  }
  return out
}

/** Cheia setului de reguli văzut de utilizator într-un dialog (linie + regulă + id-urile panourilor). */
export function hitsKey(hits: RuleHit[]): string {
  return hits.map((h) => `${h.rule.action}\u0000${h.rule.pattern}\u0000${h.cmd}\u0000${[...h.panes].sort().join('\u0001')}`)
    .sort().join('\u0002')
}

/** „Rulează" dintr-un dialog (regulă SAU „nu pot verifica"): verdictul se reface ACUM, iar Enter-ul
    pleacă doar dacă nu s-a schimbat nimic din ce a văzut utilizatorul (review final 3.6.12, M).
    `seen` = confirmările arătate; `acceptedUnknown` = id-urile panourilor neverificabile pe care
    utilizatorul le-a acceptat explicit în dialogul „nu pot verifica" (null = dialog de regulă). Un
    unknown trece doar cu aceleaşi confirmări ŞI fără panou neverificabil nou (F5).
    `now` = null: dialogul s-a deschis FĂRĂ broadcast (nicio re-verificare a celorlalte panouri) →
    `local` — Enter-ul pleacă doar în panoul ăsta, chiar dacă între timp broadcast-ul a pornit (F2).
    Altfel: escaladare (block / dialog nou / unknown). */
export function runDecision(now: PeerVerdict | null, seen: RuleHit[], acceptedUnknown: string[] | null): 'send' | 'local' | 'escalate' {
  if (now === null) return 'local'
  if (now.kind === 'ok') return 'send'
  if (now.kind === 'wait') return 'escalate'   // nu se întâmplă cu final=true; defensiv
  if (now.kind === 'rule') {
    if (now.rule.action === 'block') return 'escalate'
    return hitsKey(now.hits) === hitsKey(seen) ? 'send' : 'escalate'
  }
  if (!acceptedUnknown || hitsKey(now.hits) !== hitsKey(seen)) return 'escalate'
  return now.unreadable.every((id) => acceptedUnknown.includes(id)) ? 'send' : 'escalate'
}

/** Linia de VERIFICAT fără caractere de control: Alt+Enter (`\x1b\r`) e Enter pe linia curentă, nu
    „linie + ESC" (review final 3.6.12, L). Secvenţele ESC (săgeţi, Alt+literă) şi C0/DEL dispar.
    TAB / VT / FF devin spaţiu, nu dispar: `rm\t-rf` trebuie să atingă `rm\s+-rf` (F4). */
export function stripControls(s: string): string {
  return s.replace(/[\t\v\f]/g, ' ')
    .replace(/\x1b(?:\[[0-9;?]*[ -/]*[@-~]|O[\s\S]|[\s\S])?/g, '').replace(/[\x00-\x1f\x7f]/g, '')
}

/** Un chunk care TRIMITE o linie dar conţine şi taste de editare readline (Ctrl+U `\x15`, DEL `\x7f`,
    Ctrl+P `\x10`, Ctrl+Y `\x19`, Ctrl+V `\x16`, ESC-. …): linia pe care o rulează shell-ul nu e
    textul pe care l-am verifica, deci verdictul e „nu pot verifica" (fail-closed, verificare 3.6.12
    F4). Permise: CR/LF, marcajele bracketed paste şi ESC-ul singur dinaintea unui Enter (Alt+Enter).
    TAB (3.6.13): în afara unui bracketed paste e COMPLETARE readline (schimbă linia: `rm -rf /tm⇥`
    → `/tmp/`), deci opac; între `\x1b[200~` şi primul `\x1b[201~` care urmează (sau capătul
    chunk-ului) e text literal — dar numai cu `bracketed` (shell-ul a cerut bracketed paste în TOATE
    panourile-ţintă; altfel marcajele pot veni chiar din textul lipit, iar shell-ul nu le onorează).
    Tot restul C0, DEL, C1 şi orice alt ESC = opac. */
export function opaqueInput(d: string, bracketed = false): boolean {
  const literalTabs = bracketed
    ? d.replace(/\x1b\[200~[\s\S]*?(?:\x1b\[201~|$)/g, (seg) => seg.replace(/\t/g, ''))
    : d
  const rest = literalTabs.replace(/\x1b\[20[01]~/g, '').replace(/\x1b(?=[\r\n])/g, '')
  return /[\x00-\x09\x0b\x0c\x0e-\x1f\x7f-\x9f]/.test(rest)
}

/** Starea panoului pentru un Enter FĂRĂ broadcast (3.6.13, rezidual 3.6.12): ce citeşte trackerul +
    ecoul. `unechoed` = ce s-a trimis după ultimul ecou, în ordine: textul unei trimiteri doar cu
    caractere tipăribile, sau null pentru una cu taste de editare / control (↑, Ctrl+P, TAB, DEL…). */
export interface LocalState {
  atPrompt: boolean
  echoed: boolean
  pending: string | null
  unechoed: (string | null)[]
}

export type LocalVerdict =
  | { kind: 'ok' }
  | { kind: 'rule'; rule: CommandRule; cmd: string }
  | { kind: 'wait' }
  | { kind: 'unknown' }

/** Ce s-ar vedea pe linie după ecoul textului `typed`: ecoul poate fi deja parţial pe ecran (`line` se
    termină cu un început al lui `typed`), deci lipim doar restul. */
export function mergeTyped(line: string, typed: string): string {
  for (let k = Math.min(line.length, typed.length); k > 0; k--) {
    if (line.endsWith(typed.slice(0, k))) return line + typed.slice(k)
  }
  return line + typed
}

/** Verdictul unui Enter într-un singur panou (fără broadcast), cu aceeaşi aşteptare a ecoului ca la
    panourile-ţintă (3.6.13): Ctrl+P / ↑ + Enter rapid trimitea o linie pe care trackerul n-o văzuse.
      • la prompt, fără ecou încă → `wait` (≤ ECHO_GRACE_MS), apoi:
          – tot ce n-are ecou e text simplu → verificăm linia de pe ecran ŞI linia + textul acela (o
            legătură lentă nu cere dialog la fiecare comandă tastată repede);
          – altfel (taste de editare fără ecou: linia poate fi oricare) → `unknown` („nu pot verifica").
      • altfel → linia de pe ecran, ca înainte. Un block cunoscut câştigă mereu.
    `lineOf` / `extra` ca la judgePeers (un chunk „text⏎…": prima linie lipită de cea tastată).
    Fără broadcast NU se cere `known` (linia necunoscută după replay) — comportamentul de dinainte. */
export function judgeLocal(s: LocalState, guard: CommandGuard | null | undefined, final: boolean,
  lineOf: (pending: string | null) => string | null = (p) => p, extra: string[] = []): LocalVerdict {
  if (!guardActive(guard)) return { kind: 'ok' }
  const lines: string[] = []
  const first = lineOf(s.pending)
  if (first) lines.push(first)
  lines.push(...extra)
  let unknown = false
  if (s.atPrompt && !s.echoed) {
    if (!final) return { kind: 'wait' }
    if (s.unechoed.length === 0 || s.unechoed.some((t) => t === null)) unknown = true
    else {
      // ecoul poate fi deja parţial pe ecran (suprapunere) SAU deloc (linia se termină întâmplător cu
      // textul: ↑ „…/tmp/x" + „x" tastat) — verificăm ambele variante, fail-closed
      const typed = s.unechoed.join('')
      for (const cand of [mergeTyped(s.pending ?? '', typed), (s.pending ?? '') + typed]) {
        const merged = lineOf(cand)
        if (merged) lines.push(merged)
      }
    }
  }
  let confirm: { rule: CommandRule; cmd: string } | null = null
  for (const raw of lines) {
    const line = stripControls(raw).trim()
    const rule = line ? matchCommandRule(line, guard) : null
    if (rule?.action === 'block') return { kind: 'rule', rule, cmd: line }
    if (rule && !confirm) confirm = { rule, cmd: line }
  }
  if (unknown) return { kind: 'unknown' }
  if (confirm) return { kind: 'rule', ...confirm }
  return { kind: 'ok' }
}

/** „Rulează" din dialogul „încă nu pot verifica linia" (un singur panou, review 3.6.13 L4): verdictul se
    reface ACUM. ok / tot necunoscut (acceptat explicit) → trimite; o regulă care atinge linia devenită
    vizibilă → escaladare (block = blocare, confirm = dialogul regulii). */
export function localRunDecision(v: LocalVerdict): 'send' | 'escalate' {
  return v.kind === 'rule' ? 'escalate' : 'send'
}

/** O trimitere de input e „text simplu" (ecoul ei doar adaugă la linie)? Fără C0 / DEL / C1 / ESC. */
export function plainText(d: string): boolean {
  return !/[\x00-\x1f\x7f-\x9f]/.test(d)
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
