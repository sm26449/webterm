import { echoSettled } from './broadcastGuard'

/** Ecoul tastelor trimise spre host (guardrail-ul de comenzi, 3.6.13).

    Problema (review 3.6.13, M1): un singur instantaneu „al ultimei trimiteri" credita ecoul unei
    taste MAI VECHI drept ecoul celei mai noi — ↑↑⏎ rapid: ecoul primului ↑ schimba linia, deci al
    doilea ↑ părea confirmat, iar guardrail-ul citea prima comandă rechemată în timp ce shell-ul o
    rula pe a doua. Acum fiecare schimbare a liniei creditează DOAR prima trimitere fără ecou (sau o
    serie de trimiteri de text simplu, dacă linia arată exact textul lor adăugat), iar referinţa
    pentru următoarea e starea de după acest ecou. Două ecouri sosite în acelaşi chunk → al doilea
    rămâne fără ecou (fail-closed: aşteptare / dialog / plasa de timp), niciodată invers.

    Rapoartele generate de TERMINAL (mouse, focus, CPR, DA…; review 3.6.13, M2) nu sunt taste: nu
    aşteaptă niciun ecou, deci nici nu intră aici (vezi isTerminalReport). */

/** Starea liniei de comandă la un moment dat: `k` = cheia completă (ecran, cursor, linie), `line` =
    linia tastată (OSC 133, de la B la cursor). null = nicio linie de shell citibilă. */
export interface LineKey { k: string; line: string }

interface Entry { seq: number; text: string | null; lump?: boolean }

export const ECHO_PENDING_MAX = 64

export class EchoTracker {
  /** trimiteri cu ecou aşteptat (contor) */
  inputSeq = 0
  /** până la care trimitere a sosit ecoul (strict: linia s-a schimbat) */
  echoedSeq = 0
  /** până la care trimitere a sosit ORICE output după ea (regula grosieră din 3.6.12) */
  coarseSeq = 0
  lastSentAt = 0
  private pending: Entry[] = []
  /** referinţa pentru prima trimitere fără ecou: starea de după ultimul ecou creditat, sau cea de la
      trimitere când nu aştepta nimic. undefined = instantaneul încă nu s-a luat; null = fără linie. */
  private base: LineKey | null | undefined = undefined

  /** O tastă (sau un text) a plecat spre host. `text` = textul ei dacă e text simplu, altfel null.
      `needBase` = nu aştepta nimic înainte: apelantul ia instantaneul liniei DUPĂ ce xterm a parsat
      tot ce sosise deja (un write gol) şi cheamă setBase(seq, …). */
  sent(text: string | null, now: number): { seq: number; needBase: boolean } {
    const seq = ++this.inputSeq
    const needBase = this.pending.length === 0
    if (needBase) this.base = undefined
    this.pending.push({ seq, text })
    if (this.pending.length > ECHO_PENDING_MAX) {
      // host care nu răspunde: comprimăm într-o singură intrare care nu se mai creditează la o
      // schimbare de linie (doar replay / plasa de timp) — fail-closed
      this.pending = [{ seq, text: null, lump: true }]
    }
    this.lastSentAt = now
    return { seq, needBase }
  }

  setBase(seq: number, key: LineKey | null): void {
    if (this.base === undefined && this.pending.length && this.pending[0].seq === seq) this.base = key
  }

  private credit(upto: number): void {
    if (upto > this.coarseSeq) this.coarseSeq = upto
    if (upto > this.echoedSeq) this.echoedSeq = upto
    this.pending = this.pending.filter((e) => e.seq > upto)
  }

  /** Output parsat de xterm, sosit când `inputSeq` era `tag`. `now` citeşte starea liniei acum. */
  output(tag: number, now: () => LineKey | null): void {
    if (tag > this.coarseSeq) this.coarseSeq = tag
    const first = this.pending[0]
    if (!first || first.seq > tag || this.base === undefined) return
    if (first.lump) return
    const cur = now()
    if (this.base === null || cur === null) {
      // fără linie citibilă (fără shell integration / comandă în curs): regula grosieră, ca în 3.6.12
      // — acolo guardrail-ul nu aşteaptă oricum ecoul
      this.credit(tag)
      this.base = this.pending.length ? cur : undefined
      return
    }
    if (cur.k === this.base.k) return                       // un ceas, un repaint: linia nu s-a mişcat
    let upto = first.seq
    let acc = ''
    for (const e of this.pending) {
      if (e.seq > tag || e.text === null || e.lump) break
      acc += e.text
      if (cur.line === this.base.line + acc) upto = e.seq
    }
    this.credit(upto)
    this.base = this.pending.length ? cur : undefined
  }

  /** Replay complet (ataşare / resync): starea ecranului de după tot ce trimisesem. */
  replayed(upto: number = this.inputSeq): void {
    this.credit(upto)
    this.base = this.pending.length ? null : undefined   // trimise după începutul replay-ului: grosier
  }

  /** Ecoul ultimelor taste (vezi echoSettled): `requireOutput` la broadcast, nu într-un panou singur. */
  echoed(requireOutput: boolean, nowMs: number, rtt: number | null): boolean {
    return echoSettled({
      strict: this.echoedSeq >= this.inputSeq,
      coarse: this.coarseSeq >= this.inputSeq,
      sinceSend: nowMs - this.lastSentAt,
      rtt,
      requireOutput,
    })
  }

  /** ce n-a primit încă ecou, în ordine: text simplu sau null (taste de editare / necunoscut) */
  unechoed(): (string | null)[] {
    return this.pending.map((e) => (e.lump ? null : e.text))
  }
}

/** Rapoarte pe care TERMINALUL le trimite singur (nu tastele utilizatorului): focus (CSI I / O), mouse
    (SGR `CSI < … M/m`, urxvt, X10 `CSI M` + 3 octeţi), CPR, DA1/DA2/DA3, DSR, DECRPM, răspunsuri la
    operaţii de fereastră, OSC de culoare, DECRQSS. Un chunk e raport doar dacă e ÎNTREG format din
    astfel de secvenţe. Excepţie fail-closed: `CSI 1;2..8 R` e şi Shift/Ctrl/Alt+F3 — rămâne tastă. */
const REPORT_RE = new RegExp('^(?:' + [
  '\\x1b\\[[IO]',
  '\\x1b\\[<\\d+;\\d+;\\d+[Mm]',
  '\\x1b\\[\\d+;\\d+;\\d+M',
  '\\x1b\\[M[\\x20-\\xff]{3}',
  '\\x1b\\[(?!1;[2-8]R)\\d+;\\d+R',
  '\\x1b\\[\\?\\d+;\\d+R',
  '\\x1b\\[[?>=][\\d;]*c',
  '\\x1bP!\\|[0-9A-Fa-f]*\\x1b\\\\',
  '\\x1b\\[\\d+n',
  '\\x1b\\[\\??[\\d;]*\\$y',
  '\\x1b\\[\\d+(?:;\\d+)*t',
  '\\x1b\\]\\d+;[^\\x07\\x1b]*(?:\\x07|\\x1b\\\\)',
  '\\x1bP[01]\\$r[^\\x1b]*\\x1b\\\\',
].join('|') + ')+$')

export function isTerminalReport(d: string): boolean {
  return d.length > 0 && REPORT_RE.test(d)
}
