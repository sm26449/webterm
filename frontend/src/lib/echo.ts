import { echoSettled, echoSettleMs } from './broadcastGuard'

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

interface Entry {
  seq: number
  /** momentul trimiterii (ms) */
  at: number
  /** textul trimis, dacă e text simplu; altfel null */
  text: string | null
  /** trimisă cât NU era nicio linie citibilă (comandă în curs: typeahead) — ecoul ei apare abia după
      următorul prompt; o confirmă doar o linie citibilă care chiar o arată (review 3.6.13, LOW-1b) */
  blind?: boolean
  /** >ECHO_PENDING_MAX trimiteri fără ecou, comprimate (host care nu ţine pasul) */
  lump?: boolean
  lumpAt?: number
  lumpKey?: string | null
}

export const ECHO_PENDING_MAX = 64

export class EchoTracker {
  /** trimiteri cu ecou aşteptat (contor) */
  inputSeq = 0
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
    this.pending.push({ seq, at: now, text, blind: this.base === null })
    if (this.pending.length > ECHO_PENDING_MAX) {
      // host care nu ţine pasul: comprimăm într-o singură intrare, eliberată doar când hub-ul a
      // ajuns din urmă (vezi output) sau la replay — fail-closed între timp
      this.pending = [{ seq, at: now, text: null, lump: true, lumpAt: now }]
    }
    this.lastSentAt = now
    return { seq, needBase }
  }

  setBase(seq: number, key: LineKey | null): void {
    if (this.base === undefined && this.pending.length && this.pending[0].seq === seq) {
      this.base = key
      if (key === null) for (const e of this.pending) e.blind = true
    }
  }

  private drop(pred: (e: Entry) => boolean): void {
    this.pending = this.pending.filter((e) => !pred(e))
  }

  /** Output parsat de xterm, sosit când `inputSeq` era `tag`. `now` citeşte starea liniei acum;
      `nowMs` / `rtt` servesc doar eliberării unei intrări comprimate. */
  output(tag: number, now: () => LineKey | null, nowMs = 0, rtt: number | null = null): void {
    if (tag > this.coarseSeq) this.coarseSeq = tag
    const first = this.pending[0]
    if (!first || first.seq > tag || this.base === undefined) return
    const cur = now()
    if (first.lump) {
      // review 3.6.13 (MEDIUM-2): o intrare comprimată nu mai blochează pentru totdeauna. Se eliberează
      // când hostul a ajuns demonstrabil din urmă: a sosit output după ultima ei tastă, linia s-a
      // schimbat de când s-a format şi a trecut plasa de timp de la ultima ei tastă
      const key = cur?.k ?? null
      if (first.lumpKey === undefined) { first.lumpKey = key; return }
      if (this.coarseSeq >= first.seq && key !== first.lumpKey && nowMs - (first.lumpAt ?? 0) >= echoSettleMs(rtt)) {
        this.pending.shift()
        for (const e of this.pending) e.blind = true          // referinţa lor nu se ştie: doar dovadă vizibilă
        this.base = this.pending.length ? cur : undefined
      }
      return
    }
    // un typeahead „orb" mai vechi decât plasa de timp a fost consumat de program (vim, un REPL) sau e
    // de mult pe ecran: nu mai blochează (altfel, după vim, prima comandă tastată repede ar cere dialog)
    if (this.pending.some((e) => e.blind && nowMs - e.at >= echoSettleMs(rtt))) {
      this.drop((e) => !!e.blind && nowMs - e.at >= echoSettleMs(rtt))
      if (!this.pending.length) { this.base = undefined; return }
    }
    const head = this.pending[0]
    if (head.seq > tag) { this.base = cur; return }
    if (cur === null) {
      // nicio linie citibilă (Enter → comanda rulează; fără shell integration): trimiterile făcute cât
      // EXISTA o linie şi-au primit ecoul (linia a dispărut) — regula grosieră, ca în 3.6.12. Cele „oarbe"
      // (typeahead) rămân: ecoul lor apare abia la următorul prompt
      this.drop((e) => e.seq <= tag && !e.blind)
      for (const e of this.pending) e.blind = true
      this.base = this.pending.length ? null : undefined
      return
    }
    if (this.base === null) {
      // linia tocmai a devenit citibilă (prompt nou): typeahead-ul e confirmat doar dacă linia ÎL ARATĂ
      let upto = 0
      let acc = ''
      for (const e of this.pending) {
        if (e.seq > tag || e.text === null || e.lump) break
        acc += e.text
        if (cur.line.endsWith(acc)) upto = e.seq
      }
      if (upto) this.drop((e) => e.seq <= upto)
      this.base = this.pending.length ? cur : undefined
      return
    }
    if (cur.k === this.base.k) return                       // un ceas, un repaint: linia nu s-a mişcat
    // o serie de text simplu pe care linia o arată exact (tastare rapidă, ecouri în acelaşi chunk)
    let matched = 0
    let acc = ''
    for (const e of this.pending) {
      if (e.seq > tag || e.text === null || e.lump) break
      acc += e.text
      if (cur.line === this.base.line + acc) matched = e.seq
    }
    if (matched) this.drop((e) => e.seq <= matched)
    else if (!head.blind) this.drop((e) => e === head)     // o schimbare = DOAR cea mai veche tastă
    // (un typeahead „orb" nu se confirmă dintr-o schimbare oarecare, doar când linia îl arată)
    this.base = this.pending.length ? cur : undefined
  }

  /** mai aşteaptă vreo trimitere ecoul? */
  get waiting(): boolean {
    return this.pending.length > 0
  }

  /** Replay complet (ataşare / resync): starea ecranului de după tot ce trimisesem. */
  replayed(upto: number = this.inputSeq): void {
    if (upto > this.coarseSeq) this.coarseSeq = upto
    this.drop((e) => e.seq <= upto)
    for (const e of this.pending) e.blind = true
    this.base = this.pending.length ? null : undefined   // trimise după începutul replay-ului: grosier
  }

  /** Ecoul ultimelor taste (vezi echoSettled): `requireOutput` la broadcast, nu într-un panou singur. */
  echoed(requireOutput: boolean, nowMs: number, rtt: number | null): boolean {
    return echoSettled({
      strict: this.pending.length === 0,
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

/** Rapoarte pe care TERMINALUL le trimite singur — DOAR formele exacte ale răspunsurilor xterm, fără
    niciun C0 (deci nici CR/LF) în corp (review 3.6.13, HIGH-1: un text LIPIT în forma unui răspuns OSC,
    cu linii în el, trecea drept raport şi ocolea guardrail-ul). Clasificarea scuteşte DOAR de
    urmărirea ecoului; guardrail-ul rulează oricum pentru orice chunk care trimite o linie (vezi
    SessionView.userInput), iar datele dintr-un paste nu sunt niciodată rapoarte.
    Rapoarte pe care TERMINALUL le trimite singur (nu tastele utilizatorului): focus (CSI I / O), mouse
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
  '\\x1b\\](?:4;\\d+|1\\d);rgb:[0-9a-fA-F/]+(?:\\x07|\\x1b\\\\)',
  '\\x1bP[01]\\$r[\\x20-\\x7e]*\\x1b\\\\',
].join('|') + ')+$')

export function isTerminalReport(d: string): boolean {
  return d.length > 0 && !/[\r\n]/.test(d) && REPORT_RE.test(d)
}

/** Input-ul e DOAR un raport de terminal (nu tastă)? `explicit` = venit pe o cale care emite numai
    rapoarte (onBinary = mouse X10); `pasting` = în timpul unui paste. Orice chunk care trimite o
    linie (CR/LF) NU e raport — trece prin guardrail (review 3.6.13, HIGH-1); nici datele unui paste. */
export function reportOnly(d: string | Uint8Array, explicit: boolean, pasting: boolean): boolean {
  const submits = typeof d === 'string' ? /[\r\n]/.test(d) : d.includes(0x0d) || d.includes(0x0a)
  if (submits || pasting) return false
  return explicit || (typeof d === 'string' && isTerminalReport(d))
}
