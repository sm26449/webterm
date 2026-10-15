import { echoSettled, echoSettleMs } from './broadcastGuard'

/** Ecoul tastelor trimise spre host (guardrail-ul de comenzi, 3.6.13).

    Problema (review 3.6.13, M1): un singur instantaneu „al ultimei trimiteri" credita ecoul unei
    taste MAI VECHI drept ecoul celei mai noi — ↑↑⏎ rapid: ecoul primului ↑ schimba linia, deci al
    doilea ↑ părea confirmat, iar guardrail-ul citea prima comandă rechemată în timp ce shell-ul o
    rula pe a doua. Acum o serie de trimiteri de text simplu se confirmă când linia arată exact textul
    lor adăugat; o tastă care NU e text (↑, Ctrl+P, TAB…) se confirmă cel mult una per rafală de
    output, şi abia după ce fluxul a tăcut (echoQuietMs) cu linia neschimbată — o redesenare ruptă în
    două chunk-uri nu mai confirmă două taste (a treia trecere de review). Două ecouri non-text în
    aceeaşi rafală → al doilea rămâne fără ecou (fail-closed: aşteptare / dialog / plasa de timp).
    Limită care rămâne: o tastă al cărei ecou soseşte în rafale despărţite de mai mult de quietMs
    (host foarte încărcat) poate fi confirmată de prima rafală; plasa e acelaşi mecanism ca înainte —
    linia citită e cea de pe ecran.

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

/** Linia fără spaţii albe, pentru comparaţia ecoului: o linie lungă continuată pe rândul următor,
    sau redesenată de tmux / readline la margine, poate apărea cu un spaţiu în plus sau în minus la
    graniţa rândului — fără asta tastarea rapidă a unei linii lungi rămânea „fără ecou" (e2e 3.6.13).
    Un text format DOAR din spaţii nu se confirmă singur (ar potrivi oricând); îl confirmă primul
    caracter vizibil de după el. */
const sq = (s: string): string => s.replace(/\s+/g, '')
/** câte linii distincte ţinem dintr-o rafală (pentru textul tastat după o tastă ne-text) */
const CAND_LINES_MAX = 16

/** cât trebuie să tacă fluxul ca o schimbare de linie dintr-o tastă ne-text să fie socotită completă:
    RTT/2 între 20 şi 50 ms (30 ms fără RTT măsurat) */
export function echoQuietMs(rtt: number | null | undefined): number {
  if (typeof rtt !== 'number' || !Number.isFinite(rtt) || rtt <= 0) return 30
  return Math.min(50, Math.max(20, rtt / 2))
}

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
  /** cea mai veche tastă care NU e text simplu, a cărei linie s-a schimbat: se confirmă abia după ce
      fluxul a tăcut (quietMs) şi linia a rămas aceeaşi — o redesenare ruptă în două chunk-uri nu mai
      confirmă două taste (review 3.6.13, a treia trecere, MEDIUM-2) */
  private cand: { seq: number; key: string; at: number; lines: string[] } | null = null
  private lastOutAt = 0
  /** output primit de xterm dar încă neparsat (term.write fără callback încă): cât e > 0, fluxul NU
      e „liniştit" — o scriere mare se parsează în mai multe felii, iar linia de acum nu e finală
      (review final 3.6.13, LOW-C). SessionView: writeStart() la term.write, writeEnd() în callback. */
  private inFlight = 0

  writeStart(): void { this.inFlight++ }
  writeEnd(): void { if (this.inFlight > 0) this.inFlight-- }

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
      // textul rămâne dacă TOATE erau text simplu (tastare rapidă pe o legătură lentă): verificarea
      // locală îl lipeşte de linie în loc să ceară „nu pot verifica" (3.6.13, e2e)
      const all = this.pending.every((e) => e.text !== null)
      const text = all ? this.pending.map((e) => e.text).join('') : null
      this.pending = [{ seq, at: now, text, lump: true, lumpAt: now }]
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
    this.lastOutAt = nowMs
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
        this.cand = null
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
      this.cand = null
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
        if (sq(acc) && sq(cur.line).endsWith(sq(acc))) upto = e.seq
      }
      if (upto) this.drop((e) => e.seq <= upto)
      this.cand = null
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
      if (sq(acc) && sq(cur.line) === sq(this.base.line + acc)) matched = e.seq
    }
    if (matched) {
      this.drop((e) => e.seq <= matched)
      this.cand = null
    } else if (!head.blind) {
      // o schimbare care nu e text simplu (↑, Ctrl+P, TAB, o redesenare): cel mult cea mai veche tastă,
      // şi abia după ce fluxul tace (vezi quiet). Încă o schimbare înainte de asta = aceeaşi rafală
      // (ex. redesenarea lui ↑ ruptă în două chunk-uri): reporneşte aşteptarea, nu confirmă alta
      if (this.cand && this.cand.seq === head.seq) {
        this.cand.key = cur.k
        this.cand.at = nowMs
        const ls = this.cand.lines
        if (ls[ls.length - 1] !== cur.line && ls.length < CAND_LINES_MAX) ls.push(cur.line)
      } else this.cand = { seq: head.seq, key: cur.k, at: nowMs, lines: [cur.line] }
    }
    // (un typeahead „orb" nu se confirmă dintr-o schimbare oarecare, doar când linia îl arată)
    this.base = this.pending.length ? cur : undefined
  }

  /** Confirmă tasta-candidat dacă fluxul a tăcut destul şi linia n-a mai mişcat de atunci. */
  private quiet(nowMs: number, rtt: number | null, keyNow: LineKey | null): void {
    const c = this.cand
    if (!c) return
    const head = this.pending[0]
    if (!head || head.seq !== c.seq) { this.cand = null; return }
    if (this.inFlight > 0) return                         // output încă neparsat: nu e linişte
    const q = echoQuietMs(rtt)
    if (nowMs - c.at < q || nowMs - this.lastOutAt < q) return
    if (!keyNow || keyNow.k !== c.key) return
    this.pending.shift()
    this.cand = null
    // text simplu tastat imediat după tastă (↑ apoi „ -v"): potrivirea se oprea la tasta ne-text, iar
    // referinţa de acum îl conţine deja — l-ar fi ţinut până la plasa de 1 s (review final, LOW-A).
    // Îl confirmăm DOAR dacă linia de acum e EXACT o linie văzută în rafală + textul lui. Nu „se
    // termină cu": ↑ care recheamă „…/tmp/x" urmat de un „x" tastat ar fi confirmat x-ul înaintea
    // ecoului său (linia rechemată se termină deja în „x"); cu text nevid, linia de acum nu se poate
    // potrivi cu ea însăşi.
    // Rezidual: o redesenare ruptă exact înaintea ultimelor caractere tastate apoi identic ar putea
    // potrivi; altfel textul rămâne în aşteptare (plasa de 1 s / lipirea din verificarea locală).
    let acc = ''
    let upto = 0
    for (const e of this.pending) {
      if (e.text === null || e.lump || e.blind) break
      acc += e.text
      if (sq(acc) && c.lines.some((l) => sq(l + acc) === sq(keyNow.line))) upto = e.seq
    }
    if (upto) this.drop((e) => e.seq <= upto)
    this.base = this.pending.length ? keyNow : undefined
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
    this.cand = null
    this.base = this.pending.length ? null : undefined   // trimise după începutul replay-ului: grosier
  }

  /** Ecoul ultimelor taste (vezi echoSettled): `requireOutput` la broadcast, nu într-un panou singur.
      `keyNow` = starea liniei acum (confirmă tasta-candidat dacă fluxul a tăcut; vezi quiet). */
  echoed(requireOutput: boolean, nowMs: number, rtt: number | null, keyNow?: LineKey | null): boolean {
    if (keyNow !== undefined) this.quiet(nowMs, rtt, keyNow)
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
    return this.pending.map((e) => e.text)
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
    astfel de secvenţe. `CSI 1;<n> R` e şi F3 cu modificatori (Shift/Ctrl/Alt 2..8, cu Meta/Super 9..16
    — xterm Keyboard.ts adaugă 8 pentru metaKey): e raport DOAR dacă output-ul a cerut poziţia
    cursorului (`CSI 6 n` / `CSI ? 6 n`) de la ultimul răspuns (`cprRequested`), altfel tastă
    (review final 3.6.13, LOW-B: un CPR real pe rândul 1 — nushell, unele teme zsh după clear —
    ajungea tastă ne-text şi ţinea textul tastat după el). */
const REPORT_PARTS = [
  '\\x1b\\[[IO]',
  '\\x1b\\[<\\d+;\\d+;\\d+[Mm]',
  '\\x1b\\[\\d+;\\d+;\\d+M',
  '\\x1b\\[M[\\x20-\\xff]{3}',
  '\\x1b\\[(?!1;\\d+R)\\d+;\\d+R',
  '\\x1b\\[\\?\\d+;\\d+R',
  '\\x1b\\[[?>=][\\d;]*c',
  '\\x1bP!\\|[0-9A-Fa-f]*\\x1b\\\\',
  '\\x1b\\[\\d+n',
  '\\x1b\\[\\??[\\d;]*\\$y',
  '\\x1b\\[\\d+(?:;\\d+)*t',
  '\\x1b\\](?:4;\\d+|1\\d);rgb:[0-9a-fA-F/]+(?:\\x07|\\x1b\\\\)',
  '\\x1bP[01]\\$r[\\x20-\\x7e]*\\x1b\\\\',
]
const REPORT_RE = new RegExp('^(?:' + REPORT_PARTS.join('|') + ')+$')
const REPORT_CPR1_RE = new RegExp('^(?:' + [...REPORT_PARTS, '\\x1b\\[1;\\d+R'].join('|') + ')+$')

export function isTerminalReport(d: string, cprRequested = false): boolean {
  return d.length > 0 && !/[\r\n]/.test(d) && (cprRequested ? REPORT_CPR1_RE : REPORT_RE).test(d)
}

/** Câte cereri de poziţie a cursorului (`CSI 6 n` / `CSI ? 6 n`) conţine un chunk de output. */
export function countCprRequests(b: Uint8Array): number {
  let n = 0
  for (let i = b.indexOf(0x1b); i >= 0; i = b.indexOf(0x1b, i + 1)) {   // o cerere ruptă între chunk-uri = ratată → tastă (fail-closed)
    if (b[i + 1] !== 0x5b) continue
    let j = i + 2
    if (b[j] === 0x3f) j++
    if (b[j] === 0x36 && b[j + 1] === 0x6e) n++
  }
  return n
}

/** Câte răspunsuri CPR conţine un input (pentru a consuma cererile). */
export function countCprReplies(d: string): number {
  return (d.match(/\x1b\[\??\d+;\d+R/g) ?? []).length
}

/** Input-ul e DOAR un raport de terminal (nu tastă)? `explicit` = venit pe o cale care emite numai
    rapoarte (onBinary = mouse X10); `pasting` = în timpul unui paste. Orice chunk care trimite o
    linie (CR/LF) NU e raport — trece prin guardrail (review 3.6.13, HIGH-1); nici datele unui paste. */
export function reportOnly(d: string | Uint8Array, explicit: boolean, pasting: boolean, cprRequested = false): boolean {
  const submits = typeof d === 'string' ? /[\r\n]/.test(d) : d.includes(0x0d) || d.includes(0x0a)
  if (submits || pasting) return false
  return explicit || (typeof d === 'string' && isTerminalReport(d, cprRequested))
}
