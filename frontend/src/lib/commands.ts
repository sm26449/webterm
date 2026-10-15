import { IMarker, Terminal } from '@xterm/xterm'
import type { CommandGuard, CommandRule } from './api'

/** Regula care se potrivește pe comandă (regex, case-insensitive), regulile `block` înaintea
    celor `confirm` — la fel ca serverul (`_match_guard_rule`). null = trece.
    Regex invalid e ignorat (serverul îl validează la salvare, dar suntem defensivi). */
export function matchCommandRule(cmd: string, guard: CommandGuard | null | undefined): CommandRule | null {
  if (!guard?.enabled || !cmd) return null
  const ordered = [...guard.rules.filter((r) => r.action === 'block'), ...guard.rules.filter((r) => r.action !== 'block')]
  for (const r of ordered) {
    try { if (new RegExp(r.pattern, 'i').test(cmd)) return r } catch { /* regex invalid: sări */ }
  }
  return null
}

/** Model de „comenzi" (blocks) construit din marcajele OSC 133 emise de shell:
      A = început de prompt · B = început de comandă tastată
      C = început de execuție · D;<cod> = sfârșit, cu exit code
    Cu ele știm, pentru fiecare comandă: textul, rândul de start/stop în buffer,
    exit code-ul și durata. Fără shell integration nu apare nimic — degradare
    curată, terminalul rămâne exact cum era.

    Legătura cu bufferul se face prin markers xterm (rânduri care „se mișcă"
    corect când scrollback-ul se rotește), nu prin indici bruți. */
export interface Command {
  id: number
  text: string
  /** rândul (absolut, în buffer) unde începe OUTPUT-ul comenzii */
  startMarker: IMarker
  endMarker?: IMarker
  exitCode?: number
  startedAt: number
  endedAt?: number
  /** octeţii primiţi între C şi D, decodaţi (vezi `feed`). Sub tmux e SINGURA sursă
      corectă pentru output: ecranul e repictat asincron faţă de marcaje. */
  captured?: string
}

/** secvenţe de control scoase când livrăm output ca TEXT (clipboard, markdown) */
const CTRL_RE =
  /(?:\[[0-9;?<=>]*[a-zA-Z@`~]|\][^]*(?:|\\)|[PX^_][^]*\\|[()*+][A-Za-z0-9]|O[A-Za-z]|.)/g

function plain(s: string): string {
  return s
    .replace(CTRL_RE, '')
    .split('\n')
    // CR = rescrie rândul (bare de progres); CR-ul final al unui CRLF (pty fără tmux) nu şterge nimic
    .map((line) => line.replace(/\r+$/, '').split('\r').pop() ?? '')   // CR = rescrie rândul (bare de progres)
    .join('\n')
}

const CAPTURE_MAX = 256 * 1024      // per comandă; peste atât, output-ul se citeşte de pe ecran

export class CommandTracker {
  private term: Terminal
  private nextId = 1
  /** poziţia lui B ca MARKER xterm (review 3.6.13, H1): un rând absolut „îmbătrâneşte" când
      scrollback-ul e plin şi fiecare derulare taie rândul de sus (xterm nu mai mută ybase) — linia
      se citea de pe alt rând, iar verificarea vedea doar un fragment. Markerul urmează tăierea; un
      marker dispărut (rândul promptului a ieşit din scrollback) = linie necunoscută (fail-closed). */
  private promptMarker: IMarker | null = null
  /** textul rândului promptului la prima tastă de după B (vezi notePromptPainted) */
  private promptSnap: string | null = null
  /** textul din dreapta cursorului pe rândul promptului la prima tastă (RPROMPT), cu poziţia lui */
  private rightPrompt: { text: string; marker: IMarker; col: number } | null = null
  /** poziţia ORIGINALĂ a lui B (nu se re-ancorează niciodată): citirea conservatoare porneşte de aici
      (review 3.6.13: o euristică nu are voie să SCOATĂ text din ce judecă guardrail-ul — doar să
      adauge variante) */
  private origMarker: IMarker | null = null
  private origCol = 0
  /** re-ancorarea s-a încercat deja pentru acest B (cel mult o dată per B) */
  private anchorTried = false
  /** ştergere de ecran / RIS / regiune de scroll după B (vezi noteScreenReset) */
  private screenSuspect = false
  private promptCol = 0
  private pendingText: string | null = null  // textul comenzii, dacă shell-ul ni-l trimite (E)
  private current: Command | null = null
  /** shell integration văzută în panoul ăsta: un marcaj B (sfârşit de prompt), live SAU rejucat.
      Doar B contează (review final 3.6.12): o integrare care emite numai A/C/D nu ne arată niciodată
      linia tastată, deci n-ar ieşi din „linie necunoscută" — dialog la fiecare Enter difuzat.
      Supravieţuieşte lui reset() — un panou nu-şi pierde shell integration la o reconectare. */
  private integratedFlag = false
  /** după reset() (replay de istoric) nu ştim linia tastată până la următorul B live */
  private staleFlag = false
  /** 3.6.13: hub-ul spune că ultimul marcaj LIVE de dinaintea replay-ului e C — rulează ceva
      (ssh, `sudo -i`, un REPL) pornit înainte de replay. Ca un `current` văzut live, fără captură:
      Enter-ul merge la program. Se stinge la D (live) sau la următorul reset(). */
  private runningUnseen = false
  /** ultimul marcaj REJUCAT (felul lui; '?' = rejucat pe ecranul alternativ) şi, dacă e B,
      poziţia lui (marker xterm, ca rândul să urmeze rotirea scrollback-ului) — vezi applyHubState */
  private replayLast: string | null = null
  private replayB: IMarker | null = null
  private replayBCol = 0
  commands: Command[] = []
  onChange?: () => void
  /** fire-uit o dată per comandă finalizată (pt. istoricul global) */
  onCommand?: (cmd: Command) => void
  /** fire-uit când comanda e CREATĂ (la C), înainte de output. Folosit de player
      ca să atașeze timpul din .cast la momentul potrivit (comenzile goale n-au C). */
  onStart?: (cmd: Command) => void

  /** rândul absolut ACUM al lui B (din marker), sau null — inclusiv când markerul a dispărut */
  private get promptRow(): number | null {
    const m = this.promptMarker
    if (!m || m.isDisposed || typeof m.line !== 'number' || m.line < 0) return null
    return m.line
  }

  /** Rândul promptului nu mai e de încredere — linia nu se poate citi, fail-closed (review 3.6.13,
      H1 + verificare). Markerul urmează tăierea / inserarea / ştergerea de rânduri, dar NU mişcările
      fără aceste evenimente: Ctrl+L în zsh (ED2 pe loc, promptul redesenat sus fără un B nou), o
      regiune de scroll cu marginea de sus ≠ 1 (bara tmux sus, panoul de jos dintr-un split tmux),
      repictarea tmux după un resize. Deci „pierdut" când:
        • markerul a ieşit din buffer;
        • rândul lui e SUB cursor (promptul a fost redesenat mai sus);
        • între el şi cursor e un rând care nu continuă linia (nici wrap, nici plin până la ultima
          celulă) — linia tastată ocupă rânduri CONTIGUE;
        • textul rândului nu mai începe cu ce era acolo la prima tastă de după B (promptul pictat);
        • după B a trecut prin output o ştergere de ecran / RIS / regiune de scroll mutată şi nu avem
          ce verifica (nicio tastă încă). */
  get promptLost(): boolean {
    return this.promptLostReason() !== null
  }

  /** De ce e linia „pierdută" (null = nu e) — şi pentru diagnoză (fără text tastat: doar motivul). */
  promptLostReason(): string | null {
    if (this.promptMarker === null) return null
    const row = this.promptRow
    if (row === null) return 'marker-gone'
    // citirea conservatoare (B-ul original) e mereu judecată: dacă marcajul ei a dispărut (scrollback
    // tăiat) cât poziţia de citire e încă vie, nu mai avem ce judeca conservator → necunoscut
    const o = this.origMarker
    if (o !== null && (o.isDisposed || typeof o.line !== 'number' || o.line < 0)) return 'orig-gone'
    const cur = this.absCursor().row
    if (row > cur) return `below-cursor ${row}>${cur}`
    // contiguitate măsurată în celule (nu lungimea textului: spaţii finale, caractere late)
    for (let r = row; r < cur; r++) if (!this.rowContinues(r)) return `gap ${row}..${cur} @${r}`
    if (this.promptSnap !== null) {
      const line = this.term.buffer.active.getLine(row)
      // prefix EXACT, inclusiv spaţiile (nu „începe cu" pe textul tăiat la dreapta)
      if (!line || line.translateToString(false, 0, this.promptSnap.length) !== this.promptSnap) {
        return `prefix len=${this.promptSnap.length} col=${this.promptCol}`
      }
    } else if (this.screenSuspect) return 'screen-reset'
    return null
  }

  /** Prima tastă de după B: promptul e pictat — reţinem PREFIXUL lui (exact, cu spaţii): până la
      coloana lui B; sub tmux B poate cădea la coloana 0 (marcajele sosesc înaintea textului), atunci
      până la cursor, tăiat după ultimul terminator de prompt ($ # % > ❯ urmat de spaţiu) — fără
      textul din dreapta (RPROMPT, p10k, starship: review 3.6.13, M) şi fără un typeahead deja
      redesenat (care poate fi şters apoi). Ce e la dreapta cursorului la acel moment pe rândul
      promptului e un prompt din dreapta: îl ştim, ca citirea până la capătul liniei să-l scoată. */
  notePromptPainted(reanchor = false): void {
    if (this.promptMarker === null) return
    let row = this.promptRow
    if (row === null) return
    const cur = this.absCursor()
    // Re-ancorare (review 3.6.13): cel mult o dată per B şi DOAR când poziţia lui B e demonstrabil
    // veche — între ea şi cursor e un rând care nu continuă linia (sub tmux B soseşte înaintea
    // textului pictat, pe rândul comenzii anterioare), iar între ea şi cursor nu e un terminator de
    // prompt urmat de mai mult text (zsh push-line / print -z / fzf, typeahead redesenat: textul de
    // după prompt e o linie restaurată, nu se sare). Citirea de la B-ul ORIGINAL rămâne mereu printre
    // variantele judecate (pendingVariants), deci re-ancorarea poate doar ADĂUGA o citire.
    if (reanchor && !this.anchorTried && this.term.buffer.active.type !== 'alternate') {
      this.anchorTried = true
      // pe acelaşi rând, cu cursorul la STÂNGA lui B: B e dincolo de conţinut — mutarea începutului
      // spre stânga doar ADAUGĂ text citit
      const leftOfB = cur.row === row && cur.col < this.promptCol
      // începutul blocului de rânduri al liniei curente (rânduri care se continuă până la cursor)
      let first = cur.row
      while (first > row + 1 && this.rowContinues(first - 1)) first--
      // testul de „linie restaurată": cu B la coloana 0 pe un rând de deasupra, rândurile promptului
      // însuşi (un prompt pe două rânduri cu `%`/`>` urmat de text pe primul) nu sunt text tastat —
      // testăm doar blocul cursorului; cu B în interiorul rândului, textul de după B contează
      const restored = this.promptCol === 0
        ? this.restoredText(first, 0, cur)
        : this.restoredText(row, this.promptCol, cur)
      if (leftOfB || (cur.row > row && this.hasGap(row, cur.row) && !restored)) {
        const m = this.term.registerMarker(0)
        if (m) {
          if (!leftOfB) {
            // B era pe ALT rând (despărţit de linia de acum printr-un rând care nu o continuă): citirea
            // conservatoare porneşte la rândul de DUPĂ marcajul vechi, coloana 0 (netăiat, cu tot
            // promptul): un buffer restaurat pe mai multe rânduri (`rm -rf …` pe primul, cu un prompt
            // fără terminator) e judecat întreg, nu doar blocul cursorului. Poate doar ADĂUGA
            // confirmări (o comandă/un output vechi citit în plus), niciodată nu scoate text.
            const cm = this.term.registerMarker(row + 1 - cur.row)
            if (cm) {
              this.origMarker?.dispose()
              this.origMarker = cm
              this.origCol = 0
            }
          }
          this.reanchorAt(m, cur.col)
          row = this.promptRow
          if (row === null) return
        }
      }
    }
    if (this.promptSnap !== null) return
    const line = this.term.buffer.active.getLine(row)
    if (!line) return
    const full = line.translateToString(false)
    let snap: string
    if (this.promptCol > 0) snap = full.slice(0, this.promptCol)
    else {
      const before = cur.row === row ? full.slice(0, cur.col) : full.trimEnd()
      const m = /^(.*[$#%>\u276f] )/u.exec(before)
      snap = m ? m[1] : before
    }
    if (snap.trim()) this.promptSnap = snap
    if (cur.row === row && this.rightPrompt === null) {
      // textul din dreapta cursorului, ÎNCEPÂND după un şir de spaţii (un prompt din dreapta e separat
      // de cursor prin spaţii; textul lipit de cursor e text tastat, nu RPROMPT)
      const rest = full.slice(cur.col)
      const m = /^(\s{2,})(\S.*?)\s*$/u.exec(rest)
      const mk = m ? this.term.registerMarker(0) : undefined
      if (m && mk) this.rightPrompt = { text: m[2], marker: mk, col: cur.col + m[1].length }
    }
  }

  /** între rândurile from..to e un rând care nu continuă linia */
  private hasGap(from: number, to: number): boolean {
    for (let r = from; r < to; r++) if (!this.rowContinues(r)) return true
    return false
  }

  /** între (row, col) şi cursor e un terminator de prompt urmat de text: o linie restaurată */
  private restoredText(row: number, col: number, cur: { row: number; col: number }): boolean {
    const b = this.term.buffer.active
    let text = ''
    for (let r = row; r <= cur.row; r++) {
      const l = b.getLine(r)
      if (!l) continue
      text += l.translateToString(false, r === row ? col : 0, r === cur.row ? cur.col : undefined) + '\n'
    }
    return /[$#%>\u276f] +[^\s]/u.test(text)
  }

  /** Rândul continuă pe următorul: următorul e marcat wrap, sau rândul e plin până la ultima celulă. */
  private rowContinues(r: number): boolean {
    const b = this.term.buffer.active
    const line = b.getLine(r)
    if (!line) return false
    return !!b.getLine(r + 1)?.isWrapped || reachesLastCell(line, this.term.cols)
  }

  /** Output-ul (în ordinea parsării) a trecut printr-o ştergere de ecran (ED2/ED3), RIS sau o regiune
      de scroll care nu începe la rândul 1: dacă nu vine un B nou, rândul promptului e suspect. */
  noteScreenReset(): void {
    if (this.promptMarker !== null) this.screenSuspect = true
  }

  /** un B nou (sau seed-ul de la hub): poziţia originală ŞI cea de citire */
  private setPrompt(marker: IMarker | null, col: number): void {
    this.clearPrompt()
    this.promptMarker = marker
    this.origMarker = marker
    this.origCol = col
    this.promptCol = col
  }

  /** re-ancorarea: doar poziţia de citire se mută; cea originală rămâne (citirea conservatoare) */
  private reanchorAt(marker: IMarker, col: number): void {
    if (this.promptMarker && this.promptMarker !== this.origMarker && !this.promptMarker.isDisposed) this.promptMarker.dispose()
    this.promptMarker = marker
    this.promptCol = col
    this.promptSnap = null
    this.screenSuspect = false
  }

  private clearPrompt(): void {
    if (this.promptMarker && this.promptMarker !== this.origMarker) this.promptMarker.dispose()
    this.origMarker?.dispose()
    this.rightPrompt?.marker.dispose()
    this.promptMarker = null
    this.origMarker = null
    this.rightPrompt = null
    this.promptSnap = null
    this.screenSuspect = false
    this.anchorTried = false
  }

  /** comanda tocmai încheiată de un D din chunk-ul care se parsează acum: restul chunk-ului îi
      aparţine încă (sub tmux, D poate sosi înaintea ultimelor rânduri pictate) — vezi feedTail */
  private justEnded: Command | null = null

  constructor(term: Terminal) {
    this.term = term
  }

  /** Uită starea acumulată: după un `term.reset()` (replay de istoric la (re)conectare)
      rândurile şi markerii de dinainte nu mai există, iar o comandă „în curs" ar fi
      închisă de primul D din replay şi raportată ca istoric — cu text luat de pe alte
      rânduri (prompturi, bucăţi de output). Vezi replayRef din SessionView. */
  reset(): void {
    for (const c of this.commands) c.startMarker.dispose()
    this.commands = []
    this.current = null
    this.justEnded = null
    this.clearPrompt()
    this.promptCol = 0
    this.pendingText = null
    this.staleFlag = true
    this.runningUnseen = false
    this.replayLast = null
    this.replayB?.dispose()
    this.replayB = null
    this.onChange?.()
  }

  /** Un marcaj OSC 133 din istoricul REJUCAT: nu e activitate live (îl ignorăm), dar dovedeşte că
      shell-ul are integration — deci „nu sunt la prompt" după replay înseamnă „nu ştiu", nu „fără
      integration" (re-review 3.6.12, M1).
      Ultimul marcaj rejucat NU spune dacă rulează ceva ACUM (verificare 3.6.12, F1): tail-ul de la
      ataşare / reconectare (read_tail) omite octeţii încă ne-scrişi pe disc (până la ~2,5 s), deci un
      C rejucat poate avea D/A/B-ul lui lipsă — panoul e de fapt la prompt, cu o linie nevăzută. Iar
      clientul nu poate deosebi un resync fără gol (resume/unlock, flush până la cutoff) de unul cu
      gol (ataşare, client lent): mesajul `resync` nu spune. Deci linia rămâne necunoscută — până
      la starea hub-ului (applyHubState, 3.6.13), care ştie ce a fost LIVE şi dacă replay-ul a fost
      complet. Aici doar ţinem minte ultimul marcaj rejucat şi, pentru B, unde a căzut pe ecran. */
  noteReplayedMark(data: string): void {
    const kind = data.split(';')[0]
    if (kind === 'B') this.integratedFlag = true
    this.replayB?.dispose()
    this.replayB = null
    if (this.term.buffer.active.type === 'alternate') { this.replayLast = '?'; return }
    this.replayLast = kind
    if (kind === 'B') {
      this.replayB = this.term.registerMarker(0) ?? null
      this.replayBCol = this.absCursor().col
    }
  }

  /** Starea OSC 133 a hub-ului (mesajul `osc133`), aplicată DUPĂ ce xterm a parsat replay-ul şi
      ÎNAINTE de orice octet live (gateway-ul o trimite exact în punctul în care fluxul live începe
      să curgă spre noi). Fail-closed — orice nepotrivire lasă linia necunoscută:
        • `integrated` → integrat (doar adaugă: un `false` nu şterge ce am văzut noi) — rezidualul
          „replay fără niciun marcaj": hub-ul a văzut B-ul live, deci linia e necunoscută, nu „fără
          integrare". Vine DOAR aici, după un replay trimis, nu în `init` (review 3.6.13, L7: `init`
          pleacă înainte de verificarea de step-up / blocare);
        • `last === 'C'`: ultimul marcaj LIVE e un început de execuţie care urmează unui prompt (hub-ul
          raportează C doar după B / B→E, şi nu de pe ecranul alternativ — review 3.6.13, L1) →
          rulează ceva (ssh, `sudo -i`, un REPL): Enter-ul merge la program, ca în calea live
          (runningUnseen). Nu depinde de replay;
        • `last === 'B'` + `synced` (replay-ul se termină exact în punctul live şi conţine marcajul)
          + ultimul marcaj REJUCAT tot B, pe ecranul principal → linia e cunoscută: de la poziţia
          acelui B la cursor, exact cum ar fi citit-o un B live;
        • orice altceva (A / D / null, nesincronizat, alt ultim marcaj rejucat) → rămâne necunoscută
          până la următorul B live.
      Se aplică doar imediat după un replay (stale, fără comandă şi fără B live de atunci).
      Întoarce true dacă a schimbat ceva din starea liniei. */
  applyHubState(s: unknown): boolean {
    if (!s || typeof s !== 'object') return false
    const { integrated, last, synced } = s as Record<string, unknown>
    if (integrated === true) this.integratedFlag = true
    if (!this.staleFlag || this.current !== null || this.promptMarker !== null || this.runningUnseen) return false
    if (last === 'C') {
      this.runningUnseen = true
      this.onChange?.()
      return true
    }
    const b = this.replayB
    if (last === 'B' && synced === true && this.replayLast === 'B' && b && !b.isDisposed && b.line >= 0
      && this.term.buffer.active.type !== 'alternate') {
      this.replayB = null                     // markerul trece la prompt (nu se mai eliberează ca „rejucat")
      this.setPrompt(b, this.replayBCol)
      this.staleFlag = false
      this.onChange?.()
      return true
    }
    return false
  }

  /** shell integration văzută (un B, live sau în replay) */
  get integrated(): boolean {
    return this.integratedFlag
  }

  /** linia tastată e necunoscută: reset() (replay) fără un B live de atunci */
  get stale(): boolean {
    return this.staleFlag
  }

  /** Putem crede `atPrompt()` / `pendingCommand()`? false = panou cu shell integration, pe ecranul
      principal, fără comandă în curs, dar fie după un replay fără prompt live de atunci, fie
      (încă) fără B — linia tastată acolo poate fi orice (ex. o comandă rechemată cu ↑ înainte de
      reconectare). Fără shell integration: true (degradare ca înainte — nu putem citi nimic). */
  lineKnown(): boolean {
    if (!this.integratedFlag) return true
    if (this.current !== null || this.runningUnseen) return true   // rulează ceva: Enter-ul merge la program
    if (this.term.buffer.active.type === 'alternate') return true   // TUI: Enter-ul nu e o linie de shell
    // după replay: necunoscut până la un B live, CHIAR dacă replay-ul s-a oprit într-un C (vezi
    // noteReplayedMark — F1) — cu excepţia stării hub-ului (applyHubState, 3.6.13): un C LIVE
    // (runningUnseen, mai sus) sau un B live aflat în replay-ul complet (promptRow din replay)
    return !this.staleFlag && this.promptRow !== null && !this.promptLost
  }

  /** Octeţii care curg spre terminal, daţi de SessionView cât rulează o comandă.
      Ecranul nu e o sursă de încredere sub tmux (marcajele vin out-of-band, panoul e
      repictat separat), deci output-ul „exact" se ia din flux, nu din rânduri. */
  feed(chunk: string): void {
    const cmd = this.current ?? this.justEnded
    if (!cmd) return
    const cur = cmd.captured ?? ''
    if (cur.length > CAPTURE_MAX) return          // plafon: o comandă vorbăreaţă nu umflă RAM-ul
    cmd.captured = cur + chunk
  }

  /** Captura cere octeţi? (o comandă rulează, sau una tocmai s-a încheiat în chunk-ul curent) */
  get capturing(): boolean {
    return this.current !== null || this.justEnded !== null
  }

  /** Sfârşitul unui chunk de output: comanda încheiată în el nu mai primeşte octeţi. Comportamentul
      de dinainte (tot chunk-ul cu D-ul intra în captură; promptul de la coadă îl taie outputOf),
      dar în ordinea PARSĂRII, nu la sosire (e2e 3.6.13). */
  endChunk(): void {
    this.justEnded = null
  }

  /** Shell-ul aşteaptă la prompt, după marcajele shell integration: B (sfârşit de prompt) văzut,
      nicio comandă pornită de atunci (C), ecranul principal. Un program pornit din shell (mc, vim,
      less, `sudo -i`) emite C înainte să ruleze, deci nu mai suntem „la prompt" până la D + B.
      Fără shell integration: mereu false. */
  atPrompt(): boolean {
    return this.promptRow !== null && this.current === null && !this.runningUnseen
      && this.term.buffer.active.type !== 'alternate'
  }

  /** rulează o comandă acum? (SessionView evită decodarea inutilă a fluxului) */
  get running(): boolean {
    return this.current !== null
  }

  private absCursor(): { row: number; col: number } {
    const b = this.term.buffer.active
    return { row: b.baseY + b.cursorY, col: b.cursorX }
  }

  /** Textul comenzii = ce s-a tastat între B (sfârșit de prompt) și C (execuție). */
  private readCommand(): string {
    const b = this.term.buffer.active
    const end = this.absCursor()
    if (this.promptRow == null) return ''
    let out = ''
    for (let row = this.promptRow; row <= end.row; row++) {
      const line = b.getLine(row)
      if (!line) continue
      const from = row === this.promptRow ? this.promptCol : 0
      const to = row === end.row ? end.col : line.length
      out += line.translateToString(false, from, to)
      // un rând continuat prin wrap (linie lungă) NU e o despărţire: fără spaţiu, altfel `rm -rf /tm`
      // + `p` pe rândul următor se citea „rm -rf /tm p", iar ecoul tastelor nu se mai potrivea
      // (3.6.13, e2e: linia lungă tastată rapid rămânea „fără ecou")
      // Sub tmux rândurile continuate sunt repictate explicit (fără isWrapped), deci şi un rând umplut
      // până la ultima coloană e o continuare — fără spaţiu (review 3.6.13, L3: comparaţia ecoului e
      // exactă, nu mai ignoră spaţiile)
      if (row !== end.row && !b.getLine(row + 1)?.isWrapped && !reachesLastCell(line, this.term.cols)) out += ' '
    }
    return out.trim()
  }

  /** Varianta „cu spaţiu" a liniei, când un rând plin până la ultima celulă e urmat de unul care NU e
      marcat ca wrap: poate fi o continuare (tmux repictează fără isWrapped) sau un rând nou (Ctrl+V
      Ctrl+J, zsh multi-linie) — ambiguu, deci guardrail-ul verifică AMBELE variante (review 3.6.13,
      L-b). null = nicio ambiguitate. */
  pendingAlt(): string | null {
    if (this.promptRow == null || this.term.buffer.active.type === 'alternate') return null
    const b = this.term.buffer.active
    const end = this.absCursor()
    let ambiguous = false
    let out = ''
    for (let row = this.promptRow; row <= end.row; row++) {
      const line = b.getLine(row)
      if (!line) continue
      const from = row === this.promptRow ? this.promptCol : 0
      const to = row === end.row ? end.col : line.length
      out += line.translateToString(false, from, to)
      if (row !== end.row && !b.getLine(row + 1)?.isWrapped) {
        if (reachesLastCell(line, this.term.cols)) ambiguous = true
        out += ' '
      }
    }
    return ambiguous ? (out.trim() || null) : null
  }

  /** Variantele liniei pe care guardrail-ul le verifică ÎN PLUS faţă de pendingCommand (până la
      cursor), verdictul cel mai strict câştigă (review 3.6.13): lipirea ambiguă cu spaţiu (pendingAlt)
      şi linia citită până la CAPĂTUL ei logic — textul de după cursor rulează şi el (↑ recheamă
      `rm -rf /srv/data`, Home / ← apoi `sudo `: citit doar până la cursor se vedea „sudo "). Un prompt
      din dreapta (RPROMPT) cunoscut de la prima tastă e scos de la coadă; un text fantomă (sugestia
      zsh) poate doar adăuga confirmări, nu „necunoscut". */
  pendingVariants(): string[] {
    if (this.promptRow == null || this.term.buffer.active.type === 'alternate') return []
    const base = this.pendingCommand()
    const out = new Set<string>()
    const alt = this.pendingAlt()
    if (alt) out.add(alt)
    for (const withSpace of [false, true]) {
      // CONSERVATOR: de la B-ul ORIGINAL până la capătul liniei, netăiat — mereu judecat
      const o = this.origMarker
      const oRow = o && !o.isDisposed && typeof o.line === 'number' && o.line >= 0 ? o.line : null
      if (oRow !== null) {
        const full = this.readToEnd(oRow, this.origCol, withSpace, false)
        if (full) out.add(full)
      }
      // de la poziţia de citire (eventual re-ancorată), netăiat şi — doar ca variantă în plus — fără RPROMPT
      const row = this.promptRow
      if (row !== null) {
        const full = this.readToEnd(row, this.promptCol, withSpace, false)
        if (full) out.add(full)
        const cut = this.readToEnd(row, this.promptCol, withSpace, true)
        if (cut) out.add(cut)
      }
    }
    if (base) out.delete(base)
    return [...out]
  }

  /** De la (start, col) până la capătul liniei logice care conţine cursorul (rândurile care o
      continuă). `cutRight`: fără promptul din dreapta — doar dacă rândul şi coloana lui înregistrate
      îl ţin EXACT şi niciun text tastat nu ajunge în dreptul lui (e doar o variantă în plus). */
  private readToEnd(start: number, startCol: number, spaceOnAmbiguous: boolean, cutRight: boolean): string | null {
    const b = this.term.buffer.active
    const cur = this.absCursor()
    let last = cur.row
    for (let n = 0; n < 50 && this.rowContinues(last) && b.getLine(last + 1); n++) last++
    const rp = this.rightPrompt
    let rpRow = -1
    if (cutRight) {
      if (!rp || rp.marker.isDisposed || typeof rp.marker.line !== 'number') return null
      rpRow = rp.marker.line
      const l = b.getLine(rpRow)
      if (!l || l.translateToString(false, rp.col, rp.col + rp.text.length) !== rp.text) return null
      // textul tastat (până la cursor) nu ajunge la el, iar între cursor şi el sunt doar spaţii
      if (cur.row === rpRow && cur.col >= rp.col) return null
      if (cur.row === rpRow && l.translateToString(false, cur.col, rp.col).trim()) return null
    }
    let out = ''
    for (let row = start; row <= last; row++) {
      const line = b.getLine(row)
      if (!line) continue
      const to = cutRight && row === rpRow ? rp!.col : undefined
      out += line.translateToString(row === last && to === undefined, row === start ? startCol : 0, to)
      if (row !== last) {
        const wrapped = !!b.getLine(row + 1)?.isWrapped
        if (!wrapped && (!reachesLastCell(line, this.term.cols) || spaceOnAmbiguous)) out += ' '
      }
    }
    out = out.trim()
    return out || null
  }

  /** Comanda TASTATĂ acum, neexecutată încă (promptRow→cursor). null dacă nu suntem
      la un prompt cu shell integration. Folosit de guardrail-ul de comenzi la Enter,
      ÎNAINTE ca Enter să ajungă la host (C n-a fost încă emis, deci promptRow e valid). */
  pendingCommand(): string | null {
    if (this.promptRow == null) return null
    if (this.term.buffer.active.type === 'alternate') return null
    const t = this.readCommand()
    return t || null
  }

  handle(data: string): void {
    // Ecran alternativ (vim, htop, less): rândurile de acolo dispar la ieșire,
    // deci markerele ar fi invalide, iar „cursorul" nu are legătură cu istoricul.
    // Ignorăm complet — comanda care a pornit TUI-ul se închide normal la D,
    // pentru că D vine după ce shell-ul a revenit pe ecranul principal.
    const [kind, ...rest] = data.split(';')
    if (kind === 'B') this.integratedFlag = true
    if (this.term.buffer.active.type === 'alternate') return

    switch (kind) {
      case 'A':                    // început de prompt
        break
      case 'B':                    // promptul s-a terminat: aici începe comanda
        {
          const c = this.absCursor()
          this.setPrompt(this.term.registerMarker(0) ?? null, c.col)
          this.staleFlag = false    // un prompt LIVE: linia de aici încolo o vedem
        }
        break
      case 'E':                    // textul EXACT al comenzii, trimis de shell
        // Sub tmux, marcajele trec prin DCS passthrough şi ajung ÎNAINTEA textului
        // promptului, deci poziţia cursorului la B nu spune unde începe comanda — citeam
        // promptul ca parte din ea. Când shell-ul ne dă textul, nu mai ghicim din ecran.
        this.pendingText = rest.join(';')     // comanda poate conţine ';'
        break
      case 'C': {                  // execuția începe
        this.justEnded = null
        const text = this.pendingText ?? this.readCommand()
        this.pendingText = null
        if (!text) { this.clearPrompt(); break }
        // marker pe rândul curent: de aici încolo e OUTPUT-ul comenzii
        const marker = this.term.registerMarker(0)
        if (!marker) break
        this.current = {
          id: this.nextId++,
          text,
          startMarker: marker,
          startedAt: Date.now(),
        }
        this.onStart?.(this.current)
        this.clearPrompt()
        break
      }
      case 'D': {                  // comanda s-a terminat (cu exit code)
        this.runningUnseen = false   // şi una pornită înainte de replay (applyHubState)
        if (!this.current) break
        const code = Number(rest[0])
        this.current.exitCode = Number.isFinite(code) ? code : undefined
        this.current.endedAt = Date.now()
        this.current.endMarker = this.term.registerMarker(0) ?? undefined
        this.commands.push(this.current)
        // plafon: o sesiune lungă nu trebuie să crească la infinit
        if (this.commands.length > 500) {
          this.commands.shift()?.startMarker.dispose()
        }
        const done = this.current
        this.current = null
        this.justEnded = done
        this.onChange?.()
        this.onCommand?.(done)
        break
      }
    }
  }

  /** Output-ul EXACT al unei comenzi: rândurile dintre C (începutul execuției)
      și D (sfârșitul ei) — fără prompt, fără linia de comandă, fără nimic din
      ce a urmat. Reguli dure, pentru că textul ăsta ajunge în clipboard și
      poate fi lipit înapoi într-un shell:
       - marker-ul de la C e DEJA primul rând de output (Enter a mutat cursorul),
         deci NU sărim un rând peste el;
       - fără marker de final (comandă încă în execuție) NU ghicim până la cursor
         — am înghiți prompturile și comenzile de după (bug v1.0.20);
       - markerele „moarte" (linia a ieșit din scrollback → line < 0) invalidează
         extragerea, în loc să producă o felie aiurea. */
  outputOf(cmd: Command): string | null {
    // sursa de încredere: octeţii capturaţi între C şi D. Sub tmux ecranul e repictat
    // asincron faţă de marcaje, deci extragerea din rânduri dădea când prea mult (prompturi
    // şi comenzi străine), când prea puţin (clipboard gol) — în funcţie de timing.
    if (cmd.captured != null) {
      const out = plain(cmd.captured)
        .split('\n')
        .map((l) => l.replace(/\s+$/, ''))
      while (out.length && !out[0].trim()) out.shift()
      while (out.length && !out[out.length - 1].trim()) out.pop()
      // Reziduuri de repictare. Sub tmux marcajele trec prin DCS passthrough, deci ordinea
      // lor faţă de textul pictat NU e garantată în niciun sens: fereastra C→D poate prinde
      // ecoul comenzii repictat (oriunde, nu doar pe prima linie) sau promptul URMĂTOR, dacă
      // D ajunge după ce shell-ul l-a scris deja. Ambele sunt periculoase, nu doar urâte:
      // textul ăsta ajunge în clipboard şi, lipit într-un shell, se EXECUTĂ (regresia v1.0.20).
      const clean = (keep: number) => out.length > keep
      if (cmd.text) {
        for (let i = out.length - 1; i >= 0 && clean(1); i--) {
          if (out[i].trimEnd().endsWith(cmd.text)) out.splice(i, 1)
        }
      }
      // Promptul, doar de la coadă şi doar dacă chiar arată a prompt: se termină în $ # % >
      // ŞI conţine înaintea lui un semn de prompt (@ : ~ /). „total 42 $" nu se potriveşte.
      // Nu golim niciodată tot — un clipboard gol e altă regresie, prinsă tot în CI.
      const PROMPT_RE = /^[#$%>]$|[@:~/][^\s]*\s*[#$%>]$/
      for (let n = 0; n < 2 && clean(1); n++) {
        const last = out[out.length - 1].trim()
        if (!last || !PROMPT_RE.test(last)) break
        out.pop()
      }
      return out.join('\n')
    }
    const b = this.term.buffer.active
    const from = cmd.startMarker.line
    // Sfârşitul se calculează ACUM (la copiere), nu se ia din markerul de la D: sub tmux
    // marcajele vin out-of-band prin DCS passthrough, iar la momentul lui D ultimele rânduri
    // de output pot să nu fie încă pictate — markerul cădea peste ele şi clipboardul ieşea
    // gol. Delimitator de încredere: începutul comenzii URMĂTOARE (sau cursorul, dacă asta
    // e ultima). Markerul de la D rămâne plasa de siguranţă când nu avem nimic mai bun.
    const idx = this.commands.indexOf(cmd)
    const next = idx >= 0 ? this.commands[idx + 1] : undefined
    const nextLine = next?.startMarker.line ?? -1
    const cursorLine = b.baseY + b.cursorY
    let to = nextLine > from ? nextLine : (cmd.endMarker?.line ?? -1)
    // până la cursor DOAR pentru ultima comandă: dacă după ea mai sunt comenzi (dar marcajele lor nu
    // ajută — sub tmux pot cădea pe acelaşi rând), cursorul ar lua prompturile şi comenzile lor, iar
    // textul ăsta ajunge în clipboard şi, lipit, se execută (e2e 3.6.13). Mai bine „nu pot extrage".
    if (to <= from && cmd.endedAt && cursorLine > from && !next) to = cursorLine
    if (from < 0 || to < 0 || to <= from) return null
    const lines: string[] = []
    for (let row = from; row < to; row++) {
      const line = b.getLine(row)
      if (line) lines.push(line.translateToString(true).replace(/\s+$/, ''))
    }
    while (lines.length && !lines[lines.length - 1].trim()) lines.pop()
    while (lines.length && !lines[0].trim()) lines.shift()
    // Sub tmux, marcajele vin prin DCS passthrough şi ajung la terminal ÎNAINTEA textului
    // pictat în panou (tmux le scoate out-of-band, conţinutul îl repictează separat cu
    // poziţionări absolute), deci markerul de la C poate cădea cu rânduri bune înainte de
    // comandă: „copiază output-ul" livra prompturi şi comenzi străine — text care ajunge în
    // clipboard şi poate fi lipit înapoi într-un shell (regresia v1.0.20, altă cauză).
    // Delimitatorul de încredere e linia în care s-a ECOUT comanda, iar textul ei ne e dat
    // acum de shell (marcajul E): tăiem tot până la ULTIMA astfel de linie inclusiv.
    // niciodată nu tăiem TOT: dacă linia ecoului e singura pe care o avem, e mai bine s-o
    // livrăm decât un clipboard gol (regresie prinsă de E2E-ul pe tmux, în CI)
    if (cmd.text) {
      for (let i = lines.length - 2; i >= 0; i--) {
        if (lines[i].trimEnd().endsWith(cmd.text)) { lines.splice(0, i + 1); break }
      }
    }
    return lines.join('\n')
  }

  dispose(): void {
    this.replayB?.dispose()
    this.replayB = null
    this.clearPrompt()
    for (const c of this.commands) {
      c.startMarker.dispose()
      c.endMarker?.dispose()
    }
    this.commands = []
    this.current = null
    this.justEnded = null
  }
}

export const cmdDuration = (c: Command): string => {
  if (!c.endedAt) return ''
  const ms = c.endedAt - c.startedAt
  if (ms < 1000) return `${ms} ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`
}

/** Împarte un chunk de output DUPĂ fiecare marcaj OSC 133 (`ESC ]133;…` terminat cu BEL sau ST), ca
    SessionView să poată da tracker-ului fiecare bucată în ORDINEA PARSĂRII: o bucată aparţine
    comenzii care rula când a început (marcajul de la capătul ei schimbă starea abia după). Înainte,
    octeţii se dădeau la SOSIRE, după starea de atunci — iar xterm parsează asincron: un C şi
    output-ul lui sosite înaintea parsării lui C nu ajungeau în captură, iar „copiază output-ul" cădea
    pe extragerea de pe ecran (e2e 3.6.13: prompturi şi comenzi ulterioare în clipboard). */
export function splitAfterMarks(b: Uint8Array): Uint8Array[] {
  const out: Uint8Array[] = []
  let from = 0
  let i = 0
  while (true) {
    const e = b.indexOf(0x1b, i)
    if (e < 0) break
    i = e + 1
    // ESC ] 1 3 3 ;
    if (b[e + 1] !== 0x5d || b[e + 2] !== 0x31 || b[e + 3] !== 0x33 || b[e + 4] !== 0x33 || b[e + 5] !== 0x3b) continue
    let t = e + 6
    let end = -1
    while (t < b.length) {
      if (b[t] === 0x07) { end = t + 1; break }
      if (b[t] === 0x1b) { end = b[t + 1] === 0x5c ? t + 2 : t; break }
      t++
    }
    if (end < 0) break                       // marcaj rupt la capătul chunk-ului: restul rămâne împreună
    out.push(b.subarray(from, end))
    from = end
    i = end
  }
  if (from < b.length || out.length === 0) out.push(b.subarray(from))
  return out
}

/** Rândul ajunge până în ultima CELULĂ (nu lungimea şirului: un caracter lat ocupă două celule). */
function reachesLastCell(line: { getCell?: (x: number) => { getChars(): string; getWidth(): number } | undefined }, cols: number): boolean {
  if (!cols || typeof line.getCell !== 'function') return false
  const last = line.getCell(cols - 1)
  if (!last) return false
  if (last.getChars() !== '') return true
  // a doua jumătate a unui caracter lat (lăţime 0) aflat pe ultimele două celule
  const prev = cols >= 2 ? line.getCell(cols - 2) : undefined
  return last.getWidth() === 0 && !!prev && prev.getWidth() === 2
}

/** Output-ul conţine o ştergere de ecran (ED2 / ED3), RIS sau o regiune de scroll (DECSTBM) care NU
    începe la rândul 1 — mişcări de rânduri pe care markerele xterm nu le urmează (vezi promptLost). */
export function screenResetIn(b: Uint8Array): boolean {
  for (let i = b.indexOf(0x1b); i >= 0; i = b.indexOf(0x1b, i + 1)) {
    if (b[i + 1] === 0x63) return true                                   // ESC c (RIS)
    if (b[i + 1] !== 0x5b) continue
    let j = i + 2
    let p1 = ''
    while (j < b.length && b[j] >= 0x30 && b[j] <= 0x39) p1 += String.fromCharCode(b[j++])
    if ((p1 === '2' || p1 === '3') && b[j] === 0x4a) return true          // CSI 2 J / CSI 3 J
    if (b[j] === 0x3b) {                                                   // CSI t ; b r
      j++
      while (j < b.length && b[j] >= 0x30 && b[j] <= 0x39) j++
      if (b[j] === 0x72 && p1 !== '' && Number(p1) > 1) return true
    }
  }
  return false
}

/** screenResetIn peste o graniţă de chunk (review 3.6.13, LOW-3): `carry` = începutul NETERMINAT al
    unei secvenţe de la capătul bucăţii anterioare (ESC, ESC [, ESC [ cifre / ;), cel mult 16 octeţi —
    niciodată o secvenţă completă, ca să nu fie numărată de două ori (de ex. după un B nou). */
export function screenResetScan(carry: Uint8Array, part: Uint8Array): { hit: boolean; carry: Uint8Array } {
  const data = carry.length ? concatBytes(carry, part) : part
  const hit = screenResetIn(data)
  const tailFrom = Math.max(0, data.length - 16)
  const e = data.lastIndexOf(0x1b)
  let next: Uint8Array = new Uint8Array(0)
  if (e >= tailFrom) {
    const t = data.subarray(e)
    let ok = true
    for (let i = 1; i < t.length && ok; i++) {
      const c = t[i]
      ok = i === 1 ? c === 0x5b : (c >= 0x30 && c <= 0x39) || c === 0x3b
    }
    if (ok) next = t.slice()
  }
  return { hit, carry: next }
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}
