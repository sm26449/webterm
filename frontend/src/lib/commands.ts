import { IMarker, Terminal } from '@xterm/xterm'
import type { CommandGuard, CommandRule } from './api'

/** Prima regulă care se potrivește pe comandă (regex, case-insensitive). null = trece.
    Regex invalid e ignorat (serverul îl validează la salvare, dar suntem defensivi). */
export function matchCommandRule(cmd: string, guard: CommandGuard | null | undefined): CommandRule | null {
  if (!guard?.enabled || !cmd) return null
  for (const r of guard.rules) {
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
    .map((line) => line.split('\r').pop() ?? '')   // CR = rescrie rândul (bare de progres)
    .join('\n')
}

const CAPTURE_MAX = 256 * 1024      // per comandă; peste atât, output-ul se citeşte de pe ecran

export class CommandTracker {
  private term: Terminal
  private nextId = 1
  private promptRow: number | null = null    // rândul absolut al lui B
  private promptCol = 0
  private pendingText: string | null = null  // textul comenzii, dacă shell-ul ni-l trimite (E)
  private current: Command | null = null
  commands: Command[] = []
  onChange?: () => void
  /** fire-uit o dată per comandă finalizată (pt. istoricul global) */
  onCommand?: (cmd: Command) => void
  /** fire-uit când comanda e CREATĂ (la C), înainte de output. Folosit de player
      ca să atașeze timpul din .cast la momentul potrivit (comenzile goale n-au C). */
  onStart?: (cmd: Command) => void

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
    this.promptRow = null
    this.promptCol = 0
    this.pendingText = null
    this.onChange?.()
  }

  /** Octeţii care curg spre terminal, daţi de SessionView cât rulează o comandă.
      Ecranul nu e o sursă de încredere sub tmux (marcajele vin out-of-band, panoul e
      repictat separat), deci output-ul „exact" se ia din flux, nu din rânduri. */
  feed(chunk: string): void {
    if (!this.current) return
    const cur = this.current.captured ?? ''
    if (cur.length > CAPTURE_MAX) return          // plafon: o comandă vorbăreaţă nu umflă RAM-ul
    this.current.captured = cur + chunk
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
      if (row !== end.row) out += ' '
    }
    return out.trim()
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
    if (this.term.buffer.active.type === 'alternate') return

    const [kind, ...rest] = data.split(';')
    switch (kind) {
      case 'A':                    // început de prompt
        break
      case 'B':                    // promptul s-a terminat: aici începe comanda
        {
          const c = this.absCursor()
          this.promptRow = c.row
          this.promptCol = c.col
        }
        break
      case 'E':                    // textul EXACT al comenzii, trimis de shell
        // Sub tmux, marcajele trec prin DCS passthrough şi ajung ÎNAINTEA textului
        // promptului, deci poziţia cursorului la B nu spune unde începe comanda — citeam
        // promptul ca parte din ea. Când shell-ul ne dă textul, nu mai ghicim din ecran.
        this.pendingText = rest.join(';')     // comanda poate conţine ';'
        break
      case 'C': {                  // execuția începe
        const text = this.pendingText ?? this.readCommand()
        this.pendingText = null
        if (!text) { this.promptRow = null; break }
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
        this.promptRow = null
        break
      }
      case 'D': {                  // comanda s-a terminat (cu exit code)
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
    if (to <= from && cmd.endedAt && cursorLine > from) to = cursorLine
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
    for (const c of this.commands) {
      c.startMarker.dispose()
      c.endMarker?.dispose()
    }
    this.commands = []
    this.current = null
  }
}

export const cmdDuration = (c: Command): string => {
  if (!c.endedAt) return ''
  const ms = c.endedAt - c.startedAt
  if (ms < 1000) return `${ms} ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`
}
