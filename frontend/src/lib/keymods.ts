/* Modificatorii latch-uiţi ai keybar-ului tactil (MobileKeybar), separaţi ca să fie testabili. */

/** Aplică modificatorii aprinşi (Ctrl/Alt) pe secvenţa unei taste, ca xterm:
    · tastă de un caracter: Ctrl o maschează în caracter de control (dacă e mascabilă),
      Alt o prefixează cu ESC (meta-sends-escape) — deci Ctrl+Alt+x = ESC + ^X;
    · CSI de navigare (`ESC [ A`, `ESC [ H`, `ESC [ 5 ~`): parametrul de modificator xterm
      (1 + 2·Alt + 4·Ctrl) — `ESC [ 1 ; 3 A` = Alt+↑, `ESC [ 5 ; 5 ~` = Ctrl+PgUp;
    · rest (Esc, Tab, rotiţa): Alt = prefix ESC, Ctrl nu are formă standard → neschimbat. */
export function applyMods(seq: string, ctrl: boolean, alt: boolean): string {
  if (!ctrl && !alt) return seq
  if (seq.length === 1) {
    let s = seq
    if (ctrl && s >= '@') s = String.fromCharCode(s.toUpperCase().charCodeAt(0) & 0x1f)
    return alt ? '\x1b' + s : s
  }
  const m = 1 + (alt ? 2 : 0) + (ctrl ? 4 : 0)
  // fără regex cu \x1b (eslint no-control-regex): ESC + '[' se verifică separat
  const body = seq.startsWith('\x1b[') ? seq.slice(2) : null
  if (body !== null && /^[A-Za-z]$/.test(body)) return `\x1b[1;${m}${body}`
  const tilde = body?.match(/^(\d+)~$/)
  if (tilde) return `\x1b[${tilde[1]};${m}~`
  return alt ? '\x1b' + seq : seq
}
