/* Link-uri de replay (3.5.12): partea fără DOM — rutare, alegerile de expirare, parsarea .cast.
   Separat de componente ca să fie testat cu vitest (lib/replay.test.ts). */

/** [timp, tip ('o' | 'r' | …), date] — un eveniment asciicast v2 */
export type CastEvent = [number, string, string]

/** Expirarea e o ALEGERE fixă, nu un câmp liber: serverul acceptă doar aceste ore (max 7 zile). */
export const REPLAY_EXPIRY_HOURS = [1, 24, 168] as const
export type ReplayExpiry = (typeof REPLAY_EXPIRY_HOURS)[number]
export const REPLAY_DEFAULT_EXPIRY: ReplayExpiry = 24
export const REPLAY_LABEL_MAX = 80

/** Tokenul din `#/replay/<token>` (base64url, cum îl emite `secrets.token_urlsafe`), altfel null.
    Tokenul stă în FRAGMENT: nu pleacă la server la încărcarea paginii şi nu apare în Referer. */
export function replayTokenFromHash(hash: string): string | null {
  const m = /^#\/replay\/([A-Za-z0-9_-]{20,128})$/.exec(hash)
  return m ? m[1] : null
}

/** Antetele cererilor publice: tokenul în `X-Replay-Token`, niciodată în cale. */
export function replayHeaders(token: string): Record<string, string> {
  return { 'X-Replay-Token': token }
}

/** Parsează un fişier .cast: antetul (`{"version"…}`) şi liniile corupte se sar — o linie stricată
    nu trebuie să oprească redarea. */
export function parseCast(text: string): CastEvent[] {
  const evs: CastEvent[] = []
  for (const line of text.split('\n')) {
    if (!line.trim() || line.startsWith('{')) continue
    try {
      const e = JSON.parse(line)
      if (Array.isArray(e) && typeof e[0] === 'number' && typeof e[2] === 'string') evs.push(e as CastEvent)
    } catch {
      /* linie coruptă: o sărim */
    }
  }
  return evs
}

/** Eticheta tradusă a unei expirări (cheile `replay.exp.1|24|168`). */
export function expiryKey(h: ReplayExpiry): string {
  return `replay.exp.${h}`
}
