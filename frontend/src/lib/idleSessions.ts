import type { Session } from './api'

/* Igiena sesiunilor inactive (3.7.1) — partea fără React.

   Serverul (gateway/app/idlesess.py) decide ce e inactiv, notifică şi închide; aici doar:
   - ce notificări merită un toast cu „Păstrează deschisă" / „Închide acum" (sesiunile TALE, câte
     un toast per notificare — reţinut în localStorage, ca un reload să nu-l arate din nou);
   - validarea numerelor din Setări (aceleaşi limite ca serverul, care oricum le verifică). */

const SEEN_KEY = 'wt-idle-notices-seen'
const SEEN_MAX = 200

/** cheia unei notificări: aceeaşi sesiune notificată din nou (după folosire) = notificare nouă */
export function noticeKey(s: Pick<Session, 'id' | 'idle_notice'>): string | null {
  return s.idle_notice ? `${s.id}@${Math.round(s.idle_notice.at)}` : null
}

/** sesiunile vii ale contului `myId` cu o notificare încă neanunţată în acest browser */
export function pendingIdleNotices(sessions: Session[], myId: number | null | undefined, seen: Set<string>): Session[] {
  if (myId == null) return []
  return sessions.filter((s) => {
    const k = noticeKey(s)
    return k !== null && s.state === 'live' && !s.keep_open && s.created_by_id === myId && !seen.has(k)
  })
}

export function loadSeen(): Set<string> {
  try {
    const raw = JSON.parse(localStorage.getItem(SEEN_KEY) || '[]')
    return new Set(Array.isArray(raw) ? raw.filter((x): x is string => typeof x === 'string') : [])
  } catch {
    return new Set()
  }
}

export function saveSeen(seen: Set<string>): void {
  try {
    localStorage.setItem(SEEN_KEY, JSON.stringify([...seen].slice(-SEEN_MAX)))
  } catch {
    /* stocare indisponibilă: toast-ul poate reapărea la reload, nimic mai rău */
  }
}

/** un număr de zile valid în [lo, hi] (întreg), altfel null — formularul nu trimite valori greşite */
export function parseDays(v: string, lo: number, hi: number): number | null {
  if (!/^\d{1,3}$/.test(v.trim())) return null
  const n = Number(v.trim())
  return n >= lo && n <= hi ? n : null
}
