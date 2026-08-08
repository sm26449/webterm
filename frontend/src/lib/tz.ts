/* Fusul orar ales de utilizator, trimis la fiecare sesiune nouă ca TZ.
   Astfel shell-ul de pe server arată ora locală chiar dacă serverul e UTC,
   fără a modifica configurarea serverului. */

import { detectLang } from './i18n'

/* Locale for date/time formatting. It used to be hardcoded to 'ro-RO' in three places,
   which meant an English UI still printed "07 aug." — the language switch moved the
   strings but not the dates.

   It reads the language through `detectLang()`, the SAME function the UI uses, rather
   than through `wt_lang` directly: that key is written only when someone changes the
   language by hand, so a first-time visitor on a `de-DE` browser would have had an
   English interface with German dates. */
const LOCALES: Record<string, string> = { ro: 'ro-RO', en: 'en-US' }

export function uiLocale(): string {
  try {
    return LOCALES[detectLang()] || 'en-US'
  } catch {
    return 'en-US'
  }
}

/* Un timestamp formatat cu AMBELE alegeri ale utilizatorului: limba interfeţei ŞI fusul orar
   selectat în Setări. Existau amândouă mecanismele, dar `toLocaleString()` fără argumente le
   ignora pe amândouă: lua limba BROWSERULUI şi fusul MAŞINII. Un român cu Chrome pe `en-US`
   vedea interfaţa în română şi jurnalul de audit cu date americane; iar cine îşi punea
   `Europe/Bucharest` în Setări nu vedea niciun efect acolo unde conta — audit, expirarea
   tokenurilor, backupuri, diagnostic. Opt locuri foloseau varianta fără argumente; acum trec
   toate pe aici. `date`/`datetime` acoperă cele două forme folosite în UI. */
export function fmtTs(epochSeconds: number, style: 'date' | 'datetime' = 'datetime'): string {
  try {
    const opts: Intl.DateTimeFormatOptions =
      style === 'date'
        ? { timeZone: getTimezone(), year: 'numeric', month: '2-digit', day: '2-digit' }
        : { timeZone: getTimezone(), year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit' }
    return new Intl.DateTimeFormat(uiLocale(), opts).format(new Date(epochSeconds * 1000))
  } catch {
    // fus invalid salvat în localStorage, sau Intl fără date pentru locală: mai bine o dată
    // brută decât un ecran gol
    return new Date(epochSeconds * 1000).toISOString().slice(0, 19).replace('T', ' ')
  }
}

export function browserTimezone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  } catch {
    return 'UTC'
  }
}

export function getTimezone(): string {
  return localStorage.getItem('wt_tz') || browserTimezone()
}

export function setTimezone(tz: string): void {
  localStorage.setItem('wt_tz', tz)
}

export function allTimezones(): string[] {
  const anyIntl = Intl as unknown as { supportedValuesOf?: (k: string) => string[] }
  if (typeof anyIntl.supportedValuesOf === 'function') {
    try {
      return anyIntl.supportedValuesOf('timeZone')
    } catch {
      /* fallback mai jos */
    }
  }
  return [
    'UTC', 'Europe/Bucharest', 'Europe/London', 'Europe/Berlin', 'Europe/Paris',
    'Europe/Madrid', 'Europe/Moscow', 'America/New_York', 'America/Chicago',
    'America/Denver', 'America/Los_Angeles', 'America/Sao_Paulo', 'Asia/Dubai',
    'Asia/Kolkata', 'Asia/Singapore', 'Asia/Tokyo', 'Australia/Sydney',
  ]
}

export function timeInZone(tz: string): string {
  try {
    return new Intl.DateTimeFormat(uiLocale(), {
      timeZone: tz, hour: '2-digit', minute: '2-digit', second: '2-digit',
    }).format(new Date())
  } catch {
    return '—'
  }
}
