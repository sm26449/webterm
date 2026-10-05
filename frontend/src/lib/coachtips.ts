import { lsGet, lsRemove, lsSet } from './storage'

/* Logica „pură" a sfaturilor contextuale (coach tips), scoasă din componentă ca să fie
   TESTABILĂ fără DOM, exact ca lib/walkthrough.ts. Un sfat = un callout mic, non-modal, arătat
   O SINGURĂ DATĂ lângă elementul relevant; „s-a mai arătat?" trăieşte aici, nu în prezentare.

   Sfaturile COMPLETEAZĂ walkthrough-ul de primă rulare (nu-l dublează): walkthrough-ul explică
   totul o dată, la început; sfaturile apar la momentul potrivit, lângă UI-ul concret. */

// Prefixul comun al tuturor cheilor de sfat. Numele cheilor sunt parte din contractul cu testele
// e2e (ele le presetează ca sfaturile să nu blocheze fluxul de login), deci nu le schimba.
export const TIP_PREFIX = 'wt_tip_'

export const TIP_ADDHOST_AGENT = 'wt_tip_addhost_agent'
export const TIP_ADDHOST_SSH = 'wt_tip_addhost_ssh'   // folosit şi de jump (aceeaşi copie)
export const TIP_TERMINAL_PASTE = 'wt_tip_terminal_paste'
export const TIP_TOOLBAR = 'wt_tip_toolbar'

/** Lista canonică a cheilor cunoscute. `resetAllTips` o parcurge explicit (testabil fără
    enumerarea localStorage, pe care FakeStorage din teste n-o expune), iar e2e o oglindeşte. */
export const TIP_KEYS = [
  TIP_ADDHOST_AGENT,
  TIP_ADDHOST_SSH,
  TIP_TERMINAL_PASTE,
  TIP_TOOLBAR,
] as const

/** „Închis" = citirea întoarce exact '1'. Orice altceva (null, '0', gunoi) = încă se poate arăta.
    Pe un localStorage indisponibil, lsGet întoarce null → sfatul se arată (best-effort), ceea ce
    e corect: mai bine un hint în plus decât o excepţie la atingerea storage-ului. */
export function isTipDismissed(key: string): boolean {
  return lsGet(key) === '1'
}

/** Marchează sfatul ca văzut, definitiv (per browser). Best-effort: dacă storage-ul e blocat,
    sfatul pur şi simplu nu se persistă şi ar putea reapărea — acceptabil pentru un hint. */
export function dismissTip(key: string): void {
  lsSet(key, '1')
}

/** „Arată din nou sfaturile" din Setări: şterge TOATE cheile de sfat. Întâi lista cunoscută
    (mereu curăţată, chiar fără enumerare), apoi, best-effort, orice cheie `wt_tip_*` rămasă
    (sfaturi viitoare) — într-un try/catch, fiindcă `window.localStorage` poate arunca la simpla
    atingere (vezi lib/storage.ts), iar în testul `node` stub-ul nu e un obiect Storage real. */
export function resetAllTips(): void {
  for (const k of TIP_KEYS) lsRemove(k)
  try {
    for (const k of Object.keys(window.localStorage)) {
      if (k.startsWith(TIP_PREFIX)) lsRemove(k)
    }
  } catch {
    /* localStorage indisponibil / stub fără enumerare: lista explicită de mai sus a făcut treaba */
  }
}
