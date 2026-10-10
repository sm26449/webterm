/* Contractul „eroare ≠ gol" (docs/design/DESIGN-SYSTEM.md, „Încărcare şi erori").

   Un fetch picat NU are voie să devină o listă goală: „n-ai niciun passkey", „nicio sesiune",
   „niciun rezultat" sunt afirmaţii despre server, iar pe un fetch eşuat nu ştim nimic. Aici e
   starea unei încărcări, legată de IDENTITATEA a ceea ce se încarcă (`key`: hostul, interogarea):

     loading — nu ştim încă (poate purta datele vechi ale ACELEIAŞI chei, la un refresh);
     ok      — datele de pe server;
     error   — n-am putut încărca; `data` = ultima versiune bună a aceleiaşi chei (afişată „veche"),
               sau nimic dacă n-a reuşit niciodată.

   Un răspuns sosit pentru altă cheie (host A după ce ai trecut pe B) e IGNORAT — altfel sesiunile
   lui A apăreau pe pagina lui B. Funcţii pure: testate în loadable.test.ts. */

export type Load<T> =
  | { status: 'loading'; key: string; data?: T }
  | { status: 'ok'; key: string; data: T }
  | { status: 'error'; key: string; error: string; data?: T }

/** Varianta fără cheie şi fără date, pentru secţiunile de formular din Setări (datele stau în
    câmpuri): `ok` = câmpurile arată ce e pe server; altfel Save e blocat şi se vede de ce. */
export type LoadState = { status: 'loading' } | { status: 'ok' } | { status: 'error'; error: string }

/** un formular se poate salva DOAR peste valori încărcate — altfel valorile implicite
    (praguri 90/90/90, SMTP gol) ar suprascrie configuraţia reală de pe server */
export const canSave = (s: LoadState): boolean => s.status === 'ok'

export type Outcome<T> = { ok: true; data: T } | { ok: false; error: string }

/** prima încărcare pentru o cheie: fără date (nimic de la cheia veche) */
export const startLoad = <T>(key: string): Load<T> => ({ status: 'loading', key })

/** reîncărcare (Retry / refresh) pe ACEEAŞI cheie: păstrează datele bune, dacă sunt */
export const reloadLoad = <T>(cur: Load<T>): Load<T> => ({ status: 'loading', key: cur.key, data: cur.data })

/** aplică un răspuns; unul pentru altă cheie decât cea curentă e ignorat (răspuns întârziat) */
export function settleLoad<T>(cur: Load<T>, key: string, r: Outcome<T>): Load<T> {
  if (cur.key !== key) return cur
  if (r.ok) return { status: 'ok', key, data: r.data }
  return { status: 'error', key, error: r.error, data: cur.data }
}

/** starea văzută de randare pentru cheia CURENTĂ: dacă starea ţinută e a altei chei (randarea
    dintre schimbarea hostului şi efectul care resetează), e „loading", fără datele vechi */
export const loadFor = <T>(s: Load<T>, key: string): Load<T> => (s.key === key ? s : startLoad<T>(key))

/** datele de afişat: ok → datele; error/loading → ultima versiune bună a aceleiaşi chei, dacă e */
export const loadData = <T>(s: Load<T>): T | undefined => s.data

/** datele afişate sunt vechi (refresh-ul a picat, arătăm ultima versiune bună) */
export const isStale = <T>(s: Load<T>): boolean => s.status === 'error' && s.data !== undefined
