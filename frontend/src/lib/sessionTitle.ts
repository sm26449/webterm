/* Titlul AFIŞAT al unei sesiuni (audit funcţional 3.6.3, #7).

   Serverul dă sesiunilor fără titlu un nume implicit unic per host, „Session N" — mereu în
   engleză (gateway/app/api.py, create_session; acelaşi tipar recunoaşte şi vechiul „Sesiune N").
   Clientul îl traduce la afişare. Datele rămân neatinse: nicio migrare, niciun câmp nou în API,
   iar un titlu ales de om (orice altceva) se arată exact cum e. */

const DEFAULT_TITLE = /^(?:Session|Sesiune) (\d+)$/

export function isDefaultSessionTitle(title: string | null | undefined): boolean {
  return DEFAULT_TITLE.test(title ?? '')
}

export function sessionTitle(title: string | null | undefined,
                             t: (k: string, v?: Record<string, string | number>) => string): string {
  const m = DEFAULT_TITLE.exec(title ?? '')
  return m ? t('session.defaultTitle', { n: m[1] }) : (title ?? '')
}
