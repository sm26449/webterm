/* Încărcarea flotei (hosturi + sesiuni) — eroare ≠ gol (auditul funcţional 3.6.3, #1).

   Înainte: `Promise.all([hosts, sessions])` — un /api/sessions picat arunca TOT, lista de hosturi
   rămânea [] şi Dashboard-ul + sidebar-ul arătau ecranul de primă rulare („No hosts yet / Add a
   host", „0/0 hosts online") unui admin cu o flotă întreagă. Acum fiecare parte se decide singură:
   ce a venit se foloseşte, ce a picat îşi păstrează valoarea de la ultima încărcare reuşită şi
   primeşte o eroare proprie. `hostsLoaded` spune dacă lista de hosturi a venit MĂCAR O DATĂ —
   starea goală („nu ai niciun host") se arată numai atunci. */

export interface FleetState<H, S> {
  hosts: H[]
  sessions: S[]
  /** lista de hosturi a sosit cel puţin o dată (altfel: încă se încarcă / a picat) */
  hostsLoaded: boolean
  sessionsLoaded: boolean
  hostsErr: string | null
  sessionsErr: string | null
}

export function initialFleet<H, S>(): FleetState<H, S> {
  return { hosts: [], sessions: [], hostsLoaded: false, sessionsLoaded: false, hostsErr: null, sessionsErr: null }
}

/** Ce primesc Dashboard-ul şi sidebar-ul: starea încărcării, fără listele în sine. */
export interface FleetStatus { hostsLoaded: boolean; hostsErr: string | null; sessionsErr: string | null }

/** Combină rezultatele unei runde de încărcare cu starea anterioară. */
export function settleFleet<H, S>(
  prev: FleetState<H, S>,
  hosts: PromiseSettledResult<H[]>,
  sessions: PromiseSettledResult<S[]>,
  errText: (e: unknown) => string,
): FleetState<H, S> {
  return {
    hosts: hosts.status === 'fulfilled' ? hosts.value : prev.hosts,
    sessions: sessions.status === 'fulfilled' ? sessions.value : prev.sessions,
    hostsLoaded: prev.hostsLoaded || hosts.status === 'fulfilled',
    sessionsLoaded: prev.sessionsLoaded || sessions.status === 'fulfilled',
    hostsErr: hosts.status === 'rejected' ? errText(hosts.reason) : null,
    sessionsErr: sessions.status === 'rejected' ? errText(sessions.reason) : null,
  }
}
