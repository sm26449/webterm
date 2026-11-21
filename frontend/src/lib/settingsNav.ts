/* Navigarea în Setări pe telefon şi pe rail-ul de desktop (3.7.1, auditul UX Setări C3 / Me6).

   Pe telefon (sub `sm`) Setările sunt două ecrane: lista categoriilor (cu căutarea deasupra) şi
   categoria aleasă (cu „‹ Settings" înapoi). Pe desktop/tabletă rămâne cadrul cu rail + conţinut,
   iar rail-ul e o singură oprire de Tab, cu săgeţile între categorii (roving tabindex).

   Logica stă aici, pură, ca s-o testăm fără DOM: ce ecran apare la deschidere, ce se vede pe
   fiecare ecran, ce face Escape şi unde mută o tastă focusul în rail. */

export type PhoneScreen = 'list' | 'cat'

/** Ecranul de pornire pe telefon. O ţintă EXPLICITĂ (link adânc: cardul Securitate, clopoţelul,
    saltul din Health, revenirea după step-up SSO) aterizează direct în categorie — cine a apăsat
    „Your 2FA" vrea 2FA, nu un cuprins. Rotiţa simplă deschide lista: pe un ecran mic cuprinsul
    E navigarea (pe desktop rail-ul e mereu vizibil, deci acolo rămâne „ultima categorie"). */
export function initialPhoneScreen(explicitTarget: boolean): PhoneScreen {
  return explicitTarget ? 'cat' : 'list'
}

export interface SettingsLayout {
  /** lista categoriilor (pe desktop: rail-ul) */
  showNav: boolean
  /** panoul de conţinut (categoria activă sau rezultatele căutării) */
  showContent: boolean
  /** antetul „‹ Settings  <categorie>" în locul titlului şi al căutării */
  showBack: boolean
  /** câmpul de căutare */
  showSearch: boolean
}

/** Ce se vede. Pe desktop totul, mereu. Pe telefon: pe listă — căutarea şi lista, iar cât timp se
    caută rezultatele iau locul listei; în categorie — antetul cu Back şi conţinutul (căutarea e un
    Back distanţă, ca în macheta din audit §4.2). */
export function settingsLayout(phone: boolean, screen: PhoneScreen, searching: boolean): SettingsLayout {
  if (!phone) return { showNav: true, showContent: true, showBack: false, showSearch: true }
  if (screen === 'cat') return { showNav: false, showContent: true, showBack: true, showSearch: false }
  return { showNav: !searching, showContent: searching, showBack: false, showSearch: true }
}

/** Escape, în ordine: goleşte căutarea; pe telefon, din categorie, înapoi la listă; altfel închide.
    (Golirea căutării o face deja câmpul însuşi; aici e pentru Escape primit oriunde în dialog.) */
export function escapeAction(phone: boolean, screen: PhoneScreen, searching: boolean): 'clear' | 'back' | 'close' {
  if (searching) return 'clear'
  if (phone && screen === 'cat') return 'back'
  return 'close'
}

/** Roving tabindex pe rail: indexul spre care se mută focusul pentru tasta dată, sau null dacă
    tasta nu e a rail-ului (Tab, Enter, Space îşi fac treaba lor — butoanele se activează nativ).
    Săgeţile trec peste grupuri (lista e plată) şi se rotesc la capete, ca într-un tablist. */
export function railKeyTarget(key: string, index: number, count: number): number | null {
  if (count <= 0) return null
  const i = index < 0 || index >= count ? 0 : index
  switch (key) {
    case 'ArrowDown': case 'ArrowRight': return (i + 1) % count
    case 'ArrowUp': case 'ArrowLeft': return (i - 1 + count) % count
    case 'Home': return 0
    case 'End': return count - 1
    default: return null
  }
}

/** Butonul rail-ului care ţine oprirea de Tab: categoria activă dacă e în listă, altfel prima. */
export function railTabStop<T>(ids: readonly T[], active: T): T | undefined {
  return ids.includes(active) ? active : ids[0]
}
