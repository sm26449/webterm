/* Unde se deschid Setările din rotiţă (3.7.1, auditul UX Setări C1).

   Înainte, rotiţa alegea tab-ul după starea serverului (cheie de semnare → System health → backup),
   deci aceeaşi acţiune „deschid setările" ducea în patru locuri diferite şi cine voia să schimbe
   tema ateriza pe un „Critical". Acum rotiţa deschide ultima categorie folosită în acest browser
   (implicit Account); alarmele rămân pe insigna rotiţei şi a rail-ului, iar linkurile adânci
   (cardul Securitate din Dashboard, clopoţelul, saltul din Health, revenirea după step-up SSO)
   trec ca ţintă explicită şi câştigă mereu.

   Preferinţă per browser, nu per cont: e doar o comoditate de navigare, iar un localStorage blocat
   (lib/storage) înseamnă pur şi simplu „Account". */
import { lsGet, lsSet } from './storage'
import { SETTINGS_CATS, type SettingsCat, type SettingsTarget } from './settingsIndex'

export const SETTINGS_LAST_KEY = 'wt_settings_last'

const isCat = (v: string | null): v is SettingsCat => !!v && SETTINGS_CATS.some((c) => c.id === v)

/** Ţinta la deschiderea Setărilor: ţinta explicită (link adânc) neschimbată; altfel ultima
    categorie, dacă e un tab cunoscut şi încă vizibil contului; altfel Account. */
export function settingsOpenTarget(
  explicit: SettingsTarget | undefined,
  last: string | null,
  visible: (cat: SettingsCat) => boolean,
): SettingsTarget {
  if (explicit) return explicit
  // o valoare veche / coruptă sau un tab pierdut între timp (permisiune retrasă) nu deschide un
  // panou gol: cade pe Account, care e vizibil oricui
  if (isCat(last) && visible(last)) return { cat: last }
  return { cat: 'cont' }
}

export const readLastSettingsCat = (): string | null => lsGet(SETTINGS_LAST_KEY)

export function rememberSettingsCat(cat: SettingsCat): void {
  lsSet(SETTINGS_LAST_KEY, cat)
}
