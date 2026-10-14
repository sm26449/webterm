import { ApiError } from './api'

/* Hosturi „crown jewel" (3.6.10, docs/ROLES.md#crown-jewel-hosts). Serverul refuză cu 409 o acordare
   (legătură, cont nou cu rol, mapare SSO) care dă un shell (⚑) pe un astfel de host unui rol
   ne-Owner — `authz.crownJewel` — şi mutarea unui host crown-jewel într-un folder/tag peste care
   există deja asemenea legături — `authz.crownJewelMove`. Cererea trece doar retrimisă cu
   `confirm_crown_jewel: true`, după o confirmare EXPLICITĂ a omului (dialog blocant, „danger").

   Aici e doar mecanica (testabilă în vitest): trimite, la 409-ul crown-jewel întreabă, retrimite
   cu confirmarea. Nicio decizie de securitate: serverul verifică din nou şi auditează. */

export const CROWN_CODES = ['authz.crownJewel', 'authz.crownJewelMove'] as const

export const isCrownError = (e: unknown): e is ApiError =>
  e instanceof ApiError && (CROWN_CODES as readonly string[]).includes(e.code)

type T = (k: string, v?: Record<string, string | number>) => string

/** Textele dialogului de confirmare (cu hosturile / hostul trimise de server în `vars`). */
export function crownDialog(e: ApiError, t: T): { title: string; message: string; confirmLabel: string; danger: true } {
  const move = e.code === 'authz.crownJewelMove'
  return {
    title: t('crown.confirmTitle'),
    message: move
      ? t('crown.confirmMove', { host: String(e.vars.host ?? ''), n: Number(e.vars.n ?? 0) })
      : t('crown.confirmGrant', { hosts: String(e.vars.hosts ?? '') }),
    confirmLabel: t(move ? 'crown.confirmMoveButton' : 'crown.confirmGrantButton'),
    danger: true,
  }
}

/** Rezultatul `null` = omul a refuzat confirmarea (nimic nu s-a schimbat pe server). */
export async function withCrownConfirm<T>(
  send: (extra: { confirm_crown_jewel?: true }) => Promise<T>,
  ask: (e: ApiError) => Promise<boolean>,
): Promise<T | null> {
  try {
    return await send({})
  } catch (e) {
    if (!isCrownError(e)) throw e
    if (!(await ask(e))) return null
    return await send({ confirm_crown_jewel: true })
  }
}
