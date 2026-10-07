import { api, errText, Host, withStepup } from './api'
import { notify } from './notify'

type T = (key: string, vars?: Record<string, string | number>) => string

/** Wake-on-LAN: gateway-ul cere unui agent vecin din acelaşi LAN să trimită magic packet-ul.
    Folosit de sidebar (⏻ pe rândul hostului) şi de overlay-ul „host offline" din sesiune —
    acelaşi endpoint, acelaşi step-up, acelaşi feedback pe toast. Întoarce true la succes. */
export async function wakeHost(host: Host, t: T): Promise<boolean> {
  try {
    const r = await withStepup(host.id, () => api<{ via: string }>(`/api/hosts/${host.id}/wake`, { method: 'POST' }))
    notify(t('sidebar.wakeSent', { host: host.name }), t('sidebar.wakeVia', { peer: r.via }), 'info')
    return true
  } catch (e) {
    notify(t('sidebar.wakeFailed', { host: host.name }), errText(e, t) || '', 'warn')
    return false
  }
}
