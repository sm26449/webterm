import { Host } from './api'

/** Culoare stabilă per host, derivată din nume (nu din id — id-ul se poate
   schimba la re-import). Aceeași culoare peste tot: sidebar, tab, terminal,
   palette → identifici instant pe ce echipament ești. */
function hash(name: string): number {
  let h = 2166136261
  for (let i = 0; i < name.length; i++) {
    h ^= name.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return Math.abs(h)
}

/** Paletă curată, aleasă manual: 12 nuanțe echilibrate perceptual, toate
   lizibile pe fundal întunecat (trec AA). Hue-urile aleatoare din HSL arătau
   noroioase și inegale ca luminozitate — ăsta e un set „designed". */
const HOST_PALETTE = [
  '#60a5fa', // albastru
  '#34d399', // smarald
  '#fbbf24', // chihlimbar
  '#a78bfa', // violet
  '#f472b6', // roz
  '#22d3ee', // cyan
  '#fb923c', // portocaliu
  '#4ade80', // verde
  '#f87171', // roșu-coral
  '#818cf8', // indigo
  '#2dd4bf', // teal
  '#e879f9', // fucsia
]

/** Culoare stabilă per host (aceeași peste tot: sidebar, tab, terminal, palette). */
export function hostColor(host: { name: string }): string {
  return HOST_PALETTE[hash(host.name) % HOST_PALETTE.length]
}

/** `user@hostname` sau, în lipsă, numele host-ului. */
export function hostAt(host: Host): string {
  const user = host.ssh_username || host.agent_user
  if (host.hostname) return user ? `${user}@${host.hostname}` : host.hostname
  return host.name
}

export function protoLabel(host: Host): string {
  return (host.connection_type || 'agent').toUpperCase()
}

/** Stare de conectivitate cu semantică de culoare (nu doar online/offline). */
export function reachState(host: Host): 'online' | 'ondemand' | 'offline' {
  if (host.online) return 'online'
  return host.connection_type && host.connection_type !== 'agent' ? 'ondemand' : 'offline'
}
