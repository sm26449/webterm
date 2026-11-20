// 3.7.0: the agent's mTLS state on the host page (docs/design/AGENT-MTLS.md). The server decides; this only
// picks the words. required = the host only accepts its client certificate now (the ratchet).

export interface HostMtls {
  required: boolean
  last: number | null
  not_after: number | null
  issued: boolean
}

export type MtlsState = 'required' | 'issued' | 'none'

export function mtlsState(m: HostMtls | null | undefined): MtlsState {
  if (!m) return 'none'
  if (m.required) return 'required'
  return m.issued ? 'issued' : 'none'
}

/** Days until the client certificate expires, or null when there is none. Negative = expired. */
export function mtlsDaysLeft(m: HostMtls | null | undefined, nowSec: number): number | null {
  if (!m || !m.not_after) return null
  return Math.floor((m.not_after - nowSec) / 86400)
}

/** A certificate that should already have been renewed (renewal starts with a third of its life left). */
export function mtlsExpiringSoon(m: HostMtls | null | undefined, nowSec: number): boolean {
  const d = mtlsDaysLeft(m, nowSec)
  return d !== null && d < 30
}
