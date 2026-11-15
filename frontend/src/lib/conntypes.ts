/* Tipurile de conexiune ale unui host — oglinda lui `gateway/app/conntypes.py` (lista e
   comparată de `tests/conntypes_test.py`; un tip nou se adaugă în AMBELE locuri).

   NULL / gol = `agent` (hosturile de dinaintea tipurilor de conexiune), ca pe server. */

export const CONN_TYPES = ['agent', 'ssh', 'ssh-jump', 'telnet', 'telnet-jump'] as const
export type ConnType = typeof CONN_TYPES[number]

const SSH_FAMILY: readonly string[] = ['ssh', 'ssh-jump']
const TELNET_FAMILY: readonly string[] = ['telnet', 'telnet-jump']
const JUMP: readonly string[] = ['ssh-jump', 'telnet-jump']

/** Tipul efectiv: NULL / gol = agent. Nu normalizează majusculele (serverul refuză `host.badType`). */
export const connTypeOf = (t: string | null | undefined): string => t || 'agent'

export const isConnType = (t: string): t is ConnType => (CONN_TYPES as readonly string[]).includes(t)
export const isAgentType = (t: string | null | undefined): boolean => connTypeOf(t) === 'agent'
/** autentificare SSH: utilizator, parolă/cheie, cheie de host */
export const isSshType = (t: string | null | undefined): boolean => SSH_FAMILY.includes(connTypeOf(t))
export const isTelnetType = (t: string | null | undefined): boolean => TELNET_FAMILY.includes(connTypeOf(t))
/** TCP-ul pleacă din agentul hostului `via_host_id` */
export const isJumpType = (t: string | null | undefined): boolean => JUMP.includes(connTypeOf(t))
/** gateway-ul se conectează la un hostname (orice în afară de agent, dintre tipurile cunoscute) */
export const isNetworkType = (t: string | null | undefined): boolean => isSshType(t) || isTelnetType(t)
export const defaultPort = (t: string | null | undefined): number => (isTelnetType(t) ? 23 : 22)
