import { describe, expect, it } from 'vitest'
import {
  CONN_TYPES, connTypeOf, defaultPort, isAgentType, isConnType, isJumpType, isNetworkType,
  isSshType, isTelnetType,
} from './conntypes'

describe('conntypes', () => {
  it('NULL / gol = agent, ca pe server', () => {
    expect(connTypeOf(null)).toBe('agent')
    expect(connTypeOf(undefined)).toBe('agent')
    expect(connTypeOf('')).toBe('agent')
    expect(isAgentType(null)).toBe(true)
    expect(isNetworkType(null)).toBe(false)
  })

  it('familiile acoperă exact tipurile cunoscute', () => {
    for (const t of CONN_TYPES) {
      expect(isConnType(t)).toBe(true)
      // fiecare tip e ori agent, ori de reţea (SSH sau telnet), niciodată ambele
      expect(isAgentType(t) !== isNetworkType(t)).toBe(true)
      expect(isSshType(t) && isTelnetType(t)).toBe(false)
    }
    expect(CONN_TYPES.filter(isJumpType)).toEqual(['ssh-jump', 'telnet-jump'])
    expect(CONN_TYPES.filter((t) => isSshType(t))).toEqual(['ssh', 'ssh-jump'])
  })

  it('un tip necunoscut nu e nici agent, nici de reţea (validarea îl refuză)', () => {
    expect(isConnType('SSH')).toBe(false)
    expect(isAgentType('SSH')).toBe(false)
    expect(isNetworkType('SSH')).toBe(false)
  })

  it('portul implicit: 23 pentru telnet, 22 altfel', () => {
    expect(defaultPort('telnet')).toBe(23)
    expect(defaultPort('telnet-jump')).toBe(23)
    expect(defaultPort('ssh-jump')).toBe(22)
    expect(defaultPort(null)).toBe(22)
  })
})
