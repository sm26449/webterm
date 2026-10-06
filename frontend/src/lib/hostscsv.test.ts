import { describe, expect, it } from 'vitest'
import type { Host } from './api'
import { csvToRows, importPayload, parseCsv, previewRows, stripFormulaPrefix } from './hostscsv'

const HEAD = 'name,connection_type,hostname,port,username,via_host,folder,tags,note,require_2fa,credential_policy,auth_method,agent_note'

describe('parseCsv (RFC 4180)', () => {
  it('câmpuri simple, LF', () => {
    expect(parseCsv('a,b,c\n1,2,3\n')).toEqual([['a', 'b', 'c'], ['1', '2', '3']])
  })
  it('CRLF şi rândul gol de la final nu devine rând de date', () => {
    expect(parseCsv('a,b\r\n1,2\r\n')).toEqual([['a', 'b'], ['1', '2']])
    expect(parseCsv('a,b\r\n1,2\r\n\r\n')).toEqual([['a', 'b'], ['1', '2']])
  })
  it('BOM-ul UTF-8 e ignorat (exportul îl pune pentru Excel)', () => {
    expect(parseCsv('﻿name,x\nşţ,ă')).toEqual([['name', 'x'], ['şţ', 'ă']])
  })
  it('ghilimele: virgulă în câmp, ghilimele dublate', () => {
    expect(parseCsv('"a, b","el a zis ""da""",c')).toEqual([['a, b', 'el a zis "da"', 'c']])
  })
  it('rând nou (LF şi CRLF) în interiorul ghilimelelor', () => {
    expect(parseCsv('n,note\r\nx,"linia 1\r\nlinia 2\nlinia 3"\r\n')).toEqual(
      [['n', 'note'], ['x', 'linia 1\r\nlinia 2\nlinia 3']])
  })
  it('câmpuri goale, inclusiv la final de rând', () => {
    expect(parseCsv('a,,c,\n,,,')).toEqual([['a', '', 'c', ''], ['', '', '', '']])
  })
  it('ultimul rând fără terminator', () => {
    expect(parseCsv('a\nb')).toEqual([['a'], ['b']])
  })
  it('câmp citat gol', () => {
    expect(parseCsv('"",x')).toEqual([['', 'x']])
  })
})

describe('stripFormulaPrefix (pereche cu neutralizarea de la export)', () => {
  it('scoate exact un apostrof dinaintea unui declanşator', () => {
    expect(stripFormulaPrefix("'=HYPERLINK(1)")).toBe('=HYPERLINK(1)')
    expect(stripFormulaPrefix("'+router")).toBe('+router')
    expect(stripFormulaPrefix("'-dash")).toBe('-dash')
    expect(stripFormulaPrefix("'@cmd")).toBe('@cmd')
    expect(stripFormulaPrefix("''=x")).toBe("'=x")
  })
  it('lasă în pace restul', () => {
    expect(stripFormulaPrefix("'normal")).toBe("'normal")
    expect(stripFormulaPrefix('=raw')).toBe('=raw')
    expect(stripFormulaPrefix('')).toBe('')
  })
  it('csvToRows aplică strip-ul pe fiecare celulă', () => {
    const { rows } = csvToRows(`${HEAD}\n'+r,ssh,h,22,u,,,,'=1+1,0,ask,password,\n`)
    expect(rows[0].name).toBe('+r')
    expect(rows[0].note).toBe('=1+1')
  })
})

describe('csvToRows', () => {
  it('antetul în orice ordine/majuscule; coloane necunoscute ignorate; lipsă → ""', () => {
    const { rows, error } = csvToRows('Connection_Type,NAME,extra\nssh,web,zzz\n')
    expect(error).toBeUndefined()
    expect(rows[0].name).toBe('web')
    expect(rows[0].connection_type).toBe('ssh')
    expect(rows[0].hostname).toBe('')
    expect('extra' in rows[0]).toBe(false)
  })
  it('fişier gol / fără antet de hosturi', () => {
    expect(csvToRows('').error).toBe('empty')
    expect(csvToRows('a,b\n1,2').error).toBe('noHeader')
  })
})

const host = (h: Partial<Host>): Host => ({ id: 1, name: 'x', note: '', online: false, hostname: null,
  connection_type: 'agent', ...h } as Host)

describe('previewRows (aceeaşi ordine de verificări ca serverul)', () => {
  const existing = [
    host({ id: 1, name: 'gw', connection_type: 'agent' }),
    host({ id: 2, name: 'web01', connection_type: 'ssh', hostname: '10.0.0.5', ssh_port: 2222, ssh_username: 'deploy' }),
    host({ id: 3, name: 'eph', connection_type: 'ssh-jump', hostname: '9.9.9.9', ssh_port: 22, ssh_username: 'u', ephemeral: true }),
  ]
  const rows = (csv: string) => csvToRows(`${HEAD}\n${csv}`).rows

  it('nou, agent, duplicat după nume şi după adresă', () => {
    const st = previewRows(rows([
      'nou,ssh,10.1.1.1,,root,,,,,0,,,',
      'agent-nou,agent,,,,,,,,0,,,',
      'WEB01,ssh,1.2.3.4,,x,,,,,0,,,',
      'alt,ssh,10.0.0.5,2222,DEPLOY,,,,,0,,,',
      'eph2,ssh,9.9.9.9,22,u,,,,,0,,,',           // ţinta efemeră nu contează
    ].join('\n')), existing)
    expect(st.map((s) => s.kind)).toEqual(['new', 'agent', 'exists', 'exists', 'new'])
  })
  it('acelaşi nume de două ori în fişier → al doilea e duplicat', () => {
    const st = previewRows(rows('a,ssh,h1,,u,,,,,0,,,\na,ssh,h2,,u,,,,,0,,,'), existing)
    expect(st.map((s) => s.kind)).toEqual(['new', 'exists'])
  })
  it('via_host: agentul din ACELAŞI fişier, chiar dacă vine după ţintă', () => {
    const st = previewRows(rows('t,ssh-jump,10.2.2.2,,u,nou-gw,,,,0,,,\nnou-gw,agent,,,,,,,,0,,,'), existing)
    expect(st.map((s) => s.kind)).toEqual(['new', 'agent'])
  })
  it('fiecare cod de eroare', () => {
    const codes = previewRows(rows([
      ',ssh,h,,u,,,,,0,,,',
      'x1,,h,,u,,,,,0,,,',
      'x2,rdp,h,,u,,,,,0,,,',
      'x3,ssh,,,u,,,,,0,,,',
      'x4,ssh,h4,,,,,,,0,,,',
      'x5,ssh,h5,70000,u,,,,,0,,,',
      'x6,ssh,h6,2a,u,,,,,0,,,',
      'x7,ssh,h7,,u,,,,,0,,parola,',
      'x8,ssh,h8,,u,,,,,0,never,,',
      'x9,ssh-jump,h9,,u,,,,,0,,,',
      'x10,ssh-jump,h10,,u,nimeni,,,,0,,,',
      'x11,telnet-jump,h11,,,web01,,,,0,,,',
    ].join('\n')), existing).map((s) => ('code' in s ? s.code : s.kind))
    expect(codes).toEqual(['host.nameRequired', 'hostcsv.typeRequired', 'host.badType',
      'host.hostnameRequired', 'ssh.userRequired', 'host.badPort', 'host.badPort', 'host.badAuthMethod',
      'host.badCredentialPolicy', 'hostcsv.viaRequired', 'hostcsv.viaMissing', 'sshjump.needsAgent'])
  })
  it('via ambiguu (doi agenţi cu acelaşi nume)', () => {
    const st = previewRows(rows('t,ssh-jump,h,,u,gw,,,,0,,,'), [...existing, host({ id: 9, name: 'GW' })])
    expect(st[0]).toEqual({ kind: 'error', code: 'hostcsv.viaAmbiguous', vars: { name: 'gw' } })
  })
  it('politica din opţiuni bate coloana (o politică greşită în fişier nu mai contează)', () => {
    expect(previewRows(rows('x,ssh,h,,u,,,,,0,never,,'), existing, 'ask')[0].kind).toBe('new')
  })
  it('importPayload: doar rândurile bifate, fără agent_note', () => {
    const r = rows('a,agent,,,,,,,,0,,,reinstall\nb,ssh,h,,u,,,,,0,,,')
    const p = importPayload(r, [false, true])
    expect(p).toHaveLength(1)
    expect(p[0].name).toBe('b')
    expect('agent_note' in p[0]).toBe(false)
  })
})
