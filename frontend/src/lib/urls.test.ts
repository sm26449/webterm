import { describe, expect, it } from 'vitest'
import { joinRows, urlsFromText, type Row } from './urls'

describe('urlsFromText', () => {
  it('găsește un URL simplu', () => {
    expect(urlsFromText(['vezi https://example.com/x pagina'])).toEqual(['https://example.com/x'])
  })

  it('un URL rupt pe rânduri, DEJA reunit, e un singur link', () => {
    const joined =
      'https://claude.com/cai/oauth/authorize?code=true&client_id=9d1c250a-e61b-44d9-88ed' +
      '-5944d1962f5e&response_type=code&scope=user%3Aprofile+user%3Ainference&state=Up6x18rb'
    expect(urlsFromText([joined])).toEqual([joined])
  })

  it('mai multe URL-uri pe o linie, în ordine', () => {
    expect(urlsFromText(['a http://one.test b https://two.test/p c'])).toEqual([
      'http://one.test', 'https://two.test/p',
    ])
  })

  it('dedupe, păstrând prima apariţie', () => {
    expect(urlsFromText([
      'https://dup.test/a',
      'iar https://dup.test/a din nou',
      'https://alt.test',
    ])).toEqual(['https://dup.test/a', 'https://alt.test'])
  })

  it('nu ia interpuncţia finală şi nici parantezele de închidere', () => {
    expect(urlsFromText(['(vezi https://x.test/y).'])).toEqual(['https://x.test/y'])
    expect(urlsFromText(['final: https://x.test/z,'])).toEqual(['https://x.test/z'])
  })

  it('ignoră scheme non-web (fără javascript:, ftp:, file:)', () => {
    expect(urlsFromText(['javascript:alert(1) ftp://h/f file:///etc/passwd'])).toEqual([])
  })

  it('fără URL → listă goală', () => {
    expect(urlsFromText(['doar text', '  ', 'prompt$ ls'])).toEqual([])
  })
})

const R = (text: string, wrapped = false, full = false): Row => ({ text, wrapped, full })

describe('joinRows', () => {
  it('soft-wrap (isWrapped) reuneşte fără spaţiu', () => {
    // terminalul a rupt mid-token: continuarea NU are spaţiu de început
    const out = joinRows([R('https://x.test/aaaa', true, true), R('bbbb/cccc', true)])
    expect(out).toEqual(['https://x.test/aaaa' + 'bbbb/cccc'])
  })

  it('hard-wrap INDENTAT (Ink/Claude Code): rânduri pline, nedclarate wrapped, cu indentare', () => {
    // cazul RAPORTAT: aplicaţia îşi face singură wrap-ul, emite rânduri pline (full=true),
    // isWrapped=false, iar caseta indentează continuările — spaţiile de la început trebuie tăiate
    const rows = [
      R('  https://claude.com/cai/oauth/authorize?scope=user%3Amcp_serv', false, true),
      R('  ers+user%3Afile_upload&state=abc', false, false),
    ]
    expect(urlsFromText(joinRows(rows))).toEqual([
      'https://claude.com/cai/oauth/authorize?scope=user%3Amcp_servers+user%3Afile_upload&state=abc',
    ])
  })

  it('hard-wrap pe TREI rânduri pline', () => {
    const rows = [
      R('https://h.test/' + 'a'.repeat(50), false, true),
      R('b'.repeat(50), false, true),
      R('c'.repeat(10), false, false),
    ]
    expect(urlsFromText(joinRows(rows))).toEqual([
      'https://h.test/' + 'a'.repeat(50) + 'b'.repeat(50) + 'c'.repeat(10),
    ])
  })

  it('GARDĂ: un rând SCURT (nu full) cu URL nu se lipeşte de rândul următor', () => {
    // altfel un „vezi http://scurt.test" urmat de proză ar deveni un URL greşit
    const rows = [R('vezi http://scurt.test', false, false), R('mai multe detalii aici', false, false)]
    expect(urlsFromText(joinRows(rows))).toEqual(['http://scurt.test'])
  })

  it('GARDĂ: două URL-uri pe rânduri scurte separate rămân două', () => {
    const rows = [R('http://unu.test', false, false), R('http://doi.test', false, false)]
    expect(urlsFromText(joinRows(rows))).toEqual(['http://unu.test', 'http://doi.test'])
  })
})
