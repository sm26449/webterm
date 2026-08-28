import { describe, expect, it } from 'vitest'
import { urlsFromText } from './urls'

describe('urlsFromText', () => {
  it('găsește un URL simplu', () => {
    expect(urlsFromText(['vezi https://example.com/x pagina'])).toEqual(['https://example.com/x'])
  })

  it('un URL rupt pe rânduri, DEJA reunit, e un singur link', () => {
    // linia logică = rândurile rupte concatenate (ce face logicalLines înainte de apel)
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
