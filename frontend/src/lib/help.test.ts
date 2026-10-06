import { describe, expect, it } from 'vitest'
import { docsRef, docsUrl, HELP } from './help'
import en from '../lang/en'
import ro from '../lang/ro'

describe('docsRef / docsUrl', () => {
  it('links the tag of the running release', () => {
    expect(docsRef('3.5.1')).toBe('v3.5.1')
    expect(docsUrl('docs/HOSTS.md#tags', '3.5.1'))
      .toBe('https://github.com/sm26449/webterm/blob/v3.5.1/docs/HOSTS.md#tags')
  })
  it('falls back to main while the version is unknown or not a release', () => {
    expect(docsRef(null)).toBe('main')
    expect(docsRef('3.5.1-dev')).toBe('main')
  })
})

describe('HELP registry', () => {
  // un „?" care deschide un popover cu cheia brută sau un link 404 e mai rău decât niciun „?"
  it.each(Object.keys(HELP))('%s has title + body in en and ro', (id) => {
    for (const lang of [en.strings, ro.strings]) {
      expect(lang[`help.${id}.title`]).toBeTruthy()
      expect(lang[`help.${id}.body`]).toBeTruthy()
    }
  })
  // ancorele din docs: verificate în tests/i18n_catalog_test.py (are acces la repo)
})
