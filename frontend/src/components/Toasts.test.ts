import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import en from '../lang/en'
import ro from '../lang/ro'
import { I18nProvider } from '../lib/i18n'
import Toasts, { type ToastItem } from './Toasts'

// Node 20 (poarta locală, CI) nu are `navigator` global; I18nProvider îl citeşte ca să aleagă limba
beforeAll(() => { if (typeof navigator === 'undefined') vi.stubGlobal('navigator', { languages: ['en'], language: 'en' }) })

const html = (items: ToastItem[]) =>
  renderToStaticMarkup(createElement(I18nProvider, null, createElement(Toasts, { items, onDismiss: () => {} })))

describe('Toasts: acţiunea cu etichetă (3.6.30 — „Redeschide" după închiderea unui tab)', () => {
  it('cu actionLabel: mesajul e text simplu, acţiunea e un buton separat cu eticheta', () => {
    const h = html([{ id: '1', message: 'Tab closed', kind: 'info', onClick: () => {}, actionLabel: 'Reopen' }])
    expect(h).toContain('<span class="min-w-0 flex-1 break-words">Tab closed</span>')
    expect(h).toMatch(/<button type="button"[^>]*>Reopen<\/button>/)
  })
  it('fără actionLabel: comportamentul vechi — mesajul însuşi e butonul', () => {
    const h = html([{ id: '1', message: 'Task done', kind: 'info', onClick: () => {} }])
    expect(h).toMatch(/<button type="button"[^>]*>Task done<\/button>/)
  })
  it('textele există în ambele limbi şi păstrează {name}', () => {
    for (const d of [en.strings, ro.strings]) {
      expect(d['tabbar.closedToast']).toContain('{name}')
      expect(d['tabbar.reopen']).toBeTruthy()
      expect(d['tabbar.reopenGone']).toBeTruthy()
    }
  })
})
