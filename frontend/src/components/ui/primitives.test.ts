import { createElement as h } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { I18nProvider } from '../../lib/i18n'
import Field from './Field'
import SegmentedControl, { segmentedKeyTarget } from './SegmentedControl'
import SettingsSection from './SettingsSection'
import Switch from './Switch'

/* Primitivele de formular din 3.7.1 (auditul UX Setări, pasul 3). Fără DOM (nu avem jsdom):
   marcajul se verifică prin renderToStaticMarkup, tastatura prin funcţia pură segmentedKeyTarget. */

// Node 20 nu are `navigator` global; I18nProvider îl citeşte ca să aleagă limba
beforeAll(() => { if (typeof navigator === 'undefined') vi.stubGlobal('navigator', { languages: ['en'], language: 'en' }) })

const attr = (html: string, tag: string, name: string) =>
  [...html.matchAll(new RegExp(`<${tag}\\b[^>]*\\s${name}="([^"]*)"`, 'g'))].map((m) => m[1])

describe('Field: eticheta vizibilă e legată de control', () => {
  it('label for = id-ul controlului; indiciul şi eroarea intră în aria-describedby', () => {
    const html = renderToStaticMarkup(h(Field, { label: 'Host', hint: 'e.g. backup.example.com', error: 'Required',
      children: h('input', { 'aria-describedby': 'outer' }) }))
    const id = attr(html, 'input', 'id')[0]
    expect(id).toBeTruthy()
    expect(attr(html, 'label', 'for')).toEqual([id])
    expect(html).toContain('>Host</label>')
    const described = attr(html, 'input', 'aria-describedby')[0].split(' ')
    expect(described[0]).toBe('outer')               // ce avea controlul rămâne
    expect(described).toContain(`${id}-hint`)
    expect(described).toContain(`${id}-err`)
    expect(html).toContain(`id="${id}-hint"`)
    expect(html).toContain(`id="${id}-err"`)
    expect(attr(html, 'input', 'aria-invalid')).toEqual(['true'])
  })
  it('păstrează id-ul pus de apelant şi merge pe select / textarea', () => {
    for (const tag of ['select', 'textarea', 'input']) {
      const html = renderToStaticMarkup(h(Field, { label: 'L', children: h(tag, { id: 'mine' }) }))
      expect(attr(html, tag, 'id')).toEqual(['mine'])
      expect(attr(html, 'label', 'for')).toEqual(['mine'])
      expect(attr(html, tag, 'aria-describedby')).toEqual([])   // fără indiciu, nimic de descris
    }
  })
})

describe('SegmentedControl: radio group, nu umplerea primară', () => {
  const opts = [{ value: 'off', label: 'Off' }, { value: 'daily', label: 'Daily' }, { value: 'weekly', label: 'Weekly' }]
  it('radiogroup cu nume, radio + aria-checked, un singur tab-stop pe opţiunea aleasă', () => {
    const html = renderToStaticMarkup(h(SegmentedControl, { label: 'Schedule', value: 'daily', options: opts, onChange: () => {} }))
    expect(html).toMatch(/<div role="radiogroup" aria-label="Schedule"/)
    expect(attr(html, 'button', 'role')).toEqual(['radio', 'radio', 'radio'])
    expect(attr(html, 'button', 'aria-checked')).toEqual(['false', 'true', 'false'])
    expect(attr(html, 'button', 'tabindex')).toEqual(['-1', '0', '-1'])
    expect(attr(html, 'button', 'type')).toEqual(['button', 'button', 'button'])
    expect(html).not.toContain('bg-sky-600')         // ales = suprafaţă ridicată + inel (M7)
    expect(html).toContain('ring-sky-500')
  })
  it('fără alegere (stare neîncărcată): nimic bifat, prima opţiune activă e tab-stop', () => {
    const html = renderToStaticMarkup(h(SegmentedControl, { label: 'S', value: null,
      options: [{ value: 'a', label: 'A', disabled: true }, ...opts], onChange: () => {} }))
    expect(attr(html, 'button', 'aria-checked')).toEqual(['false', 'false', 'false', 'false'])
    expect(attr(html, 'button', 'tabindex')).toEqual(['-1', '0', '-1', '-1'])
  })
  it('labelledBy înlocuieşte aria-label', () => {
    const html = renderToStaticMarkup(h(SegmentedControl, { label: 'x', labelledBy: 'hdr', value: 'off', options: opts, onChange: () => {} }))
    expect(html).toContain('aria-labelledby="hdr"')
    expect(html).not.toContain('aria-label="x"')
  })
  it('tastatura: săgeţi cu rotire, Home/End, opţiunile dezactivate sunt sărite', () => {
    const all = [true, true, true]
    expect(segmentedKeyTarget('ArrowRight', 0, all)).toBe(1)
    expect(segmentedKeyTarget('ArrowDown', 2, all)).toBe(0)       // rotire la capăt
    expect(segmentedKeyTarget('ArrowLeft', 0, all)).toBe(2)
    expect(segmentedKeyTarget('ArrowUp', 1, all)).toBe(0)
    expect(segmentedKeyTarget('Home', 2, all)).toBe(0)
    expect(segmentedKeyTarget('End', 0, all)).toBe(2)
    const mid = [true, false, true]
    expect(segmentedKeyTarget('ArrowRight', 0, mid)).toBe(2)
    expect(segmentedKeyTarget('ArrowLeft', 2, mid)).toBe(0)
    expect(segmentedKeyTarget('Home', 2, [false, true, true])).toBe(1)
    expect(segmentedKeyTarget('End', 0, [true, true, false])).toBe(1)
    expect(segmentedKeyTarget('Enter', 0, all)).toBeNull()         // nu e tasta noastră
    expect(segmentedKeyTarget('ArrowRight', 0, [false, false])).toBeNull()
  })
})

describe('Switch', () => {
  it('role=switch + aria-checked pe un <button type=button>, eticheta clicabilă (label for)', () => {
    const html = renderToStaticMarkup(h(Switch, { checked: true, onChange: () => {}, label: 'Email', hint: 'why' }))
    expect(html).toMatch(/<button id="([^"]+)" type="button" role="switch" aria-checked="true"/)
    const id = attr(html, 'button', 'id')[0]
    expect(attr(html, 'label', 'for')).toEqual([id])
    expect(attr(html, 'button', 'aria-describedby')).toEqual([`${id}-hint`])
    expect(html).toContain('wt-touch')               // 44 px sub pointer: coarse
  })
  it('ariaLabel dă numele în context; labelVisibility ascunde eticheta vizual, nu din DOM', () => {
    const html = renderToStaticMarkup(h(Switch, { checked: false, onChange: () => {}, label: 'Email',
      ariaLabel: 'Email for: Host offline', labelVisibility: 'mobile' }))
    expect(attr(html, 'button', 'aria-checked')).toEqual(['false'])
    expect(attr(html, 'button', 'aria-label')).toEqual(['Email for: Host offline'])
    expect(html).toMatch(/<label[^>]*class="[^"]*sm:sr-only[^"]*"[^>]*>Email<\/label>/)
  })
})

describe('SettingsSection', () => {
  const render = (props: Record<string, unknown>) =>
    renderToStaticMarkup(h(I18nProvider, null, h(SettingsSection, { title: 'Email (SMTP)', ...props } as never, h('p', null, 'body'))))
  it('titlu legat de secţiune, insigna de instanţă, subsolul cu „Unsaved changes", atributele trec mai departe', () => {
    const html = render({ description: 'One line.', instanceWide: true, dirty: true, footer: h('button', { type: 'button' }, 'Save'),
      'data-setting-id': 'smtp', hidden: true })
    const hid = attr(html, 'h3', 'id')[0]
    expect(attr(html, 'section', 'aria-labelledby')).toEqual([hid])
    expect(html).toContain('data-setting-id="smtp"')
    expect(html).toMatch(/<section[^>]*hidden=""/)
    expect(html).toContain('Instance-wide')
    expect(html).toContain('Unsaved changes')
    expect(html).toContain('>Save</button>')
  })
  it('tone=danger: zona periculoasă e marcată în text, nu doar prin culoare; headingLevel=4', () => {
    const html = render({ tone: 'danger', headingLevel: 4 })
    expect(html).toContain('Danger zone')
    expect(html).toMatch(/<h4 id="[^"]+"/)
    expect(html).not.toContain('Unsaved changes')
  })
})
