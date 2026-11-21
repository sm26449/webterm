import type { ReactNode } from 'react'

/** O comandă pe un singur rând care derulează orizontal în cutia ei (3.7.1, auditul UX Setări
    Me7 / #13). Pe telefon comanda e mai lată decât cutia, iar o regiune derulabilă care nu poate
    primi focus e de neatins de la tastatură (axe `scrollable-region-focusable`, serious): finalul
    comenzii — exact partea care contează la `sudo -k …` — rămânea invizibil. De aceea: `tabIndex=0`
    (săgeţile derulează), `role="region"` cu nume, ca cititorul de ecran să anunţe ce e.
    `label` vine deja tradus (t(...)) de la apelant. Aspectul (fundal, padding, text) rămâne al
    apelantului, prin `className`; aici stau doar comportamentul şi derularea. */
export default function CodeLine(props: { label: string; className?: string; pre?: boolean; children: ReactNode }) {
  return (
    <code
      // regiunea derulabilă TREBUIE să fie focusabilă (axe scrollable-region-focusable, WCAG 2.1.1)
      // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
      tabIndex={0}
      role="region"
      aria-label={props.label}
      className={`min-w-0 flex-1 overflow-x-auto font-mono ${props.pre ? 'whitespace-pre' : 'whitespace-nowrap'}${
        props.className ? ` ${props.className}` : ''}`}
    >
      {props.children}
    </code>
  )
}
