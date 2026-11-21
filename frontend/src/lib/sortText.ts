/** Ordinea pentru liste citite de OAMENI (foldere, etichete, nume): după limbă, fără să conteze
 *  majusculele sau diacriticele, cu numerele în ordine naturală („web-2” înaintea lui „web-10”).
 *  NU pentru chei canonice (seturi comparate, semnături, id-uri): acolo `.sort()` simplu, independent
 *  de limbă, e corect intenționat (triaj SonarQube S2871, 2026-11-20). */
const collator = new Intl.Collator(undefined, { sensitivity: 'base', numeric: true })

export function byText(a: string, b: string): number {
  return collator.compare(a, b) || (a < b ? -1 : a > b ? 1 : 0)
}
