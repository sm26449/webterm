import { useI18n } from '../lib/i18n'

/** Etichetele-ţintă ale unui snippet (consola de flotă), ca chip-uri mici. Nimic dacă nu are. */
export default function SnippetTags(props: { tags: string[]; className?: string }) {
  const { t } = useI18n()
  if (!props.tags.length) return null
  const label = t('snippets.targetsChip', { tags: props.tags.join(', ') })
  return (
    // aria-label pe un <span> fără rol e interzis (axe: aria-prohibited-attr) → text sr-only
    <span data-testid="snippet-tags" title={label}
      className={`inline-flex shrink-0 flex-wrap items-center gap-0.5 ${props.className ?? ''}`}>
      <span className="sr-only">{label}</span>
      {props.tags.map((tag) => (
        <span key={tag} aria-hidden="true"
          className="rounded-md bg-sky-500/10 px-1 font-mono text-2xs leading-4 wt-accent ring-1 ring-sky-500/30">
          #{tag}
        </span>
      ))}
    </span>
  )
}
