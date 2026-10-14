import { isLayout, type SplitLayout } from '../lib/splitLayout'

/** Cheia i18n a fiecărei forme (statice, nu `'split.layout.' + x`: testul de catalog le verifică). */
export const LAYOUT_LABEL: Record<SplitLayout, string> = {
  cols2: 'split.layout.cols2',
  cols3: 'split.layout.cols3',
  'main-left': 'split.layout.mainLeft',
  'main-top': 'split.layout.mainTop',
  grid: 'split.layout.grid',
}

/** Iconul unei forme de split (chip, picker, meniu): un dreptunghi cu liniile despărţitoare. */
export function LayoutIcon(props: { layout?: string; size?: number }) {
  const l: SplitLayout = isLayout(props.layout) ? props.layout : 'cols2'
  const d = {
    cols2: 'M8 2.5v11',
    cols3: 'M6 2.5v11M10.5 2.5v11',
    'main-left': 'M8 2.5v11M8 8h6.5',
    'main-top': 'M1.5 8h13M8 8v5.5',
    grid: 'M8 2.5v11M1.5 8h13',
  }[l]
  const s = props.size ?? 13
  return (
    <svg width={s} height={s} viewBox="0 0 16 16" fill="none" stroke="currentColor"
      strokeWidth="1.5" strokeLinecap="round" aria-hidden="true">
      <rect x="1.5" y="2.5" width="13" height="11" rx="1.5" /><path d={d} />
    </svg>
  )
}
