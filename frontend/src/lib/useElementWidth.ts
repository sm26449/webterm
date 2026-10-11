import { useLayoutEffect, useState, type RefObject } from 'react'

/** Lăţimea unui element, urmărită cu ResizeObserver — pentru layout după CONTAINER (panou de
    split), nu după fereastră. Până la prima măsurare (şi fără ResizeObserver) = lăţimea ferestrei,
    adică exact comportamentul vechi bazat pe breakpoint-uri. */
export function useElementWidth(ref: RefObject<HTMLElement>): number {
  const [w, setW] = useState(() => (typeof window !== 'undefined' ? window.innerWidth : 1024))
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    setW(el.getBoundingClientRect().width)
    if (typeof ResizeObserver !== 'function') return
    const ro = new ResizeObserver((entries) => {
      const width = entries[0]?.target.getBoundingClientRect().width
      if (width) setW((prev) => (Math.abs(prev - width) >= 1 ? width : prev))
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [ref])
  return w
}
