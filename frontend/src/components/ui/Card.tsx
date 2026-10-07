import type { HTMLAttributes, ReactNode } from 'react'
import { cardClass } from './classes'

/** Suprafaţa de card: rază `xl`, contur fin, fundal uşor ridicat. `padding` acoperă cazurile
    uzuale (`md` = p-4, `sm` = p-3, `none` când conţinutul îşi face singur spaţierea — liste cu
    rânduri pe toată lăţimea). `as` păstrează semantica locului (`section`, `li`…). */
export default function Card(props: HTMLAttributes<HTMLElement> & {
  as?: 'div' | 'section' | 'article' | 'li'
  padding?: 'none' | 'sm' | 'md'
  children: ReactNode
}) {
  const { as: Tag = 'div', padding = 'md', className, children, ...rest } = props
  const pad = padding === 'md' ? ' p-4' : padding === 'sm' ? ' p-3' : ''
  return (
    <Tag {...rest} className={`${cardClass}${pad}${className ? ` ${className}` : ''}`}>
      {children}
    </Tag>
  )
}
