import { useEffect, useRef, useState, useSyncExternalStore } from 'react'
import { createPortal } from 'react-dom'
import { api, errText, timeAgo, type Host } from '../lib/api'
import { AlertItem, AlertPage, badgeText, mergePage, normSeverity, setUnread, severityTone, unreadStore } from '../lib/alerts'
import { useI18n } from '../lib/i18n'
import { useFocusTrap } from '../lib/useFocusTrap'
import { fmtTs } from '../lib/tz'
import { BellIcon, CheckCircleIcon, CloseIcon, InfoIcon, WarningIcon } from './Icons'
import { Badge, Button, EmptyState, ErrorState, IconButton, compactAction } from './ui'

/* Clopoţelul de alerte (3.5.11) + panoul cu istoricul.

   Clopoţelul stă în antetul sidebar-ului, lângă Status şi Setări — cromul aplicaţiei, vizibil pe
   orice ecran (pe mobil în drawer). Insigna cu numărul de necitite nu e doar culoare: are cifra,
   iar numele accesibil al butonului spune „Alerte — necitite: N".

   Panoul e un dialog (acelaşi tipar ca StatusModal: focus-trap, Escape, focus restaurat), lăţime
   max-w-md, cu gutter de 16px pe telefon (p-4). Nimic nu se marchează citit „pe ascuns" la
   deschidere: omul alege „Marchează toate citite", sau deschide detaliile unei alerte. */

const PAGE = 30

function SevIcon(props: { sev: string }) {
  const s = normSeverity(props.sev)
  if (s === 'ok') return <CheckCircleIcon size={12} />
  if (s === 'info') return <InfoIcon size={12} />
  return <WarningIcon size={12} />
}

export function AlertsBell(props: { hosts: Host[]; onOpenHost: (id: number) => void; onOpenSettings: () => void }) {
  const { t } = useI18n()
  const unread = useSyncExternalStore(unreadStore.subscribe, unreadStore.snapshot)
  const [open, setOpen] = useState(false)
  const label = unread > 0 ? t('alerts.bellAriaUnread', { n: unread }) : t('alerts.bellAria')
  return (
    <>
      <IconButton size="md" label={label} onClick={() => setOpen(true)} className="relative"
        aria-haspopup="dialog" data-testid="wt-alerts-bell">
        <BellIcon size={16} />
        {unread > 0 && (
          // decorativ: numărul e deja în numele accesibil al butonului
          <span aria-hidden="true"
            className="absolute -right-0.5 -top-0.5 min-w-4 rounded-full bg-rose-600 px-1 text-center text-2xs font-semibold leading-4 text-white ring-2 ring-ink-900">
            {badgeText(unread)}
          </span>
        )}
      </IconButton>
      {/* portal în <body>: sidebar-ul (sticlă / backdrop-filter) e containing block pentru `fixed`,
          deci randat pe loc, dialogul rămânea închis în lăţimea sidebar-ului în loc să fie centrat */}
      {open && createPortal(
        <AlertsPanel hosts={props.hosts} onClose={() => setOpen(false)}
          onOpenHost={(id) => { setOpen(false); props.onOpenHost(id) }}
          onOpenSettings={() => { setOpen(false); props.onOpenSettings() }} />,
        document.body,
      )}
    </>
  )
}

export default function AlertsPanel(props: {
  hosts: Host[]
  onClose: () => void
  onOpenHost: (id: number) => void
  onOpenSettings: () => void
}) {
  const { t } = useI18n()
  const dialogRef = useRef<HTMLDivElement>(null)
  useFocusTrap(dialogRef, props.onClose)
  const [items, setItems] = useState<AlertItem[] | null>(null)
  const [unread, setUnreadLocal] = useState(0)
  const [next, setNext] = useState<number | null>(null)
  const [unreadOnly, setUnreadOnly] = useState(false)
  const [loadErr, setLoadErr] = useState('')
  const [actionErr, setActionErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [confirmClear, setConfirmClear] = useState(false)
  const [expanded, setExpanded] = useState<Set<number>>(new Set())

  const syncUnread = (n: number) => { setUnreadLocal(n); setUnread(n) }

  async function load(before?: number) {
    setLoadErr('')
    try {
      const q = new URLSearchParams({ limit: String(PAGE) })
      if (before) q.set('before', String(before))
      if (unreadOnly) q.set('unread', 'true')
      const page = await api<AlertPage>(`/api/alerts?${q}`)
      setItems((cur) => (before && cur ? mergePage(cur, page.alerts) : page.alerts))
      setNext(page.next_before)
      syncUnread(page.unread)
    } catch (e) {
      setLoadErr(errText(e, t) || '')
      if (!before) setItems(null)
    }
  }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { setItems(null); load() }, [unreadOnly])

  async function act(fn: () => Promise<void>) {
    setActionErr(''); setBusy(true)
    try { await fn() } catch (e) { setActionErr(errText(e, t) || t('alerts.actionFailed')) } finally { setBusy(false) }
  }
  const markRead = (ids: number[] | 'all') => act(async () => {
    const r = await api<{ unread: number }>('/api/alerts/read', {
      method: 'POST', body: JSON.stringify(ids === 'all' ? { all: true } : { ids }),
    })
    syncUnread(r.unread)
    setItems((cur) => {
      if (!cur) return cur
      const done = cur.map((a) => (ids === 'all' || ids.includes(a.id) ? { ...a, read: true } : a))
      return unreadOnly ? done.filter((a) => !a.read) : done
    })
  })
  const clearAll = () => act(async () => {
    await api('/api/alerts', { method: 'DELETE' })
    setItems([]); setNext(null); syncUnread(0); setConfirmClear(false)
  })
  const toggleDetails = (a: AlertItem) => {
    setExpanded((s) => {
      const n = new Set(s)
      if (n.has(a.id)) n.delete(a.id); else n.add(a.id)
      return n
    })
    if (!a.read) markRead([a.id])         // a deschis-o = a citit-o
  }

  const hostName = (id: number | null) => (id == null ? null : props.hosts.find((h) => h.id === id)?.name ?? null)

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/50 p-4 sm:items-center" onClick={props.onClose}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="wt-alerts-title"
        data-testid="wt-alerts-panel"
        className="glass flex max-h-[88vh] w-full max-w-md flex-col overflow-hidden rounded-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2 border-b border-ink-700 px-4 py-3">
          <h2 id="wt-alerts-title" className="text-lg font-semibold">{t('alerts.title')}</h2>
          <span className="text-xs text-slate-400" role="status">
            {unread > 0 ? t('alerts.unreadCount', { n: unread }) : items && items.length > 0 ? t('alerts.allRead') : ''}
          </span>
          <IconButton label={t('common.close')} onClick={props.onClose} className="ml-auto">
            <CloseIcon size={14} />
          </IconButton>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-b border-ink-800 px-4 py-2 text-xs">
          <label className="wt-touch inline-flex items-center gap-1.5 text-slate-300">
            <input type="checkbox" checked={unreadOnly} onChange={(e) => setUnreadOnly(e.target.checked)} />
            {t('alerts.unreadOnly')}
          </label>
          <span className="ml-auto flex flex-wrap items-center gap-1.5">
            <Button size="sm" variant="secondary" disabled={busy || unread === 0} onClick={() => markRead('all')}>
              {t('alerts.markAllRead')}
            </Button>
            {!confirmClear ? (
              <Button size="sm" variant="ghost" disabled={busy || !items || items.length === 0}
                onClick={() => setConfirmClear(true)}>
                {t('alerts.clear')}
              </Button>
            ) : null}
          </span>
          {confirmClear && (
            <div role="alertdialog" aria-labelledby="wt-alerts-clear-q"
              className="flex w-full flex-wrap items-center gap-2 rounded-md bg-ink-800 p-2">
              <span id="wt-alerts-clear-q" className="min-w-0 flex-1 text-slate-300">{t('alerts.clearConfirm')}</span>
              <Button size="sm" variant="danger" disabled={busy} onClick={clearAll} autoFocus>{t('alerts.clear')}</Button>
              <Button size="sm" variant="secondary" onClick={() => setConfirmClear(false)}>{t('common.cancel')}</Button>
            </div>
          )}
          <span role="alert" className={actionErr ? 'w-full wt-danger' : 'sr-only'}>{actionErr}</span>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto">
          {loadErr && !items ? (
            <ErrorState title={t('alerts.loadFailed')} message={loadErr} onRetry={() => load()} />
          ) : !items ? (
            <p className="p-4 text-sm text-slate-500">{t('alerts.loading')}</p>
          ) : items.length === 0 ? (
            <EmptyState icon={<BellIcon />} tone="neutral"
              title={unreadOnly ? t('alerts.emptyUnread') : t('alerts.empty')}
              body={unreadOnly ? undefined : t('alerts.emptyBody')} />
          ) : (
            <ul className="divide-y divide-ink-800" aria-label={t('alerts.title')}>
              {items.map((a) => {
                const sev = normSeverity(a.severity)
                const open = expanded.has(a.id)
                const hn = hostName(a.host_id)
                return (
                  <li key={a.id} className={`px-4 py-3 ${a.read ? '' : 'bg-sky-500/5'}`} data-alert-id={a.id}>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <Badge tone={severityTone(sev)}><SevIcon sev={sev} />{t(`alerts.sev.${sev}`)}</Badge>
                      {!a.read && <Badge tone="accent">{t('alerts.new')}</Badge>}
                      <span className="ml-auto text-2xs tabular-nums text-slate-500" title={fmtTs(a.ts)}>
                        <time dateTime={new Date(a.ts * 1000).toISOString()}>{t('alerts.ago', { time: timeAgo(a.ts, t) })}</time>
                      </span>
                    </div>
                    <p className={`mt-1 break-words text-sm ${a.read ? 'text-slate-300' : 'font-medium text-slate-100'}`}>{a.title}</p>
                    <p className="mt-0.5 text-2xs text-slate-500">{t(`alerts.kind.${a.kind}`)}</p>
                    <div className="mt-1.5 flex flex-wrap items-center gap-1">
                      {a.details && (
                        <button type="button" className={`${compactAction} text-slate-300`} aria-expanded={open}
                          onClick={() => toggleDetails(a)}>
                          {open ? t('alerts.hideDetails') : t('alerts.showDetails')}
                        </button>
                      )}
                      {a.host_id != null && (hn ? (
                        <button type="button" className={`${compactAction} wt-link`} onClick={() => props.onOpenHost(a.host_id!)}>
                          {t('alerts.openHost')}: {hn}
                        </button>
                      ) : (
                        <span className="text-2xs text-slate-500">{t('alerts.hostGone')}</span>
                      ))}
                      {!a.read && (
                        <button type="button" className={`${compactAction} ml-auto text-slate-400`} disabled={busy}
                          onClick={() => markRead([a.id])}>
                          {t('alerts.markRead')}
                        </button>
                      )}
                    </div>
                    {open && a.details && (
                      <pre className="mt-2 whitespace-pre-wrap break-words rounded-md bg-ink-950/60 p-2 font-mono text-2xs text-slate-300">{a.details}</pre>
                    )}
                  </li>
                )
              })}
            </ul>
          )}
          {items && next != null && (
            <div className="p-3 text-center">
              <Button size="sm" variant="secondary" onClick={() => load(next)}>{t('alerts.loadMore')}</Button>
            </div>
          )}
          {loadErr && items && <ErrorState compact title={t('alerts.loadFailed')} message={loadErr} onRetry={() => load(next ?? undefined)} />}
        </div>

        <div className="flex flex-wrap items-center gap-2 border-t border-ink-800 px-4 py-2 text-2xs text-slate-500">
          <span className="min-w-0 flex-1">{t('alerts.retention')}</span>
          <button type="button" className={`${compactAction} wt-link`} onClick={props.onOpenSettings}>{t('alerts.settings')}</button>
        </div>
      </div>
    </div>
  )
}
