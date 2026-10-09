import { useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { api, errText, Host } from '../lib/api'
import { Conflict, startCopy } from '../lib/copyjobs'
import { useI18n } from '../lib/i18n'
import { lsGet, lsSet } from '../lib/storage'
import { useFocusTrap } from '../lib/useFocusTrap'
import { FolderIcon, LevelUpIcon } from './Icons'

/* „Copiază pe host…" (3.5.5): alegi hostul destinaţie (doar hosturi cu agent ONLINE; sursa apare
   ultima, ca „acelaşi host" — duplicat / alt director), folderul destinaţie (câmp + un mic
   browser de foldere care refoloseşte listarea /fs a panoului de fişiere, deci şi step-up-ul ei)
   şi regula „dacă există". Copierea rulează pe gateway (lib/copyjobs.ts) şi apare în Transferuri;
   dialogul se închide imediat ce job-ul a pornit.

   Limitele se spun AICI, înainte de click, nu după. Folderele (3.6) se copiază cu tot conţinutul;
   permisiunile se păstrează doar dacă agentul DESTINAŢIEI e ≥ 58 (op-ul `fs_chmod`) — altfel
   spunem, pentru hostul ales, că un fişier privat (ex. 0600) aterizează cu permisiunile implicite
   (de obicei 0644) şi că scripturile îşi pierd bitul de execuţie. */

export interface CopyItem { name: string; path: string; dir: boolean; mode: number }
interface DirEntry { name: string; dir: boolean }
interface Listing { path: string; parent: string; entries: DirEntry[]; truncated: boolean }

const LAST_DIR = (hostId: number) => `wt_copy_dir_${hostId}`
/** agentul de la care destinaţia păstrează permisiunile (op-ul `fs_chmod`) */
const COPY_MODES_MIN_AGENT = 58
const LAST_CONFLICT = 'wt_copy_conflict'

export default function CopyToHostDialog(props: {
  srcHost: Host
  items: CopyItem[]
  onClose: () => void
  /** după pornire (rowId-ul din Transferuri) — panoul îşi goleşte selecţia */
  onStarted: () => void
}) {
  const { t } = useI18n()
  const ref = useRef<HTMLDivElement>(null)
  useFocusTrap(ref, props.onClose)
  const files = useMemo(() => props.items.filter((i) => !i.dir), [props.items])
  const folders = props.items.length - files.length
  // fişier „privat" = fără niciun drept pentru grup/alţii (0600, 0400…): pe o destinaţie cu agent
  // < 58 primeşte permisiunile implicite (umask-ul agentului) — o cheie SSH ar deveni citibilă
  const privateN = files.filter((f) => (f.mode & 0o077) === 0 && f.mode !== 0).length

  const [hosts, setHosts] = useState<Host[] | null>(null)
  const [dst, setDst] = useState<number | null>(null)
  const [dir, setDir] = useState('~')
  const [listing, setListing] = useState<Listing | null>(null)
  const [listErr, setListErr] = useState('')
  const [conflict, setConflict] = useState<Conflict>(() => {
    const v = lsGet(LAST_CONFLICT)
    return v === 'overwrite' || v === 'rename' ? v : 'skip'
  })
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  // hosturi-destinaţie: doar agent + online; sursa la final (copiere pe acelaşi host)
  useEffect(() => {
    api<Host[]>('/api/hosts').then((hs) => {
      const ok = hs.filter((h) => (!h.connection_type || h.connection_type === 'agent') && h.online)
      const others = ok.filter((h) => h.id !== props.srcHost.id)
      const self = ok.filter((h) => h.id === props.srcHost.id)
      const list = [...others, ...self]
      setHosts(list)
      if (list.length) pick(list[0].id)
    }).catch((e) => setErr(errText(e, t)))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // generaţie monotonă (ca `load` din FilePanel): doar răspunsul CEL MAI RECENT se aplică — altfel
  // listarea iniţială a lui `~`, sosită târziu, suprascria folderul tastat între timp
  const browseSeq = useRef(0)
  const browse = async (hostId: number, path: string) => {
    const my = ++browseSeq.current
    setListErr('')
    try {
      const l = await api<Listing>(`/api/hosts/${hostId}/fs?path=${encodeURIComponent(path)}`)
      if (my !== browseSeq.current) return
      setListing(l)
      setDir(l.path)
    } catch (e) {
      if (my !== browseSeq.current) return
      setListing(null)
      setListErr(errText(e, t))
    }
  }
  const pick = (hostId: number) => {
    setDst(hostId)
    const last = lsGet(LAST_DIR(hostId)) || '~'
    setDir(last)
    void browse(hostId, last)
  }

  const target = hosts?.find((h) => h.id === dst)
  // `fs_chmod` există din agentul 58; versiune necunoscută = tratată ca veche (spunem, nu promitem)
  const keepsModes = (target?.agent_version ?? 0) >= COPY_MODES_MIN_AGENT

  const submit = async () => {
    if (dst == null || !props.items.length || busy) return
    setBusy(true); setErr('')
    try {
      await startCopy({
        srcHost: props.srcHost.id, srcName: props.srcHost.name, dstHost: dst, dstName: target?.name ?? `#${dst}`,
        paths: props.items.map((f) => f.path), dstDir: dir.trim() || '~', onConflict: conflict,
      })
      lsSet(LAST_DIR(dst), dir.trim() || '~')
      lsSet(LAST_CONFLICT, conflict)
      props.onStarted()
      props.onClose()
    } catch (e) {
      setErr(errText(e, t))
      setBusy(false)
    }
  }

  const subdirs = (listing?.entries ?? []).filter((e) => e.dir)
  const BTN = 'rounded-md px-2 py-1 text-xs'

  return createPortal(
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4" onClick={props.onClose}>
      {/* eslint-disable-next-line jsx-a11y/no-noninteractive-element-interactions -- Escape local: altfel îl prinde şi drawer-ul panoului de fişiere (portalul păstrează bubbling-ul React) */}
      <div ref={ref} role="dialog" aria-modal="true" aria-labelledby="wt-copy-title" data-testid="wt-copy-dialog"
        className="glass flex max-h-[90vh] w-full max-w-md flex-col overflow-y-auto overscroll-contain rounded-2xl p-4 text-xs"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => { if (e.key === 'Escape') { e.stopPropagation(); props.onClose() } }}>
        <h2 id="wt-copy-title" className="text-base font-semibold">
          {folders > 0 ? t('copy.titleItems', { count: props.items.length, host: props.srcHost.name })
            : t('copy.title', { count: files.length, host: props.srcHost.name })}
        </h2>
        <p className="mt-1 text-slate-400">{t('copy.serverSide')}</p>

        <label className="mt-3 block text-slate-300" htmlFor="wt-copy-host">{t('copy.dstHost')}</label>
        {hosts && hosts.length === 0 ? (
          <p className="mt-1 wt-warn">{t('copy.noHosts')}</p>
        ) : (
          <select id="wt-copy-host" value={dst ?? ''} onChange={(e) => pick(Number(e.target.value))}
            className="mt-1 w-full rounded-md bg-ink-800 px-2 py-1.5 text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500">
            {(hosts ?? []).map((h) => (
              <option key={h.id} value={h.id}>{h.id === props.srcHost.id ? t('copy.sameHost', { host: h.name }) : h.name}</option>
            ))}
          </select>
        )}

        <label className="mt-3 block text-slate-300" htmlFor="wt-copy-dir">{t('copy.dstDir')}</label>
        <div className="mt-1 flex gap-1">
          <button type="button" disabled={!listing || listing.path === '/'} onClick={() => dst != null && listing && browse(dst, listing.parent)}
            className="wt-touch shrink-0 rounded-md px-2 text-slate-400 ring-1 ring-ink-700 hover:bg-ink-800 disabled:opacity-30"
            aria-label={t('files.upLevel')} title={t('files.upLevel')}><LevelUpIcon size={14} /></button>
          <input id="wt-copy-dir" value={dir} spellCheck={false} onChange={(e) => setDir(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && dst != null) { e.preventDefault(); void browse(dst, dir) } }}
            className="min-w-0 flex-1 rounded-md bg-ink-800 px-2 py-1 font-mono text-2xs text-slate-200 ring-1 ring-ink-700 focus:ring-sky-500" />
        </div>
        <ul aria-label={t('copy.folders')} className="mt-1 max-h-36 min-h-[3rem] overflow-y-auto rounded-md bg-ink-900/60 ring-1 ring-ink-800">
          {listErr && <li className="px-2 py-1 wt-danger">{listErr}</li>}
          {!listErr && listing && subdirs.length === 0 && <li className="px-2 py-1 text-slate-500">{t('copy.noSubfolders')}</li>}
          {subdirs.map((d) => (
            <li key={d.name}>
              <button type="button" onClick={() => dst != null && browse(dst, `${listing!.path.replace(/\/$/, '')}/${d.name}`)}
                className="flex w-full items-center gap-2 px-2 py-1 text-left font-mono text-2xs wt-link hover:bg-ink-800 [@media(pointer:coarse)]:min-h-[36px]">
                <FolderIcon />{d.name}/
              </button>
            </li>
          ))}
        </ul>

        <fieldset className="mt-3">
          <legend className="text-slate-300">{t('copy.ifExists')}</legend>
          <div className="mt-1 flex flex-wrap gap-3">
            {(['skip', 'overwrite', 'rename'] as Conflict[]).map((c) => (
              <label key={c} className="flex items-center gap-1.5 text-slate-300">
                <input type="radio" name="wt-copy-conflict" value={c} checked={conflict === c} onChange={() => setConflict(c)} />
                {t(`copy.conflict_${c}`)}
              </label>
            ))}
          </div>
        </fieldset>

        {folders > 0 && <p className="mt-3 text-slate-300">{t('copy.foldersInfo', { count: folders })}</p>}
        {target && (keepsModes
          ? <p className="mt-2 text-slate-400" data-testid="wt-copy-modes">{t('copy.modesKept')}</p>
          : <p className="mt-2 wt-warn" data-testid="wt-copy-modes">{t('copy.modesLost', { host: target.name })}</p>)}
        {!keepsModes && privateN > 0 && <p className="mt-2 wt-warn">{t('copy.privateWarn', { count: privateN })}</p>}
        <p className="mt-2 text-2xs text-slate-500">{t('copy.limits')}</p>
        {err && <p role="alert" className="mt-2 wt-danger">{err}</p>}

        <div className="mt-4 flex justify-end gap-2">
          <button type="button" onClick={props.onClose} className={`${BTN} text-slate-300 ring-1 ring-ink-700 hover:bg-ink-800`}>{t('files.cancel')}</button>
          <button type="button" onClick={() => void submit()} disabled={busy || dst == null || !props.items.length || !!listErr}
            className={`${BTN} bg-sky-600 font-medium text-white hover:bg-sky-700 disabled:opacity-40`}>
            {folders > 0 ? t('copy.startItems', { count: props.items.length }) : t('copy.start', { count: files.length })}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  )
}
