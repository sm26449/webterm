import { Command, cmdDuration } from '../lib/commands'
import { useI18n } from '../lib/i18n'

/** Lista comenzilor din sesiune (blocks): sari la oricare, vezi care a eșuat,
    copiază exact output-ul ei. Apare doar când shell integration e activă. */
export default function CommandsPanel(props: {
  commands: Command[]
  activeId: number | null
  onJump: (c: Command) => void
  onRerun: (c: Command) => void
  onCopyCommand: (c: Command) => void
  onCopyOutput: (c: Command) => void
  onCopyMarkdown: (c: Command) => void
  onClose: () => void
  onSetup: () => void
  overlay?: boolean
}) {
  const { t } = useI18n()
  // pe pane-uri înguste (telefon, sau split pe iPad) panoul e DRAWER peste
  // terminal (cu scrim); pe pane-uri late revine coloana laterală clasică.
  // Decizia pe lățimea REALĂ a pane-ului, nu pe viewport.
  const scrimCls = 'fixed inset-0 z-30 bg-black/60' + (props.overlay ? '' : ' sm:hidden')
  const asideCls = 'fixed inset-y-0 right-0 z-40 flex w-[85vw] max-w-xs flex-col border-l border-ink-800 bg-ink-900 shadow-2xl'
    + (props.overlay ? '' : ' sm:static sm:z-auto sm:w-64 sm:max-w-none sm:shrink-0 sm:shadow-none')
  return (
    <>
    <div className={scrimCls} onClick={props.onClose} aria-hidden="true" />
    <aside aria-label={t('cmds.sessionCommands')} className={asideCls}>
      <header className="flex items-center gap-2 border-b border-ink-800 px-3 py-2">
        <span className="text-xs font-semibold uppercase tracking-wide text-slate-400">{t('cmds.commands')}</span>
        <span className="rounded bg-ink-800 px-1.5 text-[11px] text-slate-500">{props.commands.length}</span>
        <button
          onClick={props.onClose}
          aria-label={t('cmds.closePanel')}
          className="wt-touch ml-auto rounded px-1.5 text-slate-500 hover:bg-ink-800 hover:text-slate-300"
        >
          ✕
        </button>
      </header>

      {props.commands.length === 0 ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-3 p-4 text-center">
          <p className="text-xs leading-relaxed text-slate-500">
            {t('cmds.emptyHint')}
          </p>
          <button
            onClick={props.onSetup}
            className="rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-700"
          >
            {t('cmds.enableShell')}
          </button>
        </div>
      ) : (
        <div className="min-h-0 flex-1 overflow-y-auto">
          {[...props.commands].reverse().map((c) => {
            const failed = c.exitCode != null && c.exitCode !== 0
            return (
              <div
                key={c.id}
                className={`group border-b border-ink-800/60 px-2.5 py-1.5 ${
                  props.activeId === c.id ? 'bg-ink-800' : 'hover:bg-ink-800/60'
                }`}
              >
                <button onClick={() => props.onJump(c)} className="block w-full text-left">
                  <div className="flex items-center gap-1.5">
                    <span
                      className={`h-1.5 w-1.5 shrink-0 rounded-full ${failed ? 'bg-rose-500' : 'bg-emerald-500'}`}
                      aria-hidden="true"
                    />
                    <span className="truncate font-mono text-[11px] text-slate-200">{c.text}</span>
                  </div>
                  <div className="mt-0.5 flex items-center gap-2 pl-3 text-[10px] tabular-nums text-slate-500">
                    {failed && <span className="wt-danger">exit {c.exitCode}</span>}
                    {c.endedAt && <span>{cmdDuration(c)}</span>}
                  </div>
                </button>
                {/* acțiuni pe bloc, apar pe hover — simple și fără ambiguitate */}
                <div className="mt-1 hidden flex-wrap items-center gap-x-2 gap-y-1 pl-3 text-[10px] group-hover:flex">
                  <button
                    onClick={() => props.onRerun(c)}
                    title={t('cmds.rerunTitle')}
                    className="rounded px-1 py-0.5 font-medium text-sky-400 hover:bg-ink-700"
                  >
                    {t('cmds.rerun')}
                  </button>
                  <span className="flex items-center gap-1.5 text-slate-500">
                    <span>{t('cmds.copy')}</span>
                    <button onClick={() => props.onCopyCommand(c)} title={t('cmds.copyCommandTitle')}
                      className="wt-link hover:underline">{t('cmds.commandWord')}</button>
                    <button onClick={() => props.onCopyOutput(c)} title={t('cmds.copyOutputTitle')}
                      className="wt-link hover:underline">{t('cmds.outputWord')}</button>
                    <button onClick={() => props.onCopyMarkdown(c)} title={t('cmds.copyMarkdownTitle')}
                      className="wt-link hover:underline">{t('cmds.markdownWord')}</button>
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </aside>
    </>
  )
}
