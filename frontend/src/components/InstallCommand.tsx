import { useState } from 'react'
import { useI18n } from '../lib/i18n'
import { copyText } from '../lib/clipboard'

/** Comanda de instalare a agentului, în două variante.

    Implicit e cea cu **user dedicat**, fiindcă asta e diferența dintre „gateway-ul are
    drepturile lui webterm pe host" și „gateway-ul e root pe host". Varianta cu utilizatorul
    curent rămâne la un click, pentru mașinile unde chiar vrei asta (sau unde nu există sudo).

    `enable-linger` face parte din comandă, nu din documentație: fără el `systemd --user`
    oprește serviciul când userul n-are sesiune de login, iar agentul pare că moare singur. */
export default function InstallCommand(props: { command: string; commandDedicated?: string }) {
  const { t } = useI18n()
  const [dedicated, setDedicated] = useState(true)
  const [copied, setCopied] = useState(false)
  const [err, setErr] = useState('')
  const cmd = dedicated && props.commandDedicated ? props.commandDedicated : props.command

  const Tab = (p: { on: boolean; label: string; onClick: () => void }) => (
    <button
      type="button"
      onClick={p.onClick}
      className={`rounded-md px-2.5 py-1 text-xs font-medium transition ${
        p.on ? 'bg-ink-700 text-slate-100' : 'text-slate-400 hover:text-slate-200'}`}
    >
      {p.label}
    </button>
  )

  return (
    <div>
      {props.commandDedicated && (
        <div className="mt-3 inline-flex gap-1 rounded-lg bg-ink-800/70 p-1">
          <Tab on={dedicated} label={t('addhost.asDedicated')}
               onClick={() => { setDedicated(true); setCopied(false) }} />
          <Tab on={!dedicated} label={t('addhost.asCurrent')}
               onClick={() => { setDedicated(false); setCopied(false) }} />
        </div>
      )}
      <div className="mt-2 flex items-stretch gap-2">
        {/* fundal opac întunecat FIX (nu black/50 peste sticla albă din Aurora):
            emerald-300 are contrast bun doar pe întunecat plin */}
        <code className="flex-1 select-all overflow-x-auto whitespace-nowrap rounded-lg bg-[#0b0e14] p-3 text-xs text-emerald-300">
          {cmd}
        </code>
        <button
          onClick={async () => {
            // ✓ apare doar la copiere reală. `copyText` cade pe execCommand când
            // originea nu e securizată (deploy pe IP), deci de obicei reuşeşte.
            if (await copyText(cmd)) {
              setCopied(true)
              setErr('')
            } else {
              setErr(t('addhost.clipboardError'))
            }
          }}
          className="shrink-0 rounded-lg bg-sky-600 px-3 text-sm font-medium text-white hover:bg-sky-700"
        >
          {copied ? '✓' : t('addhost.copy')}
        </button>
      </div>
      <p className="mt-2 text-xs text-slate-500">
        {dedicated && props.commandDedicated ? t('addhost.dedicatedHint') : t('addhost.currentHint')}
      </p>
      {err && <div className="mt-2 text-sm wt-danger">{err}</div>}
    </div>
  )
}
