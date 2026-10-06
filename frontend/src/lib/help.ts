import { getBootVersion } from './api'

/* Ajutor contextual („?") — registrul. Fiecare intrare leagă un loc din UI de:
   - un text scurt în lang/* (`help.<id>.title` / `help.<id>.body`): la ce folosește, când îți trebuie;
   - opțional un exemplu copiabil, construit cu URL-ul instanței (un `curl` gata de lipit);
   - documentul complet din repo, pe tag-ul versiunii care RULEAZĂ — nu pe main, ca textul
     să descrie exact ce ai în față.
   Motivul: un hint dens sub o setare nu mai spune nimic după o lună („la ce erau tokenurile?"),
   iar documentația exista, dar nimic din UI nu ducea la ea. */

const REPO = 'https://github.com/sm26449/webterm'

export const HELP = {
  tokens: { doc: 'docs/AUTOMATION-TOKENS.md#examples',
    example: (o: string) => `curl -s -H "Authorization: Bearer wt_…" ${o}/api/hosts | jq '.[] | {name, online}'` },
  guardrail: { doc: 'docs/GUARDRAIL.md#rules-confirm-vs-block' },
  signingKey: { doc: 'docs/design/SIGNED-UPDATES.md#whose-key' },
  enrollGroups: { doc: 'docs/FLEET.md#fleet-scale-onboarding' },
  deployKeyPolicy: { doc: 'docs/SSH-KEYS.md#deploy-key-policy-settings--security' },
  smtp: { doc: 'docs/ALERTS.md#events' },
  webhook: { doc: 'docs/ALERTS.md#channels-email-and-webhook' },
  resourceAlerts: { doc: 'docs/ALERTS.md#resource-thresholds' },
  forwardDomain: { doc: 'docs/PORT-FORWARDING.md#configurable-domain-settings' },
  directBackup: { doc: 'docs/RUNBOOK.md#backuprestore-from-the-application-v1061-no-shell-on-the-server' },
  updatesBadge: { doc: 'docs/HOSTS.md#os-updates-badge' },
  autostart: { doc: 'docs/HOSTS.md#starting-at-boot' },
  wol: { doc: 'docs/HOSTS.md#wake-on-lan' },
  tags: { doc: 'docs/HOSTS.md#tags' },
  require2fa: { doc: 'docs/HOSTS.md#require-2fa-step-up' },
  credentialPolicy: { doc: 'docs/HOSTS.md#credential-policies' },
  enrollTtl: { doc: 'docs/HOSTS.md#install-links-and-their-ttl' },
  aiTools: { doc: 'docs/AI-TOOLS.md#what-it-is-for' },
  toolbox: { doc: 'docs/DATABASE-TOOLBOX.md#connections--one-click-to-a-database-cli' },
  forwardsSso: { doc: 'docs/SSO.md#register-a-webterm-instance-in-your-idp' },
} satisfies Record<string, { doc: string; example?: (origin: string) => string }>

export type HelpId = keyof typeof HELP

/** Ref-ul de git pentru documentație: tag-ul versiunii care rulează (`v3.5.1`), sau `main` cât
    timp versiunea nu e încă știută (primul răspuns API n-a venit) ori e un build de dev. */
export function docsRef(version: string | null = getBootVersion()): string {
  return version && /^\d+\.\d+\.\d+$/.test(version) ? `v${version}` : 'main'
}

export function docsUrl(doc: string, version?: string | null): string {
  return `${REPO}/blob/${docsRef(version)}/${doc}`
}
