/* Gardă de re-intrare pentru acţiuni async cu efect (3.6.1, U02).

   O stare React (`busy`) NU ajunge: se aplică la randarea următoare, deci două activări în acelaşi
   tick (dublu-clic, Enter ţinut apăsat, Enter + clic) trec amândouă de `if (busy) return` şi
   pornesc acţiunea de două ori. La consola de flotă asta înseamnă o comandă trimisă DE DOUĂ ORI
   pe fiecare host. Aici steagul e un ref setat SINCRON la prima activare şi curăţat la final
   (succes, anulare sau eroare); starea vizuală (butonul „loading") e separată, prin `onBusy`. */

export type Flag = { current: boolean }

/** Rulează `fn` doar dacă nu rulează deja. Întoarce false dacă activarea a fost ignorată. */
export async function exclusive(flag: Flag, fn: () => Promise<unknown>, onBusy?: (busy: boolean) => void): Promise<boolean> {
  if (flag.current) return false
  flag.current = true
  onBusy?.(true)
  try {
    await fn()
    return true
  } finally {
    flag.current = false
    onBusy?.(false)
  }
}
