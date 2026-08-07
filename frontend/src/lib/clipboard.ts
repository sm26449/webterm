/* Copierea în clipboard, cu o cale de rezervă care merge fără context securizat.

   `navigator.clipboard` există DOAR în „secure context": HTTPS, sau `127.0.0.1`/`localhost`.
   O instalare pe IP de rețea sau pe hostname intern fără TLS — caz documentat şi susţinut de
   produs — nu are obiectul deloc, iar apelurile pică cu TypeError. Aproape toate locurile
   care copiau făceau `.catch(() => {})`, deci butonul „copiază" nu făcea nimic şi nici nu
   spunea nimic: comanda, output-ul, blocul markdown, URL-ul de share.

   `document.execCommand('copy')` e depreciat, dar funcţionează şi pe origini nesecurizate şi
   e singura cale acolo. Îl folosim ca rezervă, nu ca primă opţiune.

   Pentru CITIRE nu există rezervă: `execCommand('paste')` e blocat din motive de securitate
   în toate browserele. De aceea `readText` întoarce null, iar apelantul trebuie să spună
   utilizatorului că poate lipi cu tastatura (Ctrl+V ajunge la xterm oricum). */

export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    /* refuzat (permisiune, focus pierdut) → încercăm rezerva */
  }
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    // în afara ecranului, dar NU `display:none`/`hidden`: o zonă needitabilă sau
    // nerandată nu se poate selecta, iar `execCommand` ar întoarce false
    ta.setAttribute('readonly', '')
    ta.style.cssText = 'position:fixed;top:0;left:-9999px;opacity:0'
    document.body.appendChild(ta)
    ta.select()
    ta.setSelectionRange(0, text.length)
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return ok
  } catch {
    return false
  }
}

/** Textul din clipboard, sau null dacă browserul nu ne lasă să-l citim. */
export async function readText(): Promise<string | null> {
  try {
    if (!navigator.clipboard?.readText) return null
    return await navigator.clipboard.readText()
  } catch {
    return null
  }
}
