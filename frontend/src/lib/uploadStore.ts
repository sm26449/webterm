// Starea upload-urilor trăieşte în AFARA componentelor. Închiderea panoului de fişiere nu
// opreşte transferul (bucla `uploadOne` rulează mai departe în closure-ul ei), dar înainte îl
// făcea INVIZIBIL şi neanulabil: redeschiderea găsea o listă goală, iar re-drop-ul aceluiaşi
// fişier pornea un al doilea scriitor pe acelaşi upload_id. Un store la nivel de modul
// (consumat cu useSyncExternalStore) păstrează şi progresul, şi controlul — redeschizi
// panoul, vezi transferul în mers, îl poţi anula.
export type UploadState = { pct: number; state: 'up' | 'done' | 'err' }
export type UploadCtl = {
  xhr: XMLHttpRequest | null; cancelled: boolean; dest: string; uid: string; lsKey: string
}

// cheie (host, cale relativă): două sesiuni pe ACELAŞI host îşi văd reciproc upload-urile
// (sunt aceleaşi fişiere-ţintă), host-uri diferite nu. Separator NUL — singurul octet care
// nu poate apărea într-un nume de fişier POSIX.
const SEP = String.fromCharCode(0)
export const uploadKey = (hostId: number, rel: string) => `${hostId}${SEP}${rel}`
export const uploadRel = (key: string) => key.slice(key.indexOf(SEP) + 1)
export const uploadHost = (key: string) => Number(key.slice(0, key.indexOf(SEP)))

const state = new Map<string, UploadState>()
const ctls = new Map<string, UploadCtl>()
const subs = new Set<() => void>()
let snap: ReadonlyMap<string, UploadState> = new Map()

function emit() {
  snap = new Map(state)              // snapshot imuabil: useSyncExternalStore compară referinţe
  subs.forEach((f) => f())
}

export const uploadStore = {
  subscribe(f: () => void): () => void {
    subs.add(f)
    return () => { subs.delete(f) }
  },
  snapshot(): ReadonlyMap<string, UploadState> { return snap },
  set(key: string, s: UploadState): void { state.set(key, s); emit() },
  remove(key: string): void { if (state.delete(key)) emit() },
  ctl: (key: string): UploadCtl | undefined => ctls.get(key),
  setCtl(key: string, c: UploadCtl): void { ctls.set(key, c) },
  delCtl(key: string): void { ctls.delete(key) },
}
