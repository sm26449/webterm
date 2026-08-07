// Plasă de siguranță ÎN AFARA bundle-ului React (post-mortem v1.0.11, unde un
// crash de hook-uri lăsa doar un ecran alb, fără nicio ieșire): dacă aplicația
// nu ajunge să pornească — eroare JS la boot, bundle corupt, stare locală
// otrăvită — arătăm o pagină statică cu diagnosticul și ieșirile de urgență.
// Script clasic, fără dependențe și fără build: trebuie să funcționeze exact
// atunci când restul nu o face. Fișier separat (nu inline) din cauza CSP
// (script-src 'self'); tot din CSP, butoanele se leagă cu addEventListener,
// nu cu onclick inline.
(function () {
  'use strict'
  var shown = false
  var errors = []

  function esc(s) {
    return String(s).replace(/[<>&]/g, function (c) {
      return { '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c]
    })
  }

  function show(reason) {
    if (shown || !document.body) return
    shown = true
    var host = document.createElement('div')
    host.id = 'wt-failsafe'
    // stiluri doar inline: CSS-ul aplicației poate fi el însuși stricat/absent
    host.style.cssText =
      'position:fixed;inset:0;z-index:2147483647;background:#0b0e14;color:#cbd5e1;' +
      'font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow:auto;padding:24px'
    host.innerHTML =
      '<div style="max-width:640px;margin:0 auto">' +
      '<h1 style="font-size:18px;color:#f8fafc;margin:0 0 4px">WebTerm nu a pornit</h1>' +
      '<p style="margin:0 0 16px;color:#94a3b8">' + esc(reason) + '</p>' +
      (errors.length
        ? '<pre style="background:#111827;border:1px solid #1f2937;border-radius:8px;padding:12px;' +
          'white-space:pre-wrap;word-break:break-word;color:#fca5a5;margin:0 0 16px">' +
          esc(errors.slice(0, 5).join('\n')) + '</pre>'
        : '') +
      '<div style="display:flex;gap:8px;flex-wrap:wrap;margin:0 0 20px">' +
      '<button id="wt-fs-reload" style="background:#0ea5e9;color:#fff;border:0;border-radius:8px;' +
      'padding:10px 16px;font:inherit;cursor:pointer">Reîncarcă</button>' +
      '<button id="wt-fs-reset" style="background:#1e293b;color:#cbd5e1;border:1px solid #334155;' +
      'border-radius:8px;padding:10px 16px;font:inherit;cursor:pointer">Resetează starea locală și reîncarcă</button>' +
      '</div>' +
      '<div style="background:#111827;border:1px solid #1f2937;border-radius:8px;padding:12px;color:#94a3b8">' +
      'Dacă asta a apărut imediat după un update de versiune, întoarce serverul la versiunea anterioară ' +
      '(prin SSH, nu prin WebTerm):' +
      '<pre style="margin:8px 0 0;color:#e2e8f0">cd /opt/webterm &amp;&amp; sudo ./rollback.sh</pre>' +
      'Sesiunile de terminal NU se pierd: ele trăiesc în tmux pe host-uri ' +
      '(<code>tmux -L webterm attach</code>). Detalii: docs/RUNBOOK.md în repo.' +
      '</div></div>'
    document.body.appendChild(host)
    document.getElementById('wt-fs-reload').addEventListener('click', function () {
      window.location.reload()
    })
    document.getElementById('wt-fs-reset').addEventListener('click', function () {
      try { window.localStorage.clear() } catch (e) { /* privat/blochat */ }
      try { window.sessionStorage.clear() } catch (e) { /* idem */ }
      window.location.reload()
    })
  }

  window.addEventListener('error', function (e) {
    errors.push((e && e.message) || 'eroare necunoscută')
    // după boot, erorile de randare sunt tratate de ErrorBoundary (care apelează
    // __wtFailsafe explicit); aici prindem doar moartea înainte de pornire
    if (!window.__WT_BOOTED) show('O eroare JavaScript a oprit pornirea aplicației.')
  })
  window.addEventListener('unhandledrejection', function (e) {
    var r = e && e.reason
    // doar diagnostic: o promisiune respinsă singură nu e fatală (ex. un fetch
    // eșuat la reconectare) — nu declanșăm failsafe-ul pentru ea
    errors.push('promise: ' + ((r && r.message) || String(r)))
  })
  // apelat de ErrorBoundary-ul React pentru crash-uri de după boot
  window.__wtFailsafe = function (msg) {
    if (msg) errors.push(String(msg))
    show('Aplicația a întâmpinat o eroare fatală.')
  }
  // plasă finală: nici eroare, nici boot — ex. bundle care nu se mai încarcă
  setTimeout(function () {
    if (!window.__WT_BOOTED) show('Aplicația nu a pornit în 20 de secunde.')
  }, 20000)
})()
