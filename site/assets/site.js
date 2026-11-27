// evershell.dev — meniul de pe telefon şi video-ul încărcat abia la click (fără trafic inutil).
(function () {
  var btn = document.querySelector('.menu-btn');
  var nav = document.getElementById('nav');
  if (btn && nav) {
    btn.addEventListener('click', function () {
      var open = nav.classList.toggle('open');
      btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && nav.classList.contains('open')) {
        nav.classList.remove('open'); btn.setAttribute('aria-expanded', 'false'); btn.focus();
      }
    });
  }

  var frame = document.querySelector('[data-video]');
  if (frame) {
    var play = frame.querySelector('.play');
    var video = null;
    // creează <video> abia la prima cerere (click pe Play sau pe un capitol): fără trafic inutil
    var start = function (at) {
      if (!video) {
        video = document.createElement('video');
        video.controls = true; video.playsInline = true; video.preload = 'auto';
        video.setAttribute('aria-label', frame.getAttribute('data-label') || 'Product tour');
        [['mp4', 'video/mp4'], ['webm', 'video/webm']].forEach(function (t) {
          var src = frame.getAttribute('data-' + t[0]);
          if (src) { var s = document.createElement('source'); s.src = src; s.type = t[1]; video.appendChild(s); }
        });
        var track = frame.getAttribute('data-vtt');
        if (track) {
          var tr = document.createElement('track');
          tr.kind = 'captions'; tr.src = track; tr.srclang = document.documentElement.lang; tr.label = 'Captions';
          video.appendChild(tr);
        }
        frame.innerHTML = '';
        frame.appendChild(video);
        video.addEventListener('timeupdate', markChapter);
      }
      if (at != null) {
        // înainte de metadata, currentTime nu se poate seta în toate browserele
        var seek = function () { video.currentTime = at; };
        if (video.readyState >= 1) seek(); else video.addEventListener('loadedmetadata', seek, { once: true });
      }
      video.play().catch(function () { /* autoplay refuzat: rămân controalele */ });
      return video;
    };
    play.addEventListener('click', function () { start(null).focus(); });

    // capitolele de sub video: butoane care sar la secunda lor; capitolul curent are aria-current
    var chapters = [].slice.call(document.querySelectorAll('[data-chapters] button[data-t]'));
    var markChapter = function () {
      if (!video) return;
      var cur = null;
      chapters.forEach(function (b) { if (video.currentTime + 0.25 >= parseFloat(b.getAttribute('data-t'))) cur = b; });
      chapters.forEach(function (b) {
        if (b === cur) b.setAttribute('aria-current', 'true'); else b.removeAttribute('aria-current');
      });
    };
    chapters.forEach(function (b) {
      b.addEventListener('click', function () {
        start(parseFloat(b.getAttribute('data-t')));
        frame.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      });
    });
  }
})();

// Captură mărită: capturile sunt la 2880 px, dar în coloană ajung la ~600 px. Un click le deschide
// într-un <dialog> la dimensiunea reală (Escape sau click oriunde închide). Fără JS rămân imagini simple.
(function () {
  var shots = document.querySelectorAll('.shot img');
  if (!shots.length || typeof HTMLDialogElement === 'undefined') return;
  var ro = document.documentElement.lang === 'ro';
  var dlg = document.createElement('dialog');
  dlg.className = 'zoom-dlg';
  dlg.innerHTML = '<button type="button" class="zoom-close" aria-label="' + (ro ? 'Închide' : 'Close') + '">×</button><img alt="">';
  document.body.appendChild(dlg);
  var big = dlg.querySelector('img');
  dlg.addEventListener('click', function () { dlg.close(); });
  shots.forEach(function (img) {
    var btn = document.createElement('button');
    btn.type = 'button'; btn.className = 'zoom-btn';
    btn.setAttribute('aria-label', (ro ? 'Mărește captura: ' : 'Enlarge screenshot: ') + img.alt);
    var pic = img.closest('picture') || img;
    pic.parentNode.insertBefore(btn, pic); btn.appendChild(pic);
    btn.addEventListener('click', function () {
      big.src = img.currentSrc || img.src; big.alt = img.alt;
      dlg.showModal();
    });
  });
})();

// Clipurile din tur: pornesc (mute, în buclă) doar cât sunt pe ecran. Cu prefers-reduced-motion nu
// pornesc singure: rămâne posterul cu un buton Play. Butonul de pauză există mereu (WCAG 2.2.2:
// orice mişcare de peste 5 s trebuie să poată fi oprită). Fără JS: posterul + controalele native.
(function () {
  var vids = document.querySelectorAll('video[data-clip]');
  if (!vids.length) return;
  var ro = document.documentElement.lang === 'ro';
  var still = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var icon = function (paused) {
    return paused
      ? '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M7 4.5v15l13-7.5z"/></svg>'
      : '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M6 4.5h4v15H6zM14 4.5h4v15h-4z"/></svg>';
  };
  var io = ('IntersectionObserver' in window) && !still ? new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      var v = e.target;
      if (v.getAttribute('data-user-paused') === '1') return;
      if (e.isIntersecting) v.play().catch(function () {}); else v.pause();
    });
  }, { threshold: 0.5 }) : null;
  [].forEach.call(vids, function (v) {
    v.removeAttribute('controls'); v.muted = true;
    var what = v.getAttribute('aria-label') || '';
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'clip-btn' + (still ? ' big' : '');
    var sync = function () {
      btn.innerHTML = icon(v.paused);
      btn.setAttribute('aria-label', (v.paused ? (ro ? 'Pornește clipul: ' : 'Play clip: ') : (ro ? 'Oprește clipul: ' : 'Pause clip: ')) + what);
      btn.classList.toggle('playing', !v.paused);
    };
    btn.addEventListener('click', function () {
      if (v.paused) { v.setAttribute('data-user-paused', '0'); v.play().catch(function () {}); }
      else { v.setAttribute('data-user-paused', '1'); v.pause(); }
    });
    v.addEventListener('play', sync); v.addEventListener('pause', sync);
    v.parentNode.appendChild(btn);
    sync();
    if (io) io.observe(v);
  });
})();
