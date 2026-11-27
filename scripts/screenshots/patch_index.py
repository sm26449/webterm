# Capitolele + durata turului în index.html (en/ro), din site/assets/video/tour-chapters.json.
# Re-rulabil: înlocuieşte blocul <nav class="chapters"…> dacă există deja.
import json, re, subprocess, sys
SITE = '/home/stefanm/webterm/site'
dur = float(sys.argv[1])            # durata tour.mp4 (s)
ch = json.load(open(f'{SITE}/assets/video/tour-chapters.json'))
RO = {'Your fleet': 'Flota ta', 'Persistent sessions': 'Sesiuni persistente',
      'New session launcher': 'Lansatorul de sesiuni', 'Files': 'Fișiere', 'Split view': 'Ecrane împărțite',
      'Run on hosts': 'Rulare pe hosturi', 'Share link': 'Link de partajare', 'Settings search': 'Căutare în setări'}
mmss = lambda t: f'{int(t)//60}:{int(t)%60:02d}'
secs = round(dur)
for lang, path in [('en', f'{SITE}/index.html'), ('ro', f'{SITE}/ro/index.html')]:
    h = open(path).read()
    items = '\n'.join(
        f'            <li><button type="button" data-t="{c["t"]}"><time>{mmss(c["t"])}</time> {c["label"] if lang == "en" else RO[c["label"]]}</button></li>'
        for c in ch)
    aria = 'Tour chapters' if lang == 'en' else 'Capitolele turului'
    nav = (f'<nav class="chapters" data-chapters aria-label="{aria}">\n          <ol>\n{items}\n          </ol>\n        </nav>')
    if '<nav class="chapters"' in h:
        h = re.sub(r'<nav class="chapters".*?</nav>', nav, h, flags=re.S)
    else:
        # după .video-frame, în aceeaşi .window
        i = h.index('<div class="video-frame"')
        j = h.index('</div>\n', h.index('<span class="play-label"', i)) + len('</div>\n')
        h = h[:j] + '        ' + nav + '\n' + h[j:]
    if lang == 'en':
        h = re.sub(r'data-label="EverShell product tour, \d+ seconds"', f'data-label="EverShell product tour, {secs} seconds"', h)
        h = re.sub(r'aria-label="Play the \d+-second product tour"', f'aria-label="Play the {secs}-second product tour"', h)
        h = re.sub(r'Product tour · \d+:\d\d', f'Product tour · {mmss(secs)}', h)
    else:
        h = re.sub(r'data-label="Turul EverShell, \d+ de secunde"', f'data-label="Turul EverShell, {secs} de secunde"', h)
        h = re.sub(r'aria-label="Pornește turul de \d+ de secunde"', f'aria-label="Pornește turul de {secs} de secunde"', h)
        h = re.sub(r'Turul produsului · \d+:\d\d', f'Turul produsului · {mmss(secs)}', h)
    # 3.7.1: doar mp4 (H.264 merge peste tot); tour.webm nu mai e generat
    h = re.sub(r' data-webm="[^"]*tour\.webm"', '', h)
    open(path, 'w').write(h)
    print(path, 'ok')
