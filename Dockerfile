# ---- frontend build ----
# Imagini de bază pinuite pe DIGEST (nu doar tag mutabil) — consecvent cu SHA-pinning-ul
# acțiunilor GitHub: un rebuild trage exact același strat de bază. Dependabot (ecosistemul
# docker) reîmprospătează digest-ul la un tag nou.
FROM node:26-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019 AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build

# ---- runtime ----
FROM python:3.14-slim@sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6
WORKDIR /srv/webterm

# gosu pentru coborârea privilegiilor din entrypoint; user neprivilegiat dedicat
RUN apt-get update && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /srv/webterm --shell /usr/sbin/nologin webterm

# supply-chain: instalăm din lockfile-ul cu hash-uri (--require-hashes). Orice
# wheel al cărui conținut nu se potrivește cu hash-ul pinuit oprește build-ul,
# blocând un pachet substituit în tranzit sau un mirror compromis.
COPY gateway/requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY gateway/app ./gateway/app
# `.signer` declară cu CE cheie e făcută semnătura — la o rotaţie diferă de cea din ptyd.py.
# Nu e nevoie la rulare (agentul verifică cu cheia lui), dar fără el imaginea desfăşurată nu
# poate fi auditată fără repo: „a cui e semnătura asta?" rămânea fără răspuns pe server.
COPY agent/ptyd.py agent/ptyd.py.sig agent/ptyd.py.signer agent/shell-integration.sh ./agent/
COPY --from=frontend /build/dist ./frontend/dist
# CHANGELOG-ul, servit în UI (/api/changelog → About → „Ce e nou"). E în imagine, deci
# funcţionează şi într-un deployment fără acces la GitHub.
COPY CHANGELOG.md ./
# Trusa de deploy: fişierele care rulează pe HOST, nu în container. Le ducem în imagine
# ca `upgrade.sh` să le poată sincroniza din artefactul pe care oricum îl tragi şi îl
# autentifici. Fără asta, /opt/webterm rămâne îngheţat la ce a pus installer-ul: pe
# 2026-08-06 am găsit acolo un backup.sh vechi de 76 de linii, care scria arhivele în clar.
COPY docker-compose.prod.yml deploy.sh rollback.sh upgrade.sh remove.sh .env.prod.example ./deploy-kit/
COPY scripts/backup.sh scripts/restore.sh scripts/cert-check.sh ./deploy-kit/scripts/
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV WEBTERM_DATA_DIR=/data \
    WEBTERM_AGENT_FILE=/srv/webterm/agent/ptyd.py \
    PYTHONPATH=/srv/webterm/gateway \
    PYTHONDONTWRITEBYTECODE=1

RUN mkdir -p /data && chown -R webterm:webterm /data /srv/webterm
VOLUME /data
EXPOSE 8000

# repornire de către orchestrator dacă appul se blochează (nu doar dacă crapă)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=3).status==200 else 1)"

# entrypoint corectează permisiunile pe /data și coboară la user-ul `webterm`;
# FĂRĂ --proxy-headers: aplicaţia îşi parsează SINGURĂ X-Forwarded-For (security.client_ip),
# fail-closed pe numărul de hop-uri şi doar de la un peer de încredere. Cu `--proxy-headers
# --forwarded-allow-ips "*"`, uvicorn înlocuia `request.client.host` cu PRIMA intrare din XFF
# — adică exact valoarea scrisă de client — deci garda `_peer_is_trusted` nu putea eşua
# niciodată şi întreaga apărare era inertă. Verificat pe uvicorn 0.50: `_TrustedHosts("*")`
# întoarce prima intrare, nu peer-ul socketului. Cele două straturi se anulau reciproc.
# `WEBTERM_FORWARDED_ALLOW_IPS` a fost ŞTERS de aici: era pasat lui uvicorn ca
# `--forwarded-allow-ips`, iar când `--proxy-headers` a dispărut (mai sus) variabila a rămas
# orfană — citită de nimeni, dar cu cinci rânduri de comentariu care sfătuiau operatorul s-o
# strângă „ca un container vecin să nu falsifice IP-ul clientului". Cine urma sfatul nu obţinea
# NIMIC. Butonul real e `WEBTERM_TRUSTED_PROXY_CIDRS` (vezi `config.py`), care chiar e citit:
# lista de proxy-uri de la care acceptăm `X-Forwarded-For`; gol = doar peer-i privaţi/loopback.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
# --no-access-log: tokenurile de enroll, share şi forward călătoresc în CALEA cererii
# (`/install/<token>.sh`, `/s/<token>`, `/__wtfwd/set?t=…`). `audit.py` taie intenţionat
# query-string-ul exact din motivul ăsta, dar uvicorn scria linia întreagă pe stdout, deci
# secretele ajungeau în `docker logs` şi în orice colector de loguri. Auditul rămâne sursa
# de adevăr pentru „cine ce a făcut"; access-log-ul doar dubla informaţia, cu secrete.
# UN SINGUR worker, şi asta e un INVARIANT, nu o alegere de performanţă. Plafoanele de
# lockout, challenge-urile WebAuthn şi ferestrele de step-up trăiesc în dicţionare per-proces.
# Cu `--workers N`, lockout-ul devine de N ori mai slab (fiecare proces îşi ţine propriul
# contor) şi step-up-ul se rupe intermitent, după cum nimereşti procesul. Dacă vrei vreodată
# mai mulţi workeri, starea aia trebuie mutată întâi într-un depozit partajat.
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port 8000 \
     --ws-per-message-deflate false --no-access-log \
     "]
