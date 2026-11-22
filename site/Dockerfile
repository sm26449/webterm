# evershell.dev — site static într-un nginx neprivilegiat (portul 8080), în spatele Traefik-ului
# de pe VM-ul site-urilor (acelaşi cu klopot.dev şi multibus.dev). Fără pas de build: HTML/CSS scris de mână.
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY deploy/security-headers.conf /etc/nginx/security-headers.conf
COPY *.html robots.txt sitemap.xml /usr/share/nginx/html/
COPY ro/ /usr/share/nginx/html/ro/
COPY assets/ /usr/share/nginx/html/assets/
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
