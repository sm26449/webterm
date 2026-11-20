#!/bin/sh
# Pornim ca root doar cât să ne asigurăm că /data (volume, posibil creat de o
# versiune veche care rula ca root) aparține user-ului neprivilegiat, apoi
# coborâm privilegiile și rulăm aplicația ca `webterm`.
set -e
chown -R webterm:webterm /data 2>/dev/null || true
# 3.6.38: volumul cu listele allow/deny pentru Traefik (edgelists.py), dacă e montat
[ -d /edge ] && chown webterm:webterm /edge 2>/dev/null || true
exec gosu webterm "$@"
