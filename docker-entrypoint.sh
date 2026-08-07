#!/bin/sh
# Pornim ca root doar cât să ne asigurăm că /data (volume, posibil creat de o
# versiune veche care rula ca root) aparține user-ului neprivilegiat, apoi
# coborâm privilegiile și rulăm aplicația ca `webterm`.
set -e
chown -R webterm:webterm /data 2>/dev/null || true
exec gosu webterm "$@"
