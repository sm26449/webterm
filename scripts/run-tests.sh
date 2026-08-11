#!/bin/sh
# Setul de teste — SINGURA sursă de adevăr, folosită şi de CI (docker-publish.yml) şi de
# `make test`. Înainte, lista era duplicată: CI rula 22 de fişiere, `make test` doar 2, deci
# poarta locală era mult mai slabă decât cea din CI şi diverge tăcut la fiecare test nou.
#
# Grupuri (prerechizitele diferă, de-aia nu sunt toate în CI):
#   ci     — hermetice: fără agent real, tmux, sshd sau browser. Astea blochează publicarea.
#   local  — cer tmux + agentul REAL pe maşina ta. Izolate de producţie prin tests/tmux_sandbox.py.
#   stack  — cer un gateway deja pornit pe 127.0.0.1:8000 (nu le pornim noi).
#   root   — cer sudo + sshd local + useri efemeri (creează/şterge useri pe maşină).
#
# Utilizare: scripts/run-tests.sh [ci|local|all]     (PY=... ca să alegi interpretorul)
set -u   # NU `set -e`: run_group acumulează eşecurile şi epilogul de la final
         # trebuie să se tipărească şi când ceva a picat — altfel poarta ascunde
         # exact informaţia pentru care a fost scrisă (moare la grupul 16 din 40 şi taci).

cd "$(dirname "$0")/.."
PY="${PY:-python3}"
SUITE="${1:-ci}"

# Preflight pe interpretor şi dependenţe. `ci-local.sh` îl are de două runde, cu comentariul
# care descrie exact defectul — dar el e scriptul din spate, iar CONTRIBUTING trimite AICI
# (prin `make test`). Fără preflight, un contribuitor fără venv primea 43 de rânduri
# „timeout: failed to run command", iar unul cu venv incomplet primea 31 de
# `ModuleNotFoundError` amestecate printre 330 de PASS-uri — în ambele cazuri exit 1 şi
# niciun indiciu că problema e mediul, nu codul lui. Un raport roşu fals costă la fel de mult
# ca unul verde fals: prima dată te trimite să cauţi un bug inexistent, a doua oară nu te mai
# uiţi la el. Semnalat de un audit extern care a parcurs traseul primului contribuitor.
command -v "$PY" >/dev/null 2>&1 || [ -x "$PY" ] || {
  echo "Nu găsesc interpretorul '$PY'." >&2
  echo "  Rulează cu PY=/cale/către/python, sau creează venv-ul:" >&2
  echo "    python3 -m venv .venv && ./.venv/bin/pip install -r gateway/requirements.txt -r gateway/requirements-dev.txt" >&2
  exit 2
}
MISSING=$("$PY" - <<'PYEOF' 2>/dev/null || echo "?"
import importlib.util as u
print(" ".join(m for m in ("aiosqlite", "httpx", "fastapi", "cryptography")
                if u.find_spec(m) is None))
PYEOF
)
if [ -n "$MISSING" ]; then
  echo "'$PY' nu are dependenţele gateway-ului: $MISSING" >&2
  echo "  pip install -r gateway/requirements.txt -r gateway/requirements-dev.txt" >&2
  echo "  (sau rulează cu PY=/cale/către/.venv/bin/python)" >&2
  exit 2
fi

CI_TESTS="agent_hardening agent_reliability agent_tmux_hygiene ed25519_kat
          backup forward_validation idle_lock retention session_reconcile
          telnet telnet_bastion telnet_shim totp transcript_cap stepup signing
          agent_update_signing signing_api uninstall ws_keepalive agent_events
          audit_log cloud_backup transcript_text shell_integration tail_altscreen
          guardrail_alerts multi_account api_token update_check install_command upgrade_script
          reauth_secrets host_edit config_env compose_env forward_stepup session_attach_stepup
          audit_2026_07 i18n_catalog route_auth audit_reads agent_flood attach_alert account_confirm csrf_ratelimit"

# security_test e ultimul: îşi porneşte singur un uvicorn efemer şi verifică auth obligatoriu
# pe fs, CSWSH, lockout 429, headere, traversare, gating enroll/share — regresii pe care
# e2e-ul (calea fericită) nu le vede.
CI_LAST="security"

LOCAL_TESTS="integration_m1 agent_v3 account_tz file_transfer"

# rulate manual: `stack` cere un gateway pornit, `root` modifică useri de sistem
STACK_TESTS="instance_fence storm"
ROOT_TESTS="ssh provision"

: "${WEBTERM_DATA_DIR:=$(mktemp -d)}"
: "${WEBTERM_PUBLIC_URL:=http://127.0.0.1:8000}"
export WEBTERM_DATA_DIR WEBTERM_PUBLIC_URL

fail=0

# Un test care nu există trebuie să OPREASCĂ rularea, nu să fie descoperit peste luni.
# `integration_m1` a stat pe listă cu fişierul numit `integration_m1.py` (fără `_test`), deci
# nu s-a rulat NICIODATĂ: 23 de verificări moarte, iar grupurile `local` şi `all` erau rupte —
# dar nimeni nu le rulează zilnic, aşa că eroarea a trecut neobservată. Verificăm ÎNAINTE de
# prima rulare, ca lista să nu poată diverge tăcut de fişiere.
check_exists() {
    missing=""
    for t in $1; do
        [ -f "tests/${t}_test.py" ] || missing="$missing tests/${t}_test.py"
    done
    if [ -n "$missing" ]; then
        echo "ERROR: tests listed but missing:$missing" >&2
        echo "(rename the file to <name>_test.py, or drop it from the list)" >&2
        exit 2
    fi
}

# Şi direcţia INVERSĂ, care lipsea: un fişier `tests/*_test.py` care nu e pe nicio listă
# nu rulează niciodată şi nimeni nu află. Un contribuitor scrie un test (checklist-ul de PR
# i-o cere), CI e verde, testul lui n-a fost atins. E acelaşi defect ca cel de mai sus, doar
# pe cealaltă direcţie.
check_orphans() {
    orphans=""
    # listele sunt scrise pe mai multe rânduri, deci conţin newline-uri: fără normalizare,
    # numele de la capăt de rând nu se potriveau cu tiparul „ nume " şi apăreau ca orfane.
    all_listed=" $(echo $CI_TESTS $CI_LAST $LOCAL_TESTS $STACK_TESTS $ROOT_TESTS) "
    for f in tests/*_test.py; do
        n=$(basename "$f" _test.py)
        case "$all_listed" in *" $n "*) ;; *) orphans="$orphans $f" ;; esac
    done
    if [ -n "$orphans" ]; then
        echo "ERROR: test files that no list runs:$orphans" >&2
        echo "(add them to a list in this file, or delete them)" >&2
        exit 2
    fi
}

# Un test care ATÂRNĂ nu e o poartă, e o pierdere de timp: firul aiosqlite e non-daemon, deci
# orice excepţie dinaintea lui `db.close()` ţine procesul viu la infinit. Fără termen, jobul din
# CI merge până la limita de 6h a GitHub, iar local suita pare pur şi simplu blocată. Reparaţia
# per-fişier (`try/finally`) a fost aplicată în câteva teste şi nu se poate generaliza prin
# disciplină — deci o punem aici, unde acoperă şi testele care încă n-au primit-o.
TEST_TIMEOUT="${TEST_TIMEOUT:-420}"

run_group() {
    check_exists "$1"
    for t in $1; do
        echo "──────── $t ────────"
        if command -v timeout >/dev/null 2>&1; then
            # `|| true` era necesar cât timp exista `set -e`. Scoaterea lui `set -e` a lăsat
            # `|| true` pe loc — iar `$?` devenea al lui `true`, adică MEREU 0. Rezultat:
            # `fail=1` de mai jos nu se executa niciodată, detecţia de test blocat (rc=124)
            # era moartă, iar suita ieşea cu 0 oricâte teste picau. Poarta pe care se sprijină
            # tot restul nu putea să cadă. Fără `set -e`, comanda poate eşua fără să oprească
            # scriptul, deci `|| true` nu mai are niciun rol.
            timeout -k 10 "$TEST_TIMEOUT" "$PY" "tests/${t}_test.py"
            rc=$?
            [ "$rc" = 124 ] && echo "  FAILED: $t exceeded ${TEST_TIMEOUT}s (hung?) — check the aiosqlite thread" >&2
        else
            "$PY" "tests/${t}_test.py"
            rc=$?
        fi
        [ "$rc" = 0 ] || fail=1
    done
}

check_orphans

case "$SUITE" in
    ci)    run_group "$CI_TESTS $CI_LAST" ;;
    local) run_group "$LOCAL_TESTS" ;;
    all)   run_group "$CI_TESTS $CI_LAST $LOCAL_TESTS" ;;
    *)     echo "usage: $0 [ci|local|all]" >&2; exit 2 ;;
esac

# no silent caps: say what did NOT run, and why
echo ""
case "$SUITE" in
    ci) echo "Not run (need tmux / a real agent): $LOCAL_TESTS" ;;
esac
echo "Not run (need a gateway running on :8000): $STACK_TESTS"
echo "Not run (need sudo + sshd + ephemeral users): $ROOT_TESTS"

exit $fail
