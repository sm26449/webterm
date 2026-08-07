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
set -eu

cd "$(dirname "$0")/.."
PY="${PY:-python3}"
SUITE="${1:-ci}"

CI_TESTS="agent_hardening agent_reliability agent_tmux_hygiene ed25519_kat
          backup forward_validation idle_lock retention session_reconcile
          telnet telnet_bastion telnet_shim totp transcript_cap stepup signing
          agent_update_signing signing_api uninstall ws_keepalive agent_events
          audit_log cloud_backup transcript_text shell_integration tail_altscreen
          guardrail_alerts multi_account api_token update_check install_command upgrade_script
          reauth_secrets host_edit config_env compose_env forward_stepup session_attach_stepup
          audit_2026_07"

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
