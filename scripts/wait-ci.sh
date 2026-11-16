#!/usr/bin/env bash
# Aşteaptă rulările GitHub Actions ale unui commit şi spune rezultatul.
#   scripts/wait-ci.sh [ref]        ref = sha, tag sau branch (implicit HEAD)
#   WAIT_MIN=60 POLL=60 MIN_RUNS=1  (minute de aşteptat, secunde între interogări, câte rulări)
# Exit 0 = toate rulările terminate cu success/skipped; 1 = cel puţin una picată/anulată;
# 2 = timeout sau API indisponibil. Rulările programate (event=schedule, ex. Security scan
# weekly) pe acelaşi sha intră şi ele: un eşec acolo e real, dar nu ţine de push. Ultima linie e stabilă, pentru grep:
#   CI-WAIT sha=<sha> runs=N failed=K: <nume rulări picate>
# De ce: fiecare sesiune scria de mână o buclă curl de 90 de iteraţii (sau `sleep; tail`,
# blocat de harness); aici e una singură. Repo public: API-ul nu cere token (fără `gh`).
# Pentru un tag: Publish image (~30 min) + Release notes pornesc pe ACELAŞI sha ca push-ul pe
# main — cu MIN_RUNS=4 aştepţi să apară şi rulările tag-ului, nu doar cele de pe main.
cd "$(dirname "$0")/.." || exit 2
REPO_SLUG="${REPO_SLUG:-sm26449/webterm}"
REF="${1:-HEAD}"
SHA=$(git rev-parse "$REF^{commit}" 2>/dev/null) || { echo "ref necunoscut: $REF" >&2; exit 2; }
WAIT_MIN="${WAIT_MIN:-60}"; POLL="${POLL:-60}"; MIN_RUNS="${MIN_RUNS:-1}"
URL="https://api.github.com/repos/$REPO_SLUG/actions/runs?head_sha=$SHA&per_page=30"
deadline=$(( $(date +%s) + WAIT_MIN * 60 ))
J=""
while :; do
  J=$(curl -fsS --max-time 20 "$URL" 2>/dev/null) || J=""
  if [ -n "$J" ]; then
    S=$(printf '%s' "$J" | python3 -c 'import json,sys
r=json.load(sys.stdin)["workflow_runs"]
print(len(r), sum(x["status"]!="completed" for x in r))' 2>/dev/null)
    set -- $S
    if [ "${1:-0}" -ge "$MIN_RUNS" ] && [ "${2:-1}" = 0 ]; then break; fi
    echo "$(date +%H:%M) runs=${1:-?} pending=${2:-?}"
  else
    echo "$(date +%H:%M) API GitHub indisponibil, reîncerc"
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "CI-WAIT sha=${SHA:0:7} timeout după ${WAIT_MIN} min"; exit 2
  fi
  sleep "$POLL"
done
printf '%s' "$J" | SHA="${SHA:0:7}" python3 -c 'import json,os,sys
r=json.load(sys.stdin)["workflow_runs"]
bad=[]
for x in sorted(r,key=lambda x:x["name"]):
    c=x["conclusion"] or "?"
    print("  %-8s %-28s %-8s %-8s %s" % (c, x["name"], x["head_branch"], x["event"], x["html_url"]))
    if c not in ("success","skipped","neutral"): bad.append("%s(%s,%s)" % (x["name"], x["head_branch"], x["event"]))
print("CI-WAIT sha=%s runs=%d failed=%d: %s" % (os.environ["SHA"], len(r), len(bad), " ".join(bad)))
sys.exit(1 if bad else 0)'
