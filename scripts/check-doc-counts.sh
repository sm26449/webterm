#!/usr/bin/env bash
# Numerele din documentaţie ↔ realitate: suitele din CONTRIBUTING.md şi verificările e2e din
# README.md. O SINGURĂ sursă pentru CI (`unit-tests`) şi pentru `ci-local.sh unit`: înainte,
# comenzile erau doar în workflow, local nu le rula nimic, iar un număr uitat se vedea abia în
# CI (job roşu → nicio imagine). Exit 0 = ok, 1 = nepotrivire (cu numărul corect afişat).
cd "$(dirname "$0")/.." || exit 2
rc=0
# + 1 = CI_LAST (security), rulat după CI_TESTS
N=$(awk '/^CI_TESTS="/{f=1} f{print} f&&/"[[:space:]]*$/{exit}' scripts/run-tests.sh \
    | sed 's/CI_TESTS=//' | tr -d '"' | wc -w)
N=$((N + 1))
if grep -q "unit-tests\` job — $N suites" CONTRIBUTING.md; then
  echo "doc counts: CONTRIBUTING.md suites = $N"
else
  echo "CONTRIBUTING.md says a different number of suites than run-tests.sh ($N)"; rc=1
fi
# doar liniile care ÎNCEP cu check( (un grep -c 'check(' simplu dă mai mult)
E=$(grep -c '^\s*check(' scripts/e2e-session.mjs)
if grep -q "e2e-session.mjs\`, $E checks" README.md; then
  echo "doc counts: README.md e2e checks = $E"
else
  echo "README.md says a different number of e2e checks than the script ($E)"; rc=1
fi
exit $rc
