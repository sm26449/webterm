#!/usr/bin/env python3
"""Print the route → permission matrix as the CODE declares it (`authz.route_perms`).

The design document's Appendix A (docs/design/ROLES-AND-SSH.md) is the human-written matrix;
`tests/route_auth_test.py` fails CI when the two disagree. This script shows the code's side, for
reviewing a change or regenerating rows:

    python3 scripts/route-matrix.py            # markdown table
    python3 scripts/route-matrix.py --counts   # just the totals
"""
import os
import sys
import tempfile

os.environ.setdefault("WEBTERM_DATA_DIR", tempfile.mkdtemp())
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "gateway"))

from app import api, authz, oidc_api, webauthn_api  # noqa: E402


def main() -> int:
    rp = authz.route_perms([api.router, webauthn_api.router, oidc_api.router])
    if "--counts" in sys.argv:
        kinds = {}
        for kind, spec in rp.values():
            k = spec.kind if kind == "perm" else kind
            kinds[k] = kinds.get(k, 0) + 1
        print("routes:", len(rp), " ".join("%s=%d" % kv for kv in sorted(kinds.items())))
        return 0
    print("| Route | Method | Perm | Scope | Tok |")
    print("|---|---|---|---|---|")
    for (method, path), (kind, spec) in sorted(rp.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        if kind == "perm":
            perm = " ∪ ".join("`%s`" % p for p in spec.perm)
            scope = {"G": "G", "L": "L"}.get(spec.kind) or "H(%s)" % (spec.host or "")
            tok = spec.tokens or ""
        else:
            perm, scope, tok = "—", {"public": "P", "self": "S"}.get(kind, "?"), ""
        print("| `%s` | %s | %s | %s | %s |" % (path, method, perm, scope, tok))
    return 0


if __name__ == "__main__":
    sys.exit(main())
