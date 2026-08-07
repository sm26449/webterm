"""Faza 2 — cablarea cheii de deployment pe calea de update (core.py).

Verifică `agent_install_source()` (GET /agent/ptyd.py) și `_agent_update_payload()`
(push-ul de update): fallback la canalul oficial fără cheie; substituție+semnătură cu cheie
deblocată (acceptată de verificatorul agentului); pauză la cheie blocată; și CONSISTENȚA
install↔update (agentul instalat trebuie să aibă exact octeții pe care-i vom semna la update).
"""
import base64
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://127.0.0.1:8000")
_here = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_here, "..", "gateway"))
sys.path.insert(0, os.path.join(_here, "..", "agent"))

from app import core, signing  # noqa: E402
import ptyd  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def main():
    exp = core.agent_expected()          # citește ptyd.py real + .sig din repo
    assert exp.get("source"), "agent source lipsă (rulează din repo)"

    # 1) FĂRĂ cheie de deployment → canalul oficial (sursă brută + semnătura mentainerului)
    check("fără cheie: install source = sursa brută", core.agent_install_source() == exp["source"])
    p0 = core._agent_update_payload(exp)
    check("fără cheie: payload = fallback (semnătura repo)",
          p0 is not None and p0[1] == exp["sig"] and base64.b64decode(p0[0]) == exp["source"].encode())

    # 2) generează cheie de deployment (deblocată imediat)
    pub = signing.generate()
    src_sub = core.agent_install_source()
    check("cu cheie: install source SUBSTITUIT", src_sub != exp["source"] and pub in src_sub)
    check("cu cheie: AGENT_VERSION neatins (anti-rollback)",
          ptyd._content_version(src_sub.encode()) == ptyd.AGENT_VERSION)

    p1 = core._agent_update_payload(exp)
    check("cu cheie deblocată: payload semnat generat", p1 is not None)
    content = base64.b64decode(p1[0])
    sig = base64.b64decode(p1[1])
    check("agentul ACCEPTĂ update-ul substituit+semnat cu cheia de deployment",
          ptyd.ed25519_verify(bytes.fromhex(pub), sig, content))

    # *** CONSISTENȚĂ *** install ↔ update: agentul instalat are EXACT octeții pe care-i semnăm
    check("consistență: octeții de install == octeții de update (același pubkey)",
          src_sub.encode() == content)

    # 3) cheie BLOCATĂ → payload None (auto-update pauzat), dar install încă merge (înrolare nouă)
    signing.lock()
    check("cheie blocată: payload None (auto-update pauzat)", core._agent_update_payload(exp) is None)
    check("cheie blocată: install source încă substituit (înrolarea merge)",
          core.agent_install_source() != exp["source"] and pub in core.agent_install_source())

    print(f"\n{ok}/{total} teste trecute")
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
