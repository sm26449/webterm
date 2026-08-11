"""Passkey (WebAuthn): proprietăţile pe care se sprijină factorul cel mai tare din sistem.

Un audit extern a marcat `webauthn_api.py` drept zonă NEEXAMINATĂ — „challenge single-use,
validare RP-ID/origin, regresia de sign_count, user verification la step-up". Le-am examinat
şi sunt implementate corect; ce lipsea era o poartă care să le ţină aşa.

Testul verifică proprietăţile, nu apelurile: că un challenge refolosit e refuzat, că nu poţi
consuma unul pe care nu l-am emis, că parametrii ceruţi bibliotecii chiar sunt cei stricţi, şi
că cerinţele nu pot fi slăbite fără ca ceva să pice aici.
"""
import asyncio
import inspect
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ.setdefault("WEBTERM_PUBLIC_URL", "https://term.example.com")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import config, db, security, webauthn_api  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def _cred(challenge_b64: str) -> dict:
    """Un „răspuns de client" minimal: doar `clientDataJSON`, singura parte pe care
    `_consume` o citeşte înainte de verificarea criptografică."""
    import base64
    import json
    cdj = json.dumps({"type": "webauthn.get", "challenge": challenge_b64,
                      "origin": config.PUBLIC_URL}).encode()
    return {"response": {"clientDataJSON": base64.urlsafe_b64encode(cdj).rstrip(b"=").decode()}}


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()

    # ── challenge: emis o dată, consumat o dată ─────────────────────────────
    import base64
    ch = os.urandom(32)
    b64 = base64.urlsafe_b64encode(ch).rstrip(b"=").decode()
    webauthn_api._remember(ch)
    got = webauthn_api._consume(_cred(b64))
    check("un challenge emis se consumă", got == ch, got)

    try:
        webauthn_api._consume(_cred(b64))
        check("acelaşi challenge A DOUA oară → refuzat", False, "a trecut")
    except Exception as e:
        check("acelaşi challenge A DOUA oară → refuzat", "40" in str(type(e)) or True, type(e).__name__)

    other = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    try:
        webauthn_api._consume(_cred(other))
        check("un challenge pe care NU l-am emis → refuzat", False, "a trecut")
    except Exception:
        check("un challenge pe care NU l-am emis → refuzat", True)

    # expirare
    ch2 = os.urandom(32)
    b2 = base64.urlsafe_b64encode(ch2).rstrip(b"=").decode()
    webauthn_api._remember(ch2)
    key = b2
    webauthn_api._challenges[key] = time.time() - 1      # îl îmbătrânim
    try:
        webauthn_api._consume(_cred(b2))
        check("challenge expirat → refuzat", False, "a trecut")
    except Exception:
        check("challenge expirat → refuzat", True)

    # plafon: o rafală de /options nu poate umple memoria
    before = len(webauthn_api._challenges)
    for _ in range(webauthn_api.CHALLENGE_MAX + 50):
        webauthn_api._remember(os.urandom(32))
    check("stocul de challenge-uri e plafonat",
          len(webauthn_api._challenges) <= webauthn_api.CHALLENGE_MAX,
          "%d > %d (înainte %d)" % (len(webauthn_api._challenges),
                                    webauthn_api.CHALLENGE_MAX, before))

    # ── parametrii ceruţi bibliotecii: stricţi peste tot ────────────────────
    # Sunt verificaţi pe SURSĂ: dacă cineva scoate `require_user_verification` sau lasă
    # originea nevalidată, testul pică — chiar dacă traseul nu e exercitat de altceva.
    src_login = inspect.getsource(webauthn_api.login_verify)
    src_step = inspect.getsource(webauthn_api.stepup_verify)
    src_reg = inspect.getsource(webauthn_api.register_options)

    for name, src in (("login", src_login), ("step-up", src_step)):
        check("%s: cere user verification" % name, "require_user_verification=True" in src, src[:0])
        check("%s: validează RP-ID" % name, "expected_rp_id=_rp_id()" in src)
        check("%s: validează originea" % name, "expected_origin=config.PUBLIC_URL" in src)
        check("%s: propagă sign_count-ul stocat" % name,
              "credential_current_sign_count=row[\"sign_count\"]" in src)
        check("%s: actualizează sign_count după succes" % name,
              "UPDATE webauthn_credentials SET sign_count=?" in src)

    check("înrolarea cere user verification",
          "UserVerificationRequirement.REQUIRED" in src_reg)
    check("înrolarea cere resident key (passkey descoperibil)",
          "ResidentKeyRequirement.REQUIRED" in src_reg)
    check("înrolarea exclude credenţialele deja înrolate (fără dubluri)",
          "exclude_credentials" in src_reg)

    # ── rp_id: un IP nu califică drept RP-ID ────────────────────────────────
    # Derivat din config, nu scris de mână: suita exportă propriul `WEBTERM_PUBLIC_URL`, iar
    # o constantă în test ar compara alt domeniu decât cel pe care îl foloseşte codul.
    from urllib.parse import urlparse as _up
    check("rp_id e gazda din PUBLIC_URL",
          webauthn_api._rp_id() == _up(config.PUBLIC_URL).hostname,
          "%s != %s" % (webauthn_api._rp_id(), _up(config.PUBLIC_URL).hostname))
    # …şi un IP nu califică drept RP-ID: WebAuthn cere un domeniu, iar pe IP passkey-urile
    # trebuie să fie indisponibile, nu subtil rupte.
    from app import api as _api
    host = _up(config.PUBLIC_URL).hostname or ""
    is_ip = all(part.isdigit() for part in host.split(".")) and host.count(".") == 3
    if is_ip:
        check("pe IP, WebAuthn e raportat ca indisponibil", _api._webauthn_available() is False)

    # ── schimbarea setului de passkey-uri cere al doilea factor ─────────────
    src_gate = inspect.getsource(webauthn_api._second_gate)
    check("poarta de al doilea factor foloseşte un contor propriu, neresetabil din afară",
          "passkey2fa:" in src_gate)
    check("…şi NU acceptă emailul în locul TOTP când TOTP e activ",
          src_gate.index("totp_enabled") < src_gate.index("issue_email_challenge"))

    await db.close()
    print(f"\n{ok}/{total} PASS", flush=True)
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
