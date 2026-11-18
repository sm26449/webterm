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
    A, B = 1001, 1002                  # două conturi
    W = webauthn_api

    def b64(c):
        return base64.urlsafe_b64encode(c).rstrip(b"=").decode()

    def refused(fn, *args):
        try:
            fn(*args)
            return False
        except Exception:
            return True

    ch = os.urandom(32)
    W._remember(ch, A)
    got = W._consume(_cred(b64(ch)), A)
    check("un challenge emis se consumă", got == ch, got)
    check("acelaşi challenge A DOUA oară → refuzat", refused(W._consume, _cred(b64(ch)), A))
    check("un challenge pe care NU l-am emis → refuzat",
          refused(W._consume, _cred(b64(os.urandom(32))), A))

    # expirare
    ch2 = os.urandom(32)
    W._remember(ch2, A)
    W._challenges[b64(ch2)] = (time.time() - 1, A)      # îl îmbătrânim
    check("challenge expirat → refuzat", refused(W._consume, _cred(b64(ch2)), A))

    # ── legat de cont: challenge-ul lui A nu e bun pentru B, şi B nu i-l poate arde ──
    ch3 = os.urandom(32)
    W._remember(ch3, A)
    check("challenge-ul contului A, prezentat de B → refuzat",
          refused(W._consume, _cred(b64(ch3)), B))
    check("…şi încercarea lui B NU l-a scos din coadă", b64(ch3) in W._challenges)
    check("A îl consumă în continuare", W._consume(_cred(b64(ch3)), A) == ch3)

    # cozile nu se amestecă: login nu primeşte un challenge de step-up, step-up nu primeşte unul de login
    ch4 = os.urandom(32)
    W._remember(ch4, A)
    check("login cu un challenge din coada autentificată → refuzat",
          refused(W._consume_anon, _cred(b64(ch4))))
    ch5 = os.urandom(32)
    W._remember_anon(ch5)
    check("step-up cu un challenge de login → refuzat", refused(W._consume, _cred(b64(ch5)), A))
    check("login îşi consumă propriul challenge", W._consume_anon(_cred(b64(ch5))) == ch5)

    # ── DoS între conturi (audit 2026-11): B face flood pe /stepup/options ──────
    W._challenges.clear()
    victim = os.urandom(32)
    W._remember(victim, A)
    for _ in range(W.CHALLENGE_MAX * 2):
        W._remember(os.urandom(32), B)
    check("flood-ul lui B nu evacuează challenge-ul lui A", b64(victim) in W._challenges)
    check("B e ţinut la plafonul per cont",
          sum(1 for _, u in W._challenges.values() if u == B) <= W.CHALLENGE_PER_USER_MAX)

    # multe conturi ostile, fiecare la plafon: tot nu ating challenge-ul unic al victimei. Limita
    # e exactă: CHALLENGE_MAX conturi active (victima inclusă) încap câte unul; peste atât, cineva
    # tot trebuie să piardă un loc — memoria rămâne plafonată, iar asta cere sute de conturi.
    W._challenges.clear()
    W._remember(victim, A)
    for uid in range(5000, 5000 + W.CHALLENGE_MAX - 1):
        for _ in range(W.CHALLENGE_PER_USER_MAX):
            W._remember(os.urandom(32), uid)
    check("stocul autentificat e plafonat global", len(W._challenges) <= W.CHALLENGE_MAX,
          len(W._challenges))
    check("conturi ostile multe: challenge-ul unic al victimei rămâne", b64(victim) in W._challenges)
    check("victima îl consumă după flood", W._consume(_cred(b64(victim)), A) == victim)

    # victima cu DOUĂ challenge-uri (două taburi): conturile ostile cu tot atâtea, venite după ea,
    # nu-i scot nici pe cel vechi — la egalitate cedează ultimul venit, nu primul din coadă
    W._challenges.clear()
    old, new = os.urandom(32), os.urandom(32)
    W._remember(old, A)
    W._remember(new, A)
    for uid in range(7000, 7000 + (W.CHALLENGE_MAX - 2) // 2):
        W._remember(os.urandom(32), uid)
        W._remember(os.urandom(32), uid)
    for uid in range(8000, 8010):                       # conturi proaspete, câte unul
        W._remember(os.urandom(32), uid)
    check("victimă cu 2 challenge-uri: nici cel vechi nu e evacuat", b64(old) in W._challenges)
    check("…nici cel nou", b64(new) in W._challenges)

    # JSON adânc imbricat (endpoint neautentificat /login/verify): 400, nu 500 (RecursionError)
    deep = base64.urlsafe_b64encode(b"[" * 200000).rstrip(b"=").decode()
    try:
        W._consume_anon({"response": {"clientDataJSON": deep}})
        check("clientDataJSON adânc imbricat → refuzat", False, "a trecut")
    except Exception as e:
        check("clientDataJSON adânc imbricat → 400 (ApiError), nu RecursionError",
              type(e).__name__ == "ApiError", type(e).__name__)

    # propriul flood al unui cont îi evacuează doar challenge-urile vechi, pe cel nou îl păstrează
    W._challenges.clear()
    for _ in range(W.CHALLENGE_PER_USER_MAX + 3):
        W._remember(os.urandom(32), A)
    last = os.urandom(32)
    W._remember(last, A)
    check("cel mai nou challenge al contului supravieţuieşte propriului plafon",
          W._consume(_cred(b64(last)), A) == last)

    # plafon: o rafală de /login/options nu poate umple memoria
    for _ in range(W.CHALLENGE_MAX + 50):
        W._remember_anon(os.urandom(32))
    check("stocul anonim e plafonat", len(W._challenges_anon) <= W.CHALLENGE_MAX,
          len(W._challenges_anon))
    check("clientDataJSON cu challenge ne-text → 400, nu 500",
          refused(W._consume, {"response": {"clientDataJSON": base64.urlsafe_b64encode(
              b'{"challenge": 5}').rstrip(b"=").decode()}}, A))

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
    host = _up(config.PUBLIC_URL).hostname or ""
    is_ip = all(part.isdigit() for part in host.split(".")) and host.count(".") == 3
    if is_ip:
        check("pe IP, WebAuthn e raportat ca indisponibil", webauthn_api.available() is False)

    # ── schimbarea setului de passkey-uri cere al doilea factor ─────────────
    src_gate = inspect.getsource(webauthn_api.second_gate)
    check("poarta de al doilea factor foloseşte un contor propriu, neresetabil din afară",
          "passkey2fa:" in src_gate)
    check("…şi NU acceptă emailul în locul TOTP când TOTP e activ",
          src_gate.index("totp_enabled") < src_gate.index("issue_email_challenge"))

    await db.close()
    print(f"\n{ok}/{total} PASS", flush=True)
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
