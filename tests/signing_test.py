"""Cheie de semnare per-deployment (gateway/app/signing.py) — Faza 1.

Cel mai important test: COMPATIBILITATEA DE SEMNĂTURĂ între cele două implementări ed25519 —
gateway-ul semnează cu `cryptography`, iar agentul verifică cu verificatorul hand-rolled din
ptyd.py. Tot feature-ul depinde de asta. Plus: generare, parolă (criptare/deblocare), substituția
UPDATE_PUBKEY (fail-closed), și fail-closed la cheie blocată. Hermetic, fără DB/UI/agent real.
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

from app import signing  # noqa: E402
import ptyd  # noqa: E402  (pentru ed25519_verify hand-rolled al agentului)

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


AGENT_SRC = open(os.path.join(_here, "..", "agent", "ptyd.py"), "rb").read()


def main():
    # 1) generare (fără parolă) + pubkey disponibil
    pub = signing.generate()
    check("generate → pubkey hex de 64 caractere", len(pub) == 64 and all(c in "0123456789abcdef" for c in pub))
    check("key_exists după generare", signing.key_exists())
    check("pubkey_hex() din fișierul public", signing.pubkey_hex() == pub)
    check("fără parolă → is_encrypted False", signing.is_encrypted() is False)

    # 2) a doua generare e refuzată (rotația e altă operație)
    try:
        signing.generate()
        check("a doua generare refuzată", False)
    except ValueError:
        check("a doua generare refuzată", True)

    # 3) substituția UPDATE_PUBKEY în sursa REALĂ a agentului
    sub = signing.substitute_pubkey(AGENT_SRC, pub)
    check("substituția pune pubkey-ul deployment-ului", b'UPDATE_PUBKEY = bytes.fromhex(' in sub and pub.encode() in sub)
    check("substituția schimbă exact o dată (sursa diferă)", sub != AGENT_SRC)
    check("AGENT_VERSION neatins (anti-rollback intact)",
          ptyd._content_version(sub) == ptyd.AGENT_VERSION)
    # fail-closed: sursă fără UPDATE_PUBKEY → ValueError
    try:
        signing.substitute_pubkey(b"nimic aici", pub)
        check("substituție fără UPDATE_PUBKEY → fail-closed", False)
    except ValueError:
        check("substituție fără UPDATE_PUBKEY → fail-closed", True)

    # 4) *** CROSS-VERIFY *** — gateway semnează, agentul verifică
    substituted, sig_b64 = signing.sign_agent(AGENT_SRC)
    sig = base64.b64decode(sig_b64)
    pub_bytes = bytes.fromhex(pub)
    check("agentul (ed25519 hand-rolled) ACCEPTĂ semnătura gateway-ului",
          ptyd.ed25519_verify(pub_bytes, sig, substituted))
    check("semnătura e peste conținutul SUBSTITUIT (nu cel original)",
          not ptyd.ed25519_verify(pub_bytes, sig, AGENT_SRC))
    # o cheie greșită respinge
    other = bytes.fromhex("00" * 32)
    check("altă cheie publică → respins", not ptyd.ed25519_verify(other, sig, substituted))

    # 5) lock → sign ridică; pubkey rămâne disponibil (instalarea merge)
    signing.lock()
    check("după lock: is_loaded False", signing.is_loaded() is False)
    try:
        signing.sign(b"x")
        check("sign cu cheie blocată → ridică", False)
    except RuntimeError:
        check("sign cu cheie blocată → ridică", True)
    check("pubkey_hex disponibil chiar blocat (install merge)", signing.pubkey_hex() == pub)

    # 6) cheie CU PAROLĂ: criptare la repaus + deblocare (regenerăm în același dir)
    os.remove(signing._key_path())
    os.remove(signing._pub_path())
    pub2 = signing.generate(passphrase="parola-secreta")
    check("cheie cu parolă → is_encrypted True", signing.is_encrypted() is True)
    signing.lock()
    check("deblocare cu parolă GREȘITĂ eșuează", signing.load(passphrase="gresita") is False)
    check("deblocare cu parola CORECTĂ reușește", signing.load(passphrase="parola-secreta") is True)
    # semnătura după deblocare tot se verifică la agent
    sub2, sb2 = signing.sign_agent(AGENT_SRC)
    check("semnătură validă și cu cheie criptată (după deblocare)",
          ptyd.ed25519_verify(bytes.fromhex(pub2), base64.b64decode(sb2), sub2))

    # 7) IMPORT: cheie ed25519 EXISTENTĂ (migrare / restore / cheie externă)
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _Ed
    ext = _Ed.generate()
    ext_pub = ext.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw).hex()
    os.remove(signing._key_path()); os.remove(signing._pub_path())
    pem_plain = ext.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8, _ser.NoEncryption())
    check("import PEM plain → pubkey-ul cheii importate", signing.import_key(pem_plain) == ext_pub)
    subi, sbi = signing.sign_agent(AGENT_SRC)
    check("cheia importată semnează valid (agentul acceptă)",
          ptyd.ed25519_verify(bytes.fromhex(ext_pub), base64.b64decode(sbi), subi))

    os.remove(signing._key_path()); os.remove(signing._pub_path())
    pem_enc = ext.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8,
                                _ser.BestAvailableEncryption(b"pem-parola"))
    try:
        signing.import_key(pem_enc)
        check("import PEM criptat FĂRĂ parolă → respins", False)
    except ValueError:
        check("import PEM criptat FĂRĂ parolă → respins", True)
    check("import PEM criptat CU parolă → pubkey corect",
          signing.import_key(pem_enc, load_passphrase="pem-parola") == ext_pub)

    os.remove(signing._key_path()); os.remove(signing._pub_path())
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    rsa_pem = _rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        _ser.Encoding.PEM, _ser.PrivateFormat.PKCS8, _ser.NoEncryption())
    try:
        signing.import_key(rsa_pem)
        check("import cheie non-ed25519 → respins", False)
    except ValueError:
        check("import cheie non-ed25519 → respins", True)

    # ── auto-generarea cheii la instalare NOUĂ ────────────────────────────────────────────
    # Regula decide singura întrebare care contează: e gratuit acum, sau rupe flota?
    # Fără cheie + fără hosturi = instalare nouă → generăm (altfel deployment-ul rămâne pe
    # ancora de încredere a mentainerului, comună tuturor instalărilor publice).
    check("instalare nouă (fără cheie, fără hosturi) → generăm",
          signing.should_autogenerate(has_hosts=False) is True)
    # Cu hosturi înrolate, agenţii au deja alt pubkey încorporat: o cheie nouă le-ar bloca
    # update-urile până la reinstalarea fiecăruia, deci NU decidem noi în locul operatorului.
    check("hosturi deja înrolate → NU generăm automat",
          signing.should_autogenerate(has_hosts=True) is False)
    signing.generate(None)
    check("cheie existentă, fără hosturi → NU regenerăm (nu suprascriem)",
          signing.should_autogenerate(has_hosts=False) is False)
    check("cheie existentă, cu hosturi → NU regenerăm",
          signing.should_autogenerate(has_hosts=True) is False)
    os.remove(signing._key_path()); os.remove(signing._pub_path())

    print(f"\n{ok}/{total} teste trecute")
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
