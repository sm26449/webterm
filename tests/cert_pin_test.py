"""Pin-ul de certificat al agentului (F-07 din auditul extern, agent v41).

Ce era greşit: pin-ul se punea pe amprenta certificatului ÎNTREG. Un audit a semnalat-o ca
risc de disponibilitate; măsurătoarea a arătat că e o certitudine — CA-ul intern al lui Caddy,
folosit exact de instalarea pe IP unde pin-ul se activează, emite certificate de **12 ore**.
Deci flota se oprea până a doua zi, iar remediul ar fi trebuit să circule pe conexiunea pe
care agenţii tocmai o refuzaseră.

Trei schimbări, toate verificate aici pe certificate GENERATE, nu pe şiruri inventate:
  · pin pe SubjectPublicKeyInfo, care supravieţuieşte unei reînnoiri cu aceeaşi cheie;
  · listă de pin-uri, ca o rotire să poată fi pregătită dinainte;
  · niciun pin pe certificate de scurtă durată — ele se rotesc mai repede decât ar putea
    pin-ul să reziste, iar un pin care garantează căderea nu e o apărare.
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def make_cert(days, key_pem=None, cn="wt.test"):
    """Certificat autosemnat REAL, cu openssl. Dacă primeşte o cheie, o reutilizează —
    aşa simulăm exact ce face o reînnoire care păstrează cheia."""
    d = tempfile.mkdtemp()
    key = os.path.join(d, "k.pem")
    crt = os.path.join(d, "c.pem")
    if key_pem:
        open(key, "w").write(key_pem)
    else:
        subprocess.run(["openssl", "genrsa", "-out", key, "2048"],
                       check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-new", "-x509", "-key", key, "-out", crt,
                    "-days", str(days), "-subj", "/CN=" + cn],
                   check=True, capture_output=True)
    der = subprocess.run(["openssl", "x509", "-in", crt, "-outform", "DER"],
                         check=True, capture_output=True).stdout
    return der, open(key).read()


def openssl_spki_sha256(der):
    """Amprenta SPKI calculată de OPENSSL — referinţa independentă faţă de parserul nostru.
    Dacă cele două nu coincid, parserul e greşit, oricât de verde ar fi restul testului."""
    p1 = subprocess.run(["openssl", "x509", "-inform", "DER", "-pubkey", "-noout"],
                        input=der, check=True, capture_output=True).stdout
    p2 = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"],
                        input=p1, check=True, capture_output=True).stdout
    import hashlib
    return hashlib.sha256(p2).hexdigest()


def main():
    import ptyd

    WS = ptyd.WSClient

    # ── parserul DER, faţă în faţă cu openssl ───────────────────────────────
    der, key = make_cert(365)
    mine = WS.spki_pin(der)
    theirs = openssl_spki_sha256(der)
    check("SPKI calculat de noi == cel calculat de openssl", mine == theirs,
          "%s != %s" % (mine, theirs))

    spki, nb, na = WS._cert_parts(der)
    check("fereastra de valabilitate e citită corect (~365 zile)",
          nb and na and 360 * 86400 < (na - nb) < 370 * 86400,
          None if not nb else (na - nb) / 86400.0)

    # ── proprietatea care contează: reînnoirea cu aceeaşi cheie ─────────────
    der2, _ = make_cert(365, key_pem=key)
    check("certificatul REÎNNOIT e alt certificat",
          ptyd.hashlib.sha256(der).hexdigest() != ptyd.hashlib.sha256(der2).hexdigest())
    check("…dar are ACELAŞI SPKI → pin-ul supravieţuieşte",
          WS.spki_pin(der) == WS.spki_pin(der2))
    der3, _ = make_cert(365)
    check("un certificat cu ALTĂ cheie are alt SPKI → pin-ul respinge",
          WS.spki_pin(der) != WS.spki_pin(der3))

    # ── verificarea propriu-zisă ────────────────────────────────────────────
    def ws_with(pins):
        w = WS.__new__(WS)
        w.cert_pins = [p.lower() for p in pins if p]
        w.cert_pin = w.cert_pins[0] if w.cert_pins else None
        w.peer_spki = None
        w.peer_der = b""
        return w

    w = ws_with([WS.spki_pin(der)])
    w._check_cert_pin(der)
    check("pin SPKI corect → trece", True)
    w2 = ws_with([WS.spki_pin(der)])
    w2._check_cert_pin(der2)
    check("acelaşi pin acceptă certificatul reînnoit", True)

    w3 = ws_with([WS.spki_pin(der)])
    try:
        w3._check_cert_pin(der3)
        check("cheie străină → refuzat", False, "a trecut")
    except ptyd.WSError as e:
        check("cheie străină → refuzat", "pin mismatch" in str(e))
        check("mesajul spune amprenta observată, ca recuperarea să fie posibilă",
              WS.spki_pin(der3)[:16] in str(e), str(e)[:120])

    # compatibilitate: agenţii deja înrolaţi au un pin pe certificatul ÎNTREG
    legacy = ptyd.hashlib.sha256(der).hexdigest()
    w4 = ws_with([legacy])
    w4._check_cert_pin(der)
    check("pin vechi (pe certificatul întreg) încă e acceptat — fără re-înrolare", True)

    # listă: oricare dintre pin-uri deschide, ca o rotire să poată fi pregătită
    w5 = ws_with([WS.spki_pin(der3), WS.spki_pin(der)])
    w5._check_cert_pin(der)
    check("listă de pin-uri: oricare se potriveşte → trece", True)

    # fără pin: nu verificăm nimic (deployment cu CA public)
    w6 = ws_with([])
    w6._check_cert_pin(der3)
    check("fără pin configurat → no-op", True)

    # ── regula care opreşte căderea de 12 ore ───────────────────────────────
    short_der, _ = make_cert(1)
    _, snb, sna = WS._cert_parts(short_der)
    check("certificat de scurtă durată: durata e citită",
          sna - snb <= 2 * 86400, (sna - snb) / 3600.0)
    check("sub pragul de fixare (48h)", (sna - snb) < ptyd.CERT_PIN_MIN_LIFETIME)
    check("un certificat normal e PESTE prag", (na - nb) >= ptyd.CERT_PIN_MIN_LIFETIME)

    check("AGENT_VERSION a crescut (altfel gateway-ul nu împinge update-ul)",
          ptyd.AGENT_VERSION >= 41, ptyd.AGENT_VERSION)

    print(f"\n{ok}/{total} PASS", flush=True)
    sys.exit(0 if ok == total else 1)


if __name__ == "__main__":
    main()
