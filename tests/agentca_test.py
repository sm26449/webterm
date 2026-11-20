"""CA-ul agenţilor şi certificatele de client (agentca.py, mTLS 3.7.0).

  * CA-ul se generează O SINGURĂ dată, cheia stă criptată în DB, la repornire e acelaşi;
  * un certificat emis pentru host N se verifică şi întoarce N + serialul;
  * se refuză: alt CA, expirat, alterat, fără clientAuth, fără id de host, antet gol / uriaş / gunoi;
  * antetul lui Traefik (PEM codat URL, fără BEGIN/END) şi PEM-ul complet sunt acceptate;
  * cheia emisă corespunde certificatului (agentul o încarcă cu ssl.load_cert_chain).
"""
import asyncio
import datetime
import json
import os
import ssl
import sys
import tempfile
import urllib.parse

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_PUBLIC_URL"] = "https://wt.example.org"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID  # noqa: E402

from app import agentca, config, db, security  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


def traefik_header(pem: str) -> str:
    """Ce pune passTLSClientCert (pem: true): corpul base64, fără BEGIN/END, codat URL."""
    body = "".join(pem.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").split())
    return urllib.parse.quote(body, safe="")


async def main():
    await db.connect()
    security.init_crypto(config.load_secret())

    print("== the CA")
    ca = await agentca.ensure_ca()
    stored = json.loads(await db.get_setting(agentca.K_CA, ""))
    check("CA created and stored", bool(stored.get("cert")) and bool(stored.get("key")))
    check("the CA's private key is encrypted at rest (no PEM in the DB)", "PRIVATE KEY" not in stored["key"])
    check("CA is a CA, valid ~10 years", ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
          and (ca.not_valid_after_utc - ca.not_valid_before_utc).days >= 3649)
    agentca.reset_for_tests()
    ca2 = await agentca.ensure_ca()
    check("after a restart it is the SAME CA, not a new one", ca2.fingerprint(hashes.SHA256()) == ca.fingerprint(hashes.SHA256()))

    print("== issuing and verifying")
    c = agentca.issue(42)
    v = agentca.verify_client_cert(traefik_header(c["cert"]))
    check("Traefik's header form verifies, with host id and serial", v and v["host_id"] == 42 and v["serial"] == c["serial"], v)
    check("a full PEM verifies too", (agentca.verify_client_cert(c["cert"]) or {}).get("host_id") == 42)
    check("validity ~1 year", 364 <= (c["not_after"] - datetime.datetime.now().timestamp()) / 86400 <= 366)
    check("two certificates for the same host have different serials", agentca.issue(42)["serial"] != c["serial"])
    d = tempfile.mkdtemp()
    open(os.path.join(d, "a.crt"), "w").write(c["cert"]); open(os.path.join(d, "a.key"), "w").write(c["key"])
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        ctx.load_cert_chain(os.path.join(d, "a.crt"), os.path.join(d, "a.key"))
        loaded = True
    except ssl.SSLError as e:
        loaded = e
    check("the agent can load the pair with the stdlib (ssl.load_cert_chain)", loaded is True, loaded)

    print("== refusals")
    later = datetime.datetime.now().timestamp() + 400 * 86400
    check("expired → refused", agentca.verify_client_cert(traefik_header(c["cert"]), now=later) is None)
    # alt CA, acelaşi nume de subiect: semnătura trebuie să cadă
    other_key = ec.generate_private_key(ec.SECP256R1())
    forged = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "webterm-agent")]))
              .issuer_name(ca.subject).public_key(other_key.public_key()).serial_number(123)
              .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
              .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
              .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier("urn:webterm:host:1")]), critical=False)
              .sign(other_key, hashes.SHA256()))
    check("same issuer NAME but another key → refused",
          agentca.verify_client_cert(forged.public_bytes(serialization.Encoding.PEM).decode()) is None)
    def by_ca(eku=True, san="urn:webterm:host:7"):
        b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")]))
             .issuer_name(ca.subject).public_key(other_key.public_key()).serial_number(77)
             .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
             .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)))
        if eku:
            b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        if san:
            b = b.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san)]), critical=False)
        return b.sign(agentca._ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
    check("signed by our CA but without clientAuth → refused", agentca.verify_client_cert(by_ca(eku=False)) is None)
    check("signed by our CA but without a host id → refused", agentca.verify_client_cert(by_ca(san=None)) is None)
    check("…or with a non-numeric host id → refused", agentca.verify_client_cert(by_ca(san="urn:webterm:host:7;8")) is None)
    check("control: same builder with both → accepted", (agentca.verify_client_cert(by_ca()) or {}).get("host_id") == 7)
    pem = c["cert"]
    i = pem.index("\n", 40) + 20
    tampered = pem[:i] + ("A" if pem[i] != "A" else "B") + pem[i + 1:]
    check("tampered certificate → refused", agentca.verify_client_cert(tampered) is None)
    for bad in ("", "not-base64!!", "A" * (agentca.MAX_HEADER + 1), "%00%01"):
        check("garbage header %r… → refused" % bad[:12], agentca.verify_client_cert(bad) is None)

    print("== a different installation")
    agentca.reset_for_tests()
    await db.set_setting(agentca.K_CA, "")
    await agentca.ensure_ca()
    check("a certificate from another installation's CA → refused", agentca.verify_client_cert(c["cert"]) is None)

    await db.close()


asyncio.run(main())
print("\n%d/%d passed" % (ok, total))
sys.exit(0 if ok == total else 1)
