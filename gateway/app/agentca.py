"""CA-ul agenţilor şi certificatele lor de client (mTLS, 3.7.0). Design: docs/design/AGENT-MTLS.md.

Fiecare instalare îşi generează PROPRIUL CA la prima pornire: cheie ECDSA P-256, valabil 10 ani. Cheia
privată stă în baza de date (setarea `agent_ca`), criptată cu `security.encrypt_secret` (aceeaşi cheie
de seif ca restul secretelor), deci intră în backup-ul criptat şi supravieţuieşte unui restore pe alt
server: agenţii nu trebuie re-enrolaţi. Partea PUBLICĂ a CA-ului ajunge la Traefik (edgemtls.py), care
cere la handshake un certificat de client semnat de el.

Certificatul unui host: cheie ECDSA P-256 generată AICI (agentul are doar biblioteca standard şi nu
poate genera chei), `CN=webterm-agent`, SAN `URI:urn:webterm:host:<id>`, EKU clientAuth, serial
aleatoriu, valabil `CERT_DAYS`. Serialul curent stă pe rândul hostului: gateway-ul e punctul de revocare
(Traefik nu verifică liste de revocare pentru certificatele de client), deci re-emiterea, re-enrolarea
sau ştergerea hostului fac certificatul vechi inutil.

`verify_client_cert` primeşte certificatul pe care Traefik l-a văzut în handshake (antetul pus de
`passTLSClientCert`) şi verifică, fără să aibă încredere în nimic din cerere: semnătura CA-ului nostru,
fereastra de valabilitate, EKU-ul şi id-ul hostului din SAN. Comparaţia cu serialul curent o face
apelantul, care are rândul hostului."""
import base64
import datetime
import json
import logging
import secrets
import urllib.parse
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import db, security

log = logging.getLogger("webterm.agentca")

K_CA = "agent_ca"
CA_DAYS = 3650
CERT_DAYS = 365
URI_PREFIX = "urn:webterm:host:"
MAX_HEADER = 16 * 1024            # un certificat P-256 are ~600 octeţi; antetul nu are motiv să fie mare

_ca_cert: Optional[x509.Certificate] = None
_ca_key = None


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _generate_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WebTerm"),
                      x509.NameAttribute(NameOID.COMMON_NAME, "WebTerm agent CA %s" % secrets.token_hex(4))])
    now = _now()
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=CA_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    return cert, key


async def ensure_ca() -> x509.Certificate:
    """CA-ul instalării: încărcat din DB, sau generat (o singură dată) dacă lipseşte."""
    global _ca_cert, _ca_key
    if _ca_cert is not None:
        return _ca_cert
    raw = await db.get_setting(K_CA, "")
    if raw:
        # întâi în variabile locale; publicăm doar perechea completă şi potrivită (audit 3.7.0: un
        # certificat încărcat fără cheie lăsa mTLS „pornit" cu emiterea imposibilă)
        d = json.loads(raw)
        cert = x509.load_pem_x509_certificate(d["cert"].encode())
        key = serialization.load_pem_private_key(security.decrypt_secret(d["key"]).encode(), password=None)
        if cert.public_key().public_numbers() != key.public_key().public_numbers():
            raise ValueError("agent CA certificate and key do not match")
        _ca_cert, _ca_key = cert, key
        return _ca_cert
    cert, key = _generate_ca()
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    await db.set_setting(K_CA, json.dumps({"cert": cert.public_bytes(serialization.Encoding.PEM).decode(),
                                           "key": security.encrypt_secret(key_pem)}))
    _ca_cert, _ca_key = cert, key
    log.info("agent CA created (valid until %s)", cert.not_valid_after_utc.date())
    return cert


def ca_pem() -> str:
    if _ca_cert is None:
        raise RuntimeError("agent CA not loaded (call ensure_ca first)")
    return _ca_cert.public_bytes(serialization.Encoding.PEM).decode()


def ca_not_after() -> Optional[float]:
    return _ca_cert.not_valid_after_utc.timestamp() if _ca_cert is not None else None


def issue(host_id: int, days: int = CERT_DAYS) -> dict:
    """Cheie + certificat de client pentru un host. Întoarce PEM-urile, serialul (hex) şi expirarea."""
    if _ca_cert is None or _ca_key is None:
        raise RuntimeError("agent CA not loaded (call ensure_ca first)")
    key = ec.generate_private_key(ec.SECP256R1())
    now = _now()
    serial = x509.random_serial_number()
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "webterm-agent")]))
            .issuer_name(_ca_cert.subject).public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(min(now + datetime.timedelta(days=days), _ca_cert.not_valid_after_utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(URI_PREFIX + str(int(host_id)))]),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(_ca_key.public_key()), critical=False)
            .sign(_ca_key, hashes.SHA256()))
    return {"cert": cert.public_bytes(serialization.Encoding.PEM).decode(),
            "key": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                     serialization.NoEncryption()).decode(),
            "serial": format(serial, "x"), "not_after": cert.not_valid_after_utc.timestamp()}


def _der_from_header(value: str) -> Optional[bytes]:
    """Antetul pus de Traefik (`passTLSClientCert` cu `pem: true`): PEM-ul certificatului, codat URL,
    fără liniile BEGIN/END. Acceptăm şi PEM-ul complet. Primul certificat, dacă sunt mai multe."""
    if not value or len(value) > MAX_HEADER:
        return None
    text = urllib.parse.unquote(value).split(",")[0]
    text = text.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "")
    text = "".join(text.split())
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, base64.binascii.Error):
        return None


def verify_client_cert(header_value: str, now: Optional[float] = None) -> Optional[dict]:
    """{"host_id", "serial", "not_after"} dacă certificatul e semnat de CA-ul NOSTRU, valabil acum, cu
    EKU clientAuth şi un id de host în SAN; altfel None. Nu face nicio presupunere despre cerere."""
    if _ca_cert is None:
        return None
    der = _der_from_header(header_value)
    if not der:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
        if cert.issuer != _ca_cert.subject:
            return None
        _ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        t = datetime.datetime.fromtimestamp(now, datetime.timezone.utc) if now else _now()
        if not (cert.not_valid_before_utc <= t <= cert.not_valid_after_utc):
            return None
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.CLIENT_AUTH not in eku:
            return None
        uris = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value \
            .get_values_for_type(x509.UniformResourceIdentifier)
        ids = [u[len(URI_PREFIX):] for u in uris if u.startswith(URI_PREFIX)]
        if len(ids) != 1 or not ids[0].isdigit():
            return None
        return {"host_id": int(ids[0]), "serial": format(cert.serial_number, "x"),
                "not_after": cert.not_valid_after_utc.timestamp()}
    except (InvalidSignature, UnsupportedAlgorithm, ValueError, x509.ExtensionNotFound, TypeError):
        return None


def reset_for_tests() -> None:
    global _ca_cert, _ca_key
    _ca_cert, _ca_key = None, None
