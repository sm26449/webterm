"""Confirmare pe email la schimbarea credenţialelor de pe un dispozitiv necunoscut (2.0.2).

Atacul închis: cineva care ARE deja parola (reutilizată, scursă, ghicită) o roteşte şi te
scoate pe tine afară din propriul cont. Emailul e canalul pe care el nu-l are.

Testul ţine două lucruri care se strică uşor:

  · verdictul „dispozitiv nou" se ia LA LOGIN şi se îngheaţă pe sesiune. `note_new_login`
    înregistrează adresa, deci o verificare făcută mai târziu, direct în `seen_logins`, ar
    răspunde întotdeauna „cunoscut" — poarta ar părea că merge şi n-ar face nimic. Dacă
    cineva rescrie asta ca interogare live, testul „ştampila supravieţuieşte" pică.
  · poarta se aplică DOAR cu SMTP configurat. Fără canal de email, „refuzăm schimbarea"
    înseamnă blocare permanentă a contului, nu securitate.
"""
import asyncio
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://127.0.0.1:8000")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import api, config, db, email_alerts, security, totp, webauthn_api  # noqa: E402
from app.errors import ApiError  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class FakeReq:
    def __init__(self, token=None):
        self.cookies = {security.COOKIE_NAME: token} if token else {}


async def main():
    await db.connect()
    security.init_crypto(config.load_secret())   # seiful: TOTP se stochează criptat
    await db.execute("INSERT INTO users(email,password_hash,created) VALUES(?,?,?)",
                     "u@example.com", "x", time.time())
    user = await db.fetchone("SELECT * FROM users WHERE email=?", "u@example.com")
    uid = user["id"]

    # ---- „loc stabilit", nu „loc văzut o dată" -------------------------------
    # Regula naivă („am mai văzut adresa") se ocoleşte singură: cine ştie parola se loghează
    # o dată de la el de-acasă şi a doua oară adresa lui e deja „cunoscută". Un loc al tău are
    # istoric: mai multe login-uri, întinse peste mai mult de o zi.
    check("prima vizită de la o adresă → dispozitiv nou",
          await security.note_new_login(user, "203.0.113.5", "Firefox") is True)
    check("a doua vizită imediat → TOT dispozitiv nou (aici pica regula naivă)",
          await security.note_new_login(user, "203.0.113.5", "Firefox") is True)
    for _ in range(5):
        await security.note_new_login(user, "203.0.113.5", "Firefox")
    check("multe login-uri, dar toate de azi → încă nestabilit",
          await security.ip_is_known(uid, "203.0.113.5") is False)
    # îmbătrânim prima apariţie: acum are şi vechime, şi număr
    await db.execute("UPDATE seen_logins SET created=? WHERE user_id=?",
                     time.time() - security.ESTABLISHED_AGE - 60, uid)
    check("istoric + vechime → loc stabilit",
          await security.ip_is_known(uid, "203.0.113.5") is True)
    check("login de la un loc stabilit → sesiune nemarcată",
          await security.note_new_login(user, "203.0.113.5", "Firefox") is False)
    # vechime fără număr nu ajunge nici ea
    await security.note_new_login(user, "198.51.100.77", "Firefox")
    await db.execute("UPDATE seen_logins SET created=? WHERE user_id=? AND ip_hash=?",
                     time.time() - security.ESTABLISHED_AGE - 60, uid,
                     security.sha256_hex("198.51.100.77"))
    check("vechime fără login-uri repetate → tot nestabilit",
          await security.ip_is_known(uid, "198.51.100.77") is False)

    # ---- ştampila trăieşte pe sesiune, nu se recalculează ----
    tok_new = await security.create_web_session(uid, "Firefox", device_new=True)
    tok_old = await security.create_web_session(uid, "Firefox", device_new=False)
    check("sesiune pornită de pe un loc nou → marcată",
          await security.session_is_new_device(FakeReq(tok_new)) is True)
    check("sesiune pornită de pe un loc cunoscut → nemarcată",
          await security.session_is_new_device(FakeReq(tok_old)) is False)
    check("fără cookie → nu inventăm un verdict",
          await security.session_is_new_device(FakeReq()) is False)
    # Miezul: adresa e ACUM în `seen_logins` (a înregistrat-o chiar login-ul care a marcat
    # sesiunea). O poartă care ar întreba tabela ar deschide; ştampila trebuie să reziste.
    check("ştampila supravieţuieşte deşi adresa a devenit între timp cunoscută",
          await security.ip_is_known(uid, "203.0.113.5") is True
          and await security.session_is_new_device(FakeReq(tok_new)) is True)

    # ---- codul: single-use, expirabil, plafonat ----
    code = await security.issue_email_challenge(uid, "account")
    check("codul are 6 cifre", len(code) == 6 and code.isdigit(), code)
    check("cod greşit → refuzat",
          await security.consume_email_challenge(uid, "account", "000000" if code != "000000"
                                                 else "111111") is False)
    check("cod corect → acceptat",
          await security.consume_email_challenge(uid, "account", code) is True)
    check("acelaşi cod a doua oară → refuzat (single-use)",
          await security.consume_email_challenge(uid, "account", code) is False)

    # scopuri separate: un cod emis pentru altceva nu deschide contul
    c2 = await security.issue_email_challenge(uid, "other")
    check("cod emis pentru alt scop nu trece la 'account'",
          await security.consume_email_challenge(uid, "account", c2) is False)

    # un al doilea „trimite-mi codul" îl invalidează pe primul
    first = await security.issue_email_challenge(uid, "account")
    second = await security.issue_email_challenge(uid, "account")
    check("re-emiterea invalidează codul anterior",
          await security.consume_email_challenge(uid, "account", first) is False
          and await security.consume_email_challenge(uid, "account", second) is True)

    # plafon de încercări: 6 cifre se ghicesc dacă ai voie de un milion de ori
    c3 = await security.issue_email_challenge(uid, "account")
    wrong = "999999" if c3 != "999999" else "888888"
    for _ in range(security.EMAIL_CODE_MAX_ATTEMPTS):
        await security.consume_email_challenge(uid, "account", wrong)
    check("după plafonul de încercări, nici codul CORECT nu mai trece",
          await security.consume_email_challenge(uid, "account", c3) is False)

    # expirare
    c4 = await security.issue_email_challenge(uid, "account")
    await db.execute("UPDATE email_challenges SET expires=? WHERE user_id=? AND purpose=?",
                     time.time() - 1, uid, "account")
    check("cod expirat → refuzat",
          await security.consume_email_challenge(uid, "account", c4) is False)

    # ---- poarta pe endpoint-ul real ------------------------------------------
    # Până aici am testat cărămizile. Asta verifică faptul care contează: că
    # `/api/account` chiar refuză o rotire de parolă venită de pe un dispozitiv nou.
    await db.execute("UPDATE users SET password_hash=? WHERE id=?",
                     security.hash_password("corect-orizontal-capsa"), uid)
    user = await db.fetchone("SELECT * FROM users WHERE id=?", uid)
    mails = []
    email_alerts.smtp_ready = lambda: asyncio.sleep(0, result=True)

    async def fake_send(to, code, what):
        mails.append((to, code, what))
    email_alerts.send_account_code = fake_send

    def body(**kw):
        return api.AccountUpdate(current_password="corect-orizontal-capsa", **kw)

    # de pe dispozitiv nou, fără cod → refuz + codul pleacă pe adresa CONTULUI
    try:
        await api.update_account(body(new_password="parola-noua-lunga"),
                                 FakeReq(tok_new), user)
        check("dispozitiv nou fără cod → refuzat", False, "a trecut")
    except ApiError as e:
        check("dispozitiv nou fără cod → refuzat", e.code == "account.codeRequired", e.code)
    check("codul pleacă pe adresa contului, nu pe cutia de alerte",
          len(mails) == 1 and mails[0][0] == "u@example.com", mails)
    check("parola NU s-a schimbat la cererea refuzată",
          security.verify_password(
              "corect-orizontal-capsa",
              (await db.fetchone("SELECT * FROM users WHERE id=?", uid))["password_hash"]))

    # cod greşit → tot refuz
    try:
        await api.update_account(body(new_password="parola-noua-lunga", email_code="000001"),
                                 FakeReq(tok_new), user)
        check("cod greşit → refuzat", False, "a trecut")
    except ApiError as e:
        check("cod greşit → refuzat", e.code == "account.badCode", e.code)

    # cod corect → trece
    await api.update_account(
        body(new_password="parola-noua-lunga", email_code=mails[0][1]), FakeReq(tok_new), user)
    row = await db.fetchone("SELECT * FROM users WHERE id=?", uid)
    check("cod corect → parola se schimbă",
          security.verify_password("parola-noua-lunga", row["password_hash"]))

    # de pe un dispozitiv cunoscut nu se cere nimic în plus
    tok_old = await security.create_web_session(uid, "Firefox", device_new=False)
    user = row
    await api.update_account(
        api.AccountUpdate(current_password="parola-noua-lunga", new_password="a-treia-parola"),
        FakeReq(tok_old), user)
    row = await db.fetchone("SELECT * FROM users WHERE id=?", uid)
    check("dispozitiv cunoscut → fără cod, schimbarea trece",
          security.verify_password("a-treia-parola", row["password_hash"]))
    check("dispozitiv cunoscut → n-am trimis niciun email în plus", len(mails) == 1, mails)

    # fără SMTP poarta NU se aplică: altfel o instalare fără email nu şi-ar mai putea
    # schimba niciodată parola — blocare permanentă, nu securitate
    email_alerts.smtp_ready = lambda: asyncio.sleep(0, result=False)
    tok_new = await security.create_web_session(uid, "Firefox", device_new=True)
    user = row
    await api.update_account(
        api.AccountUpdate(current_password="a-treia-parola", new_password="a-patra-parola"),
        FakeReq(tok_new), user)
    row = await db.fetchone("SELECT * FROM users WHERE id=?", uid)
    check("fără SMTP → poarta nu se aplică (nu blocăm contul definitiv)",
          security.verify_password("a-patra-parola", row["password_hash"]))

    # ---- passkey-urile cer al doilea factor -----------------------------------
    # Parola singură îi permitea celui care o are să-şi înroleze propriul passkey — o cheie
    # permanentă, rezistentă la phishing, la contul tău — sau să ţi-l şteargă pe al tău.
    user = await db.fetchone("SELECT * FROM users WHERE id=?", uid)
    tok_new = await security.create_web_session(uid, "Firefox", device_new=True)
    tok_old = await security.create_web_session(uid, "Firefox", device_new=False)

    class Body:
        def __init__(self, **kw):
            self.password = "x"
            self.totp_code = ""
            self.email_code = ""
            self.__dict__.update(kw)

    # fără TOTP, de pe un dispozitiv STABILIT → nimic în plus (parola rămâne suficientă)
    email_alerts.smtp_ready = lambda: asyncio.sleep(0, result=True)
    await webauthn_api._second_gate(user, FakeReq(tok_old), Body(), "enrol")
    check("fără TOTP, dispozitiv stabilit → parola rămâne suficientă", True)

    # fără TOTP, de pe un dispozitiv nou → cod pe email
    mails.clear()
    try:
        await webauthn_api._second_gate(user, FakeReq(tok_new), Body(), "enrol")
        check("fără TOTP, dispozitiv nou → cere cod pe email", False, "a trecut")
    except ApiError as e:
        check("fără TOTP, dispozitiv nou → cere cod pe email",
              e.code == "account.codeRequired", e.code)
    await webauthn_api._second_gate(user, FakeReq(tok_new), Body(email_code=mails[0][1]), "enrol")
    check("codul emis pentru passkey deschide poarta", True)

    # cu TOTP activ → codul de pe telefon, indiferent de dispozitiv
    secret = totp.new_secret()
    await db.execute("UPDATE users SET totp_enabled=1, totp_secret_encrypted=? WHERE id=?",
                     security.encrypt_secret(secret), uid)
    user = await db.fetchone("SELECT * FROM users WHERE id=?", uid)
    try:
        await webauthn_api._second_gate(user, FakeReq(tok_old), Body(), "enrol")
        check("cu TOTP → cere codul chiar şi de pe dispozitivul obişnuit", False, "a trecut")
    except ApiError as e:
        check("cu TOTP → cere codul chiar şi de pe dispozitivul obişnuit",
              e.code == "passkey.totpRequired", e.code)
    try:
        await webauthn_api._second_gate(user, FakeReq(tok_old), Body(totp_code="000000"), "enrol")
        check("cod TOTP greşit → refuzat", False, "a trecut")
    except ApiError as e:
        check("cod TOTP greşit → refuzat", e.code == "passkey.badTotp", e.code)
    # emailul NU e o alternativă la TOTP: altfel 2FA ar valora cât accesul la inbox
    code = await security.issue_email_challenge(uid, "passkey")
    try:
        await webauthn_api._second_gate(user, FakeReq(tok_new), Body(email_code=code), "enrol")
        check("cu TOTP activ, emailul NU înlocuieşte codul de pe telefon", False, "a trecut")
    except ApiError as e:
        check("cu TOTP activ, emailul NU înlocuieşte codul de pe telefon",
              e.code == "passkey.totpRequired", e.code)
    # codul corect trece
    await webauthn_api._second_gate(
        user, FakeReq(tok_old), Body(totp_code=totp.generate(secret)), "enrol")
    check("cod TOTP corect → trece", True)

    await db.close()
    print(f"\n{ok}/{total} PASS", flush=True)
    os._exit(0 if ok == total else 1)


if __name__ == "__main__":
    asyncio.run(main())
