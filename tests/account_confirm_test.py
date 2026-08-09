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

from app import api, db, email_alerts, security  # noqa: E402
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
    await db.execute("INSERT INTO users(email,password_hash,created) VALUES(?,?,?)",
                     "u@example.com", "x", time.time())
    user = await db.fetchone("SELECT * FROM users WHERE email=?", "u@example.com")
    uid = user["id"]

    # ---- note_new_login raportează verdictul, ca sesiunea să-l poată îngheţa ----
    check("primul login de pe o adresă → dispozitiv nou",
          await security.note_new_login(user, "203.0.113.5", "Firefox") is True)
    check("al doilea login de pe aceeaşi adresă → cunoscut",
          await security.note_new_login(user, "203.0.113.5", "Firefox") is False)

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
    user = row
    await api.update_account(
        api.AccountUpdate(current_password="a-treia-parola", new_password="a-patra-parola"),
        FakeReq(tok_new), user)
    row = await db.fetchone("SELECT * FROM users WHERE id=?", uid)
    check("fără SMTP → poarta nu se aplică (nu blocăm contul definitiv)",
          security.verify_password("a-patra-parola", row["password_hash"]))

    await db.close()
    print(f"\n{ok}/{total} PASS", flush=True)
    os._exit(0 if ok == total else 1)


if __name__ == "__main__":
    asyncio.run(main())
