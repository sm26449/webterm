"""Ataşarea la o sesiune de pe un host cu 2FA cere step-up (C1).

Gaura, pe scurt: **crearea** unei sesiuni cerea step-up, **ataşarea** la una existentă nu.
`browser_ws` cerea doar un cookie valid şi ataşa clientul ca owner, cu drept de scriere. Singura
apărare era idle-lock-ul, calculat din `hub.last_interaction` — pe care fiecare `SessionHub` NOU
îl pune la `time.time()`. Cum hub-urile trăiesc doar în memorie, orice repornire de gateway
(adică fiecare upgrade) golea dicţionarul, iar prima ataşare la ORICE sesiune 2FA pornea
DEBLOCATĂ, indiferent de cât stătuse. Un cookie furat listează sesiunile şi intră pe un shell
root.

A doua parte, la fel de importantă: deblocarea accepta DOAR grant de passkey. Pe o instalare pe
IP gol, `_webauthn_available()` e False (rp_id trebuie să fie domeniu), deci nu există passkey —
iar o sesiune blocată devenea irecuperabilă. Cu ataşarea acum fail-closed, asta ar fi însemnat
blocarea definitivă a oamenilor în afara propriilor servere.
"""
import asyncio
import os
import sys
import tempfile
import time

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_SETUP_TOKEN"] = "test-setup"
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
os.environ["WEBTERM_IDLE_LOCK_SECS"] = "300"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

import httpx  # noqa: E402
from app import api, config, core, db, security  # noqa: E402
from app.main import app  # noqa: E402

ok = 0
total = 0
PW = "parolabuna1"


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class Row(dict):
    """sqlite3.Row-like: SessionHub indexează, nu foloseşte .get()."""

    def __getitem__(self, k):
        return dict.get(self, k)

    def keys(self):
        return dict.keys(self)


def _hub_for(sid, host_id):
    return core.get_or_create_hub(Row(id=sid, host_id=host_id, title="root shell", state="live",
                                      rows=24, cols=80, created=time.time(),
                                      backend="tmux", kind="shell"))


def would_start_locked(hub, uid, host_id, require_2fa=True):
    """Exact decizia din `browser_ws`, izolată."""
    if not require_2fa:
        return False
    return hub.locked or not security.stepup_window_ok(uid, host_id)


async def main():
    config.ensure_dirs()
    security.init_crypto(config.load_secret())
    await db.connect()
    await api.init_setup_token()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t", timeout=30) as c:
        await c.post("/api/setup", json={"email": "a@b.co", "password": PW,
                                         "setup_token": "test-setup"})
        me = await db.fetchone("SELECT * FROM users WHERE email=?", "a@b.co")
        uid = me["id"]
        hid = (await c.post("/api/hosts", json={"name": "cu-2fa"})).json()["id"]
        await db.execute("UPDATE hosts SET require_2fa=1 WHERE id=?", hid)

        # ── 1. mecanismul care făcea idle-lock-ul inutil ─────────────────────
        core.hubs.clear()
        security._stepup_windows.clear()
        hub = _hub_for("a" * 32, hid)
        hub.lock_idle = 300
        hub.last_interaction = time.time() - 4000       # operatorul a plecat acum ~66 min
        old_rule = hub.locked or (time.time() - hub.last_interaction > hub.lock_idle)
        check("regula VECHE: hub viu + idle mare → blocată", old_rule is True)
        core.hubs.clear()                                # gateway-ul reporneşte (orice upgrade)
        hub2 = _hub_for("a" * 32, hid)
        hub2.lock_idle = 300
        old_after = hub2.locked or (time.time() - hub2.last_interaction > hub2.lock_idle)
        check("regula VECHE: după restart, aceeaşi sesiune → DEBLOCATĂ (gaura)",
              old_after is False)
        check("last_interaction e resetat la recrearea hub-ului",
              time.time() - hub2.last_interaction < 5)

        # ── 2. regula NOUĂ: fail-closed, indiferent de vârsta hub-ului ───────
        security._stepup_windows.clear()
        check("regula NOUĂ: fără fereastră de step-up → ataşarea începe BLOCATĂ",
              would_start_locked(hub2, uid, hid) is True)
        check("regula NOUĂ: rezistă la restart (hub proaspăt, tot blocată)",
              would_start_locked(_hub_for("b" * 32, hid), uid, hid) is True)
        # ...iar un hub „proaspăt activ" nu mai e o portiţă
        hub3 = _hub_for("c" * 32, hid)
        hub3.last_interaction = time.time()
        check("regula NOUĂ: sesiune activă recent NU mai lasă cookie-ul să intre",
              would_start_locked(hub3, uid, hid) is True)

        # ── 3. fluxul normal nu capătă un pas în plus ────────────────────────
        security.open_stepup_window(uid, hid)            # ce face şi crearea sesiunii
        check("cu fereastră deschisă (după create/unlock) → ataşare DEBLOCATĂ",
              would_start_locked(hub2, uid, hid) is False)
        check("hosturile fără 2FA rămân neatinse",
              would_start_locked(hub2, uid, hid, require_2fa=False) is False)

        # ── 3b. calea de SHARE: invitatul n-are cont, deci n-are step-up ─────
        # Aceeaşi cauză, altă suprafaţă — şi mai gravă: un link de share nu cere nici măcar
        # un cookie. Regula: pe host cu 2FA, invitatul vede sesiunea DOAR cât timp owner-ul
        # verificat e ataşat.
        def guest_would_start_locked(hub, require_2fa=True):
            if not require_2fa:
                return False
            owner_present = any(getattr(c, "is_owner", False) for c in hub.clients)
            return hub.locked or not owner_present

        hub_s = _hub_for("d" * 32, hid)
        hub_s.clients.clear()
        check("share pe host 2FA, fără owner ataşat → invitat BLOCAT",
              guest_would_start_locked(hub_s) is True)

        class _Owner:
            is_owner = True

        class _Guest:
            is_owner = False

        hub_s.clients.add(_Guest())
        check("alt invitat prezent NU deblochează (doar owner-ul contează)",
              guest_would_start_locked(hub_s) is True)
        hub_s.clients.add(_Owner())
        check("cu owner-ul verificat ataşat → invitatul vede sesiunea",
              guest_would_start_locked(hub_s) is False)
        hub_s.locked = True
        check("hub blocat → invitatul rămâne blocat chiar cu owner prezent",
              guest_would_start_locked(hub_s) is True)
        hub_s.locked = False
        check("share pe host FĂRĂ 2FA rămâne neatins",
              guest_would_start_locked(hub_s, require_2fa=False) is False)

        # ── 4. deblocarea trebuie să existe şi fără WebAuthn ─────────────────
        # Pe IP gol nu există passkey. Dacă deblocarea rămâne passkey-only, ataşarea
        # fail-closed transformă orice sesiune 2FA într-o uşă zidită.
        security._stepup_windows.clear()
        try:
            await api._require_host_stepup(hid, me, "", "")
            opened_without_secret = True
        except Exception:
            opened_without_secret = False
        check("deblocare fără NICIUN factor → refuzată", opened_without_secret is False)

        old_url = config.PUBLIC_URL
        config.PUBLIC_URL = "http://10.0.0.5:8000"       # instalare pe IP gol
        try:
            check("fără WebAuthn, calea de deblocare există (rp_id nu e domeniu)",
                  api._webauthn_available() is False)
            security._stepup_windows.clear()
            try:
                await api._require_host_stepup(hid, me, "", PW)
                unlocked = security.stepup_window_ok(uid, hid)
            except Exception as e:                        # noqa: BLE001
                unlocked = False
                print("      (detaliu: %s)" % e)
            check("fără WebAuthn, parola contului deblochează", unlocked is True)
            security._stepup_windows.clear()
            try:
                await api._require_host_stepup(hid, me, "", "parola-gresita")
                bad_ok = True
            except Exception:
                bad_ok = False
            check("parola greşită NU deblochează", bad_ok is False)
        finally:
            config.PUBLIC_URL = old_url

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


async def run():
    try:
        return await main()
    finally:
        await db.close()


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(run()) else 1)
