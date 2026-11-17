"""Erori de API cu un COD stabil, pe lângă mesajul în engleză.

Mesajele erau exclusiv în engleză şi ajungeau verbatim în dialoguri româneşti: „the agent is
offline; it cannot be uninstalled remotely right now. Bring it online and retry, or pass
force=1…" într-o casetă altfel tradusă. Catalogul are ~1200 de chei şi nu acoperea niciunul.

Traducerea NU se face pe server. Serverul trimite un cod stabil, iar clientul îl caută în
catalog; dacă nu-l cunoaşte, afişează mesajul englezesc. Trei motive:

  * `detail` rămâne un ŞIR în engleză — deci `curl`, scripturile, tokenurile de automatizare
    şi logurile văd exact ce vedeau şi înainte. Nicio ruptură de contract.
  * catalogul de traduceri rămâne într-un singur loc (frontend), nu duplicat pe server;
  * clientul ştie limba aleasă de om, serverul nu (`Accept-Language` e al browserului, nu al
    preferinţei din Setări).

Codurile sunt şi un semnal mai bun decât textul: `isStepupError` din frontend decidea cu un
regex pe mesaj (`/2FA|passkey|parola contului/i`) — fragil la orice reformulare, şi deja
greşit: prindea şi „the host requires 2FA — not reachable with an automation token", care NU
e o cerere de step-up.
"""
import asyncio
import json
import logging

from fastapi import HTTPException

log = logging.getLogger("webterm")


class ApiError(HTTPException):
    """HTTPException + un cod stabil, expus ca `X-WebTerm-Error` şi în corpul JSON.

    `vars` (opţional) = valorile pe care le purta mesajul englezesc (host, port, limită, secunde
    de aşteptare). Clientul le interpolează în cheia tradusă (`{retry}`, `{limit}`…) — altfel
    traducerea ar fi ori vagă („prea multe încercări"), ori ar pierde exact informaţia utilă.
    Merg în antetul `X-WebTerm-Error-Vars` (JSON) şi în corp, nu în `detail`, ca `detail` să
    rămână şirul englezesc pe care îl văd curl/scripturile."""

    def __init__(self, status_code: int, code: str, detail: str, headers=None, vars=None):
        hdrs = {**(headers or {}), "X-WebTerm-Error": code}
        if vars:
            # doar scalare, serializate compact şi ASCII-safe (antetele HTTP nu sunt UTF-8)
            hdrs["X-WebTerm-Error-Vars"] = json.dumps(
                {k: v for k, v in vars.items() if isinstance(v, (str, int, float, bool))},
                ensure_ascii=True, separators=(",", ":"))
        super().__init__(status_code=status_code, detail=detail, headers=hdrs)
        self.code = code
        self.vars = dict(vars or {})


def rate_limited(retry: int) -> ApiError:
    """429 uniform pentru lockout-ul per IP (login/setup/reauth/conectare directă)."""
    return ApiError(429, "auth.rateLimited", f"too many attempts; retry in {retry}s",
                    headers={"Retry-After": str(retry)}, vars={"retry": int(retry)})


def runtime_api_error(e: Exception, default_code: str, status: int = 502) -> ApiError:
    """RuntimeError-urile din core (update de agent, telnet/serial/sesiune) poartă mesaje
    englezeşti cu instrucţiuni de meniu („unlock it from Settings → Security") — le dăm cod,
    textul rămâne în `detail` şi în log."""
    msg = str(e) or type(e).__name__
    low = msg.lower()
    if "signing key" in low and "locked" in low:
        code = "signing.locked"
    elif ".sig missing" in low:
        code = "signing.sigMissing"
    elif "refused the update" in low:
        code = "update.refused"
    elif "agent refused" in low:
        code = "agent.refused"
    elif "source missing" in low or "no parsable" in low:
        code = "agent.sourceMissing"
    elif isinstance(e, (TimeoutError, asyncio.TimeoutError)):
        code = "host.noAnswer"
    else:
        code = default_code
    log.info("%s: %s", code, msg)
    return ApiError(status, code, msg)
