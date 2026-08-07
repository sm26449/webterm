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
from fastapi import HTTPException


class ApiError(HTTPException):
    """HTTPException + un cod stabil, expus ca `X-WebTerm-Error` şi în corpul JSON."""

    def __init__(self, status_code: int, code: str, detail: str, headers=None):
        super().__init__(status_code=status_code, detail=detail,
                         headers={**(headers or {}), "X-WebTerm-Error": code})
        self.code = code
