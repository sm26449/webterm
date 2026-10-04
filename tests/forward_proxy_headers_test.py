"""Proxy-ul HTTP de forward: antetele hop-by-hop NU trec prin el, în niciun sens.

Audit 2026-10-04: `_HOP_BY_HOP` conţinea „trailers" (o VALOARE a lui `TE`), nu „trailer"
(numele antetului, RFC 7230 §4.4) — deci un `Trailer:` din browser ajungea la ţintă, iar unul de
la ţintă ajungea în răspunsul nostru. Testul rulează `proxy_forward_http` pe un tunel FALS (nu
avem agent): sursa de forward e înlocuită cu un obiect care înregistrează cererea brută trimisă
ţintei şi răspunde cu un răspuns HTTP/1.0 canonic. Hermetic, fără reţea.
"""
import asyncio
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ["WEBTERM_PUBLIC_URL"] = "http://localhost:8000"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from starlette.requests import Request  # noqa: E402

from app import api  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class FakeStream:
    """Interfaţa `ForwardStream`: write/read/close. Ţine ce a scris proxy-ul şi serveşte
    răspunsul canonic în două bucăţi (antet + corp), apoi EOF (None)."""
    def __init__(self, reply: bytes):
        self.sent = b""
        self.chunks = [reply[:40], reply[40:]]
        self.closed = False

    async def write(self, data: bytes) -> None:
        self.sent += data

    async def read(self):
        return self.chunks.pop(0) if self.chunks else None

    async def close(self) -> None:
        self.closed = True


class FakeConn:
    def __init__(self, reply: bytes):
        self.stream = FakeStream(reply)

    async def open_forward(self, thost, tport):
        return self.stream


def make_request(headers: list[tuple[bytes, bytes]], method: bytes = b"GET") -> Request:
    scope = {"type": "http", "http_version": "1.1", "method": method.decode(), "scheme": "http",
             "path": "/x", "raw_path": b"/x", "query_string": b"", "root_path": "",
             "headers": headers, "client": ("127.0.0.1", 1234), "server": ("t", 80)}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}
    return Request(scope, receive)


async def main():
    reply = (b"HTTP/1.0 200 OK\r\nX-Up: 1\r\nTrailer: Expires\r\nConnection: close\r\n"
             b"Keep-Alive: timeout=5\r\nTE: trailers\r\nContent-Type: text/plain\r\n\r\nhello")
    conn = FakeConn(reply)

    async def fake_source(host_id):
        return conn
    orig = api._ensure_forward_source
    api._ensure_forward_source = fake_source
    try:
        req = make_request([(b"host", b"slug.fwd.example"), (b"trailer", b"Expires"),
                            (b"te", b"trailers"), (b"x-keep", b"yes"), (b"connection", b"keep-alive"),
                            (b"upgrade", b"h2c"), (b"accept", b"*/*")])
        resp = await api.proxy_forward_http(req, 1, "10.0.0.9", 8080, "/x", "http")
        sent = conn.stream.sent.decode("latin1")
        head = sent.split("\r\n\r\n", 1)[0].lower().split("\r\n")
        names = {ln.split(":", 1)[0] for ln in head[1:]}
        check("cererea către ţintă e HTTP/1.0 pe calea cerută", head[0] == "get /x http/1.0", head[0])
        check("`Trailer:` din browser NU ajunge la ţintă", "trailer" not in names, str(names))
        check("`TE:` nu ajunge la ţintă", "te" not in names, str(names))
        check("`Connection`/`Upgrade` din browser nu ajung la ţintă (doar al nostru `close`)",
              "upgrade" not in names and sent.count("Connection:") == 1
              and "Connection: close" in sent, sent[:200])
        check("antetele normale trec (X-Keep, Accept)", "x-keep" in names and "accept" in names)
        check("Host-ul e rescris pe ţinta STOCATĂ", "host: 10.0.0.9:8080" in head)

        # răspunsul: hop-by-hop de la ţintă nu ajunge în browser
        rh = {k.lower() for k in resp.headers.keys()}
        check("răspuns 200 proxy-at", resp.status_code == 200, str(resp.status_code))
        check("`Trailer:` de la ţintă NU ajunge în răspuns", "trailer" not in rh, str(rh))
        check("`Connection`/`Keep-Alive`/`TE` de la ţintă nu ajung în răspuns",
              not ({"connection", "keep-alive", "te"} & rh), str(rh))
        check("antetele normale ale ţintei trec (X-Up, Content-Type)",
              resp.headers.get("x-up") == "1" and resp.headers.get("content-type") == "text/plain")
        body = b"".join([c async for c in resp.body_iterator])
        check("corpul e transmis integral şi tunelul se închide la EOF",
              body == b"hello" and conn.stream.closed, repr(body))

        # setul însuşi: numele corect, fără forma greşită care nu potrivea nimic
        check("_HOP_BY_HOP are `trailer` şi nu `trailers`",
              "trailer" in api._HOP_BY_HOP and "trailers" not in api._HOP_BY_HOP
              and "te" in api._HOP_BY_HOP)
    finally:
        api._ensure_forward_source = orig

    print(f"\n{ok}/{total} passed")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
