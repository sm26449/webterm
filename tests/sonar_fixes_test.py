"""Corecturile din triajul SonarQube 2026-11-20 (.audit/2026-11-20-sonarqube.md):

- S7502: task-urile de fundal sunt ţinute în viaţă şi o excepţie a lor ajunge în log (`bgtasks.spawn`);
- S8786: promptul de parolă telnet şi marcajul testului de cheie SSH se citesc în timp liniar;
- S6389: filtrele de text (stare host, etichete de link) prind caracterele bidirecţionale şi separatorii
  de linie/paragraf, acum scrişi ca escape-uri în sursă."""
import asyncio
import gc
import logging
import os
import sys
import tempfile
import time

os.environ.setdefault("WEBTERM_DATA_DIR", tempfile.mkdtemp(prefix="wt-sonar-"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import bgtasks, core, deploy_keys_api, hoststatus, share_api  # noqa: E402

ok_n = total = 0


def check(name, cond, detail=""):
    global ok_n, total
    total += 1
    ok_n += bool(cond)
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


async def tasks_part():
    print("== bgtasks.spawn")
    done = []

    async def work():
        await asyncio.sleep(0.05)
        done.append(1)

    bgtasks.spawn(work(), "work")
    gc.collect()                                  # fără referinţă puternică, task-ul ar putea dispărea
    check("a spawned task is kept alive while it runs", bgtasks.pending() == 1)
    await asyncio.sleep(0.1)
    check("…runs to the end, and is released afterwards", done == [1] and bgtasks.pending() == 0)

    records = []

    class H(logging.Handler):
        def emit(self, r):
            records.append(r)
    logging.getLogger("webterm.bg").addHandler(H())

    async def boom():
        raise RuntimeError("boom")
    bgtasks.spawn(boom(), "boom task")
    await asyncio.sleep(0.01)
    check("a failing background task is logged with its name and exception",
          any("boom task" in r.getMessage() and r.exc_info for r in records), [r.getMessage() for r in records])


def regex_part():
    print("== telnet password prompt (linear)")
    P = core._PW_PROMPT
    for line in (b"Password:", b"password: ", b"Passcode", b"passphrase  :  ", b"login password :"):
        check("prompt %r matches" % line, P.search(line))
    for line in (b"Password: x", b"passwords are", b"user:"):
        check("%r does not match" % line, not P.search(line))
    hostile = b"password" + b" " * 60000 + b"x"
    t0 = time.monotonic()
    P.search(hostile)
    check("60 000 spaces after 'password' take well under a second", time.monotonic() - t0 < 0.5, time.monotonic() - t0)

    print("== SSH test output marker")
    # aceeaşi extragere ca deploy_keys_api (rpartition, fără regex)
    src = open(deploy_keys_api.__file__).read()
    check("deploy_keys_api no longer strips the marker with a trailing-whitespace regex",
          'rpartition("WT_SSH_RC:")' in src and 'WT_SSH_RC:\\d+\\s*$' not in src)

    def strip_rc(out):
        head, sep, tail = out.rpartition("WT_SSH_RC:")
        return (head if sep and tail.strip().isdigit() else out).strip()[:400]
    check("marker at the end is removed", strip_rc("ok\nWT_SSH_RC:0\n") == "ok")
    check("text after the marker keeps the output as is", strip_rc("a WT_SSH_RC:1 b") == "a WT_SSH_RC:1 b")
    t0 = time.monotonic()
    strip_rc(" " * 200000 + "x")
    check("long whitespace output is handled in linear time", time.monotonic() - t0 < 0.5)


def history_part():
    print("== history trailing spaces (linear, same result as the old regex)")
    import random
    import re
    old = re.compile(r"[ ]+((?:\x1b\[[0-9;:]*m)*)\Z")
    alpha = [" ", "a", "m", "\x1b[0m", "\x1b[1;31m", "\x1b[", ";", "\x1b[x"]
    rnd = random.Random(7)
    diff = [s for s in ("".join(rnd.choice(alpha) for _ in range(rnd.randint(0, 12))) for _ in range(50000))
            if old.sub(r"\1", s) != core._strip_trailing_spaces(s)]
    check("50 000 random lines: identical to the old regex", not diff, diff[:3])
    check("spaces then SGR: spaces go, SGR stays", core._strip_trailing_spaces("ab   \x1b[0m") == "ab\x1b[0m")
    t0 = time.monotonic()
    core.sanitize_history_line(" " * 200000 + "X")
    check("200 000 spaces then a character: linear (was 0.36 s for 4 000)", time.monotonic() - t0 < 0.2, time.monotonic() - t0)


def bidi_part():
    print("== bidi and separators are filtered (escapes in source, same runtime set)")
    for ch in "‪‮⁦⁩  \x1b\x00":
        check("U+%04X caught by host status and link-label filters" % ord(ch),
              hoststatus._CTRL.search("a" + ch) and share_api._LABEL_BAD.search("a" + ch))
    for f in (hoststatus.__file__, share_api.__file__):
        text = open(f, encoding="utf-8").read()
        check("%s has no literal bidi/separator character" % os.path.basename(f),
              not any(c in text for c in "‪‫‬‭‮⁦⁧⁨⁩  "))


asyncio.run(tasks_part())
regex_part()
history_part()
bidi_part()
print("\n%d/%d passed" % (ok_n, total))
sys.exit(0 if ok_n == total else 1)
