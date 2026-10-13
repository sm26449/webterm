"""scripts/cert-renew.sh against FAKE ACME stores (3.6.7) — never a real Traefik.

The script edits Traefik's certificate stores as root on the gateway host, so every refusal is
tested, not just the happy path. The setup is hermetic: a throw-away install directory, two store
files made from REAL certificates generated here, a fake `docker` (records stop/start, answers
`ps`/`inspect` from files) and a local TLS server standing in for Traefik on :443.

What we check:
  * it refuses to run outside a WebTerm install directory;
  * --report is read-only, lists store / domains / expiry, flags the incident (a wildcard in the
    HTTP-01 store, expired, an entry no router asks for) and NEVER prints key material;
  * the default run backs up (0600 files, 0700 dir) and does not duplicate an unchanged backup;
  * --domain refuses bad names (shell metacharacters, option injection, single label), a name
    that matches nothing, an ambiguous store, and a non-terminal without --yes — all without
    stopping Traefik or touching a store;
  * --domain --yes removes ONLY that entry (other stores untouched), stops → edits → starts only
    the Traefik container, keeps the store 0600, and polls until a valid certificate is served;
    on a timeout it says so, prints the restore command and leaves Traefik running;
  * --prune-unrouted is a dry run unless --yes, and refuses when the router labels are unknown;
  * backup retention keeps the newest 5; --restore only accepts our own backup directories.
"""
import base64
import datetime
import json
import os
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SCRIPT = os.path.join(ROOT, "scripts", "cert-renew.sh")
# a marker standing in for key material (built at runtime, not a literal); must never be printed
KEY_MARK = base64.b64encode(b"fake key material, must never be printed").decode()

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


def make_cert(names, days, cn=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn or names[0])])
    nb = now - datetime.timedelta(days=90) if days < 0 else now - datetime.timedelta(days=1)
    b = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(nb)
         .not_valid_after(now + datetime.timedelta(days=days)))
    if names:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
    cert = b.sign(key, hashes.SHA256())
    pem = cert.public_bytes(serialization.Encoding.PEM)
    kpem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    return pem, kpem


def entry(main, sans, days):
    pem, _ = make_cert([main] + sans, days)
    return {"domain": {"main": main, "sans": sans},
            "certificate": base64.b64encode(pem).decode(), "key": KEY_MARK, "Store": "default"}


def store(resolver, certs):
    return {resolver: {"Account": {"Email": "a@x.co", "PrivateKey": KEY_MARK, "KeyType": "4096"},
                       "Certificates": certs}}


LABELS = [
    {"traefik.enable": "true",
     "traefik.http.routers.webterm.rule": "Host(`wt.example.com`)",
     "traefik.http.routers.webterm.tls.certresolver": "ledns",
     "traefik.http.routers.webterm.tls.domains[0].main": "wt.example.com",
     "traefik.http.routers.webterm.tls.domains[0].sans": "*.wt.example.com",
     "traefik.http.routers.webterm-fwd.rule": "HostRegexp(`^[a-z0-9-]+\\.wt\\.example\\.com$`)",
     "traefik.http.routers.webterm-fwd.tls.certresolver": "ledns",
     "traefik.http.routers.webterm-fwd.tls.domains[0].main": "wt.example.com",
     "traefik.http.routers.webterm-fwd.tls.domains[0].sans": "*.wt.example.com"},
    {"traefik.enable": "true",
     "traefik.http.routers.authentik.rule": "Host(`auth.example.com`)",
     "traefik.http.routers.authentik.tls.certresolver": "le"},
    None,
]

ARGS = """--providers.docker=true
--certificatesresolvers.le.acme.email=a@x.co
--certificatesresolvers.le.acme.storage=/letsencrypt/acme.json
--certificatesresolvers.le.acme.httpchallenge=true
--certificatesresolvers.le.acme.httpchallenge.entrypoint=web
--certificatesresolvers.ledns.acme.email=a@x.co
--certificatesresolvers.ledns.acme.storage=/letsencrypt/acme-dns.json
--certificatesresolvers.ledns.acme.dnschallenge=true
--certificatesresolvers.ledns.acme.dnschallenge.provider=cloudflare
"""

FAKE_DOCKER = r"""#!/bin/sh
# fake docker for cert_renew_script_test: logs every call, answers from $FAKE_DIR
echo "$*" >> "$FAKE_DIR/calls"
case "$1" in
  ps)
    case "$*" in
      *service=traefik*) [ -f "$FAKE_DIR/no-traefik" ] || echo cid-traefik ;;
      *) echo "cid-traefik cid-app cid-ak" ;;
    esac ;;
  inspect)
    case "$*" in
      *Args*) cat "$FAKE_DIR/args" ;;
      *Labels*) [ -f "$FAKE_DIR/no-labels" ] && exit 1; cat "$FAKE_DIR/labels" ;;
      *Mounts*) cat "$FAKE_DIR/mount" ;;
    esac ;;
  stop|start) : ;;
  *) echo "fake docker: unexpected $*" >&2; exit 9 ;;
esac
"""


class TLSServer:
    """A stand-in for Traefik on :443: serves one certificate to anyone, whatever the SNI."""

    def __init__(self, names, days, cn=None):
        d = tempfile.mkdtemp()
        pem, kpem = make_cert(names, days, cn)
        self.crt, self.key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
        open(self.crt, "wb").write(pem)
        open(self.key, "wb").write(kpem)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(self.crt, self.key)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        self.sock.settimeout(0.3)
        while not self.stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                continue
            try:
                c.settimeout(3)
                t = self.ctx.wrap_socket(c, server_side=True)
                t.close()
            except Exception:
                try:
                    c.close()
                except OSError:
                    pass

    def close(self):
        self.stop = True
        self.sock.close()


def setup(base):
    inst = os.path.join(base, "inst")
    os.makedirs(os.path.join(inst, "scripts"))
    shutil.copy(os.path.join(ROOT, "docker-compose.prod.yml"), inst)
    open(os.path.join(inst, ".env"), "w").write("WEBTERM_DOMAIN=wt.example.com\n")
    shutil.copy(SCRIPT, os.path.join(inst, "scripts", "cert-renew.sh"))
    acme = os.path.join(base, "acme")
    os.makedirs(acme)
    write_json(os.path.join(acme, "acme.json"), store("le", [
        entry("wt.example.com", ["*.wt.example.com"], -1),      # THE incident: expired wildcard in HTTP-01
        entry("auth.example.com", [], 60),
    ]))
    write_json(os.path.join(acme, "acme-dns.json"), store("ledns", [
        entry("wt.example.com", ["*.wt.example.com"], 80),
    ]))
    fake = os.path.join(base, "fake")
    os.makedirs(os.path.join(fake, "bin"))
    open(os.path.join(fake, "args"), "w").write(ARGS)
    open(os.path.join(fake, "labels"), "w").write("\n".join(json.dumps(x) for x in LABELS) + "\n")
    open(os.path.join(fake, "mount"), "w").write(acme + "\n")
    dk = os.path.join(fake, "bin", "docker")
    open(dk, "w").write(FAKE_DOCKER)
    os.chmod(dk, 0o755)
    return inst, acme, fake


IS_ROOT = os.geteuid() == 0
NOBODY = 65534        # test mode is refused to root, so as root the suite runs the script as nobody


def give_away(path):
    """As root: hand the fixture tree to `nobody`, who runs the script in test mode."""
    if not IS_ROOT:
        return
    for dp, dns, fns in os.walk(path):
        os.chown(dp, NOBODY, NOBODY)
        for n in fns:
            os.chown(os.path.join(dp, n), NOBODY, NOBODY)


def write_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(path, 0o600)
    if IS_ROOT:
        os.chown(path, NOBODY, NOBODY)


def run(inst, fake, *args, probe_port=1, extra_env=None, script=None, test_mode=True, cwd=None,
        as_root=False):
    env = dict(os.environ)
    env.update({"DOCKER_TEST_BIN": os.path.join(fake, "bin", "docker"), "FAKE_DIR": fake,
                "WEBTERM_CERT_PROBE": "127.0.0.1:%d" % probe_port, "WEBTERM_RENEW_POLL": "1"})
    if test_mode:
        env["WEBTERM_CERT_RENEW_TEST"] = "1"      # the explicit, test-only switch
    else:
        env.pop("WEBTERM_CERT_RENEW_TEST", None)
    for k in ("WEBTERM_ACME_DIR", "WEBTERM_TRAEFIK_CONTAINER", "SUDO_USER", "DOCKER"):
        env.pop(k, None)
    env.update(extra_env or {})
    argv = ["bash", script or os.path.join(inst, "scripts", "cert-renew.sh"), *args]
    if IS_ROOT and test_mode and not as_root:
        argv = ["setpriv", "--reuid=%d" % NOBODY, "--regid=%d" % NOBODY, "--clear-groups", "--"] + argv
    p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env,
                       timeout=60, cwd=cwd)
    return p.returncode, p.stdout + p.stderr


def calls(fake):
    try:
        return open(os.path.join(fake, "calls")).read()
    except FileNotFoundError:
        return ""


def reset_calls(fake):
    try:
        os.unlink(os.path.join(fake, "calls"))
    except FileNotFoundError:
        pass


def store_names(path, resolver):
    data = json.load(open(path))
    return [c["domain"]["main"] for c in data[resolver]["Certificates"]]


def snapshot(acme):
    return {f: open(os.path.join(acme, f), "rb").read() for f in sorted(os.listdir(acme))}


def main():
    base = tempfile.mkdtemp(prefix="cert-renew-test-")
    try:
        inst, acme, fake = setup(base)
        backups = os.path.join(inst, "acme-backups")
        stray = os.path.join(base, "stray", "scripts")
        os.makedirs(stray)
        shutil.copy(SCRIPT, stray)
        os.makedirs(os.path.join(base, "plant"))
        os.makedirs(os.path.join(base, "shim"))
        os.chmod(base, 0o755)
        give_away(base)

        print("── where it runs")
        rc, out = run(inst, fake, "--report", script=os.path.join(stray, "cert-renew.sh"))
        check("refuses outside a WebTerm install dir (rc 2)", rc == 2 and "not a WebTerm install" in out, out[-300:])

        print("── --report (read-only)")
        before = snapshot(acme)
        rc, out = run(inst, fake, "--report")
        check("rc 0", rc == 0, out[-400:])
        check("lists both stores with their challenge", "Store le (HTTP-01) acme.json" in out
              and "Store ledns (DNS-01) acme-dns.json" in out, out)
        check("flags the incident: wildcard in the HTTP-01 store", "[WILDCARD-IN-HTTP01]" in out
              and "WARN: store le holds the wildcard *.wt.example.com" in out, out)
        check("flags the expired entry", "EXPIRED" in out, out)
        check("flags the le entry no router asks for (routers use ledns)", "UNROUTED" in out
              and "no router asks for" in out, out)
        check("auth.example.com (router on le) is NOT unrouted",
              not any("auth.example.com" in ln and "UNROUTED" in ln for ln in out.splitlines()), out)
        check("never prints key material", KEY_MARK not in out and "PRIVATE KEY" not in out)
        check("read-only: stores untouched, no backup, Traefik not stopped",
              snapshot(acme) == before and not os.path.exists(backups) and "stop" not in calls(fake))

        print("── default run = backup + list")
        rc, out = run(inst, fake)
        dirs = sorted(os.listdir(backups)) if os.path.isdir(backups) else []
        check("a timestamped backup was made", rc == 0 and len(dirs) == 1 and dirs[0].startswith("acme-"), out)
        bdir = os.path.join(backups, dirs[0]) if dirs else ""
        check("backup dir 0700, files 0600", dirs and stat.S_IMODE(os.stat(backups).st_mode) == 0o700
              and all(stat.S_IMODE(os.stat(os.path.join(bdir, f)).st_mode) == 0o600 for f in os.listdir(bdir)))
        check("backup holds both stores, byte for byte", dirs and sorted(os.listdir(bdir)) == ["acme-dns.json", "acme.json"]
              and all(open(os.path.join(bdir, f), "rb").read() == before[f] for f in before))
        rc, out = run(inst, fake)
        check("idempotent: an unchanged store is not backed up twice",
              rc == 0 and len(os.listdir(backups)) == 1 and "unchanged" in out, out[-300:])

        print("── --domain refusals (nothing stopped, nothing changed)")
        reset_calls(fake)
        for bad in ("a;rm -rf /", "$(id)", "`id`", "-x", "--yes", "localhost", "wt.example.com\nx.y",
                    "wt example.com", "*.*.example.com", "wt.example.com.", "WT.EXAMPLE.COM'"):
            rc, out = run(inst, fake, "--domain", bad, "--yes")
            check("bad name %r → rc 2" % bad, rc == 2 and "invalid domain" in out, "%s %s" % (rc, out[-200:]))
        rc, out = run(inst, fake, "--domain", "nomatch.example.com", "--yes")
        check("a name matching nothing → rc 3", rc == 3 and "nothing to remove" in out, out[-300:])
        rc, out = run(inst, fake, "--domain", "wt.example.com", "--store", "bad;store", "--yes")
        check("a bad --store → rc 2", rc == 2, out[-200:])
        rc, out = run(inst, fake, "--domain", "wt.example.com")
        check("no --yes and no terminal → refuses (rc 1)", rc == 1 and "re-run with --yes" in out, out[-300:])
        check("…and showed the plan first", "WOULD REMOVE wt.example.com: store le" in out
              and "WOULD REMOVE wt.example.com: store ledns" in out, out)
        check("refusals never stopped Traefik nor changed a store",
              "stop" not in calls(fake) and snapshot(acme) == before, calls(fake))
        dup = os.path.join(acme, "acme.json")
        data = json.load(open(dup))
        data["le"]["Certificates"].append(entry("auth.example.com", [], 30))
        write_json(dup, data)
        rc, out = run(inst, fake, "--domain", "auth.example.com", "--yes")
        check("two entries for one name in a store → rc 4 (ambiguous)", rc == 4 and "ambiguous" in out, out[-300:])
        data["le"]["Certificates"].pop()
        write_json(dup, data)

        print("── --domain --yes (the incident fix)")
        reset_calls(fake)
        n_backups = len(os.listdir(backups))
        good = TLSServer(["wt.example.com", "*.wt.example.com"], 89)
        try:
            rc, out = run(inst, fake, "--domain", "wt.example.com", "--store", "le", "--yes",
                          probe_port=good.port)
        finally:
            good.close()
        check("rc 0 and reports the served certificate", rc == 0 and "OK: a valid certificate is served" in out, out[-500:])
        check("removed ONLY the le entry", store_names(os.path.join(acme, "acme.json"), "le") == ["auth.example.com"],
              store_names(os.path.join(acme, "acme.json"), "le"))
        check("the ledns store is untouched", open(os.path.join(acme, "acme-dns.json"), "rb").read()
              == before["acme-dns.json"])
        check("the account key is still in the store", json.load(open(os.path.join(acme, "acme.json")))
              ["le"]["Account"]["PrivateKey"] == KEY_MARK)
        check("store stays 0600 (Traefik refuses anything else)",
              stat.S_IMODE(os.stat(os.path.join(acme, "acme.json")).st_mode) == 0o600)
        c = [ln for ln in calls(fake).splitlines() if ln.split()[0] in ("stop", "start", "restart", "rm", "kill")]
        check("stop → start of ONLY the Traefik container", c == ["stop -t 10 cid-traefik", "start cid-traefik"], c)
        check("never prints key material", KEY_MARK not in out)
        check("a backup was taken before the change", len(os.listdir(backups)) == n_backups + 1,
              "%d → %s" % (n_backups, os.listdir(backups)))

        print("── --domain: the new certificate does not come")
        reset_calls(fake)
        dflt = TLSServer([], 365, cn="TRAEFIK DEFAULT CERT")
        try:
            t0 = time.time()
            rc, out = run(inst, fake, "--domain", "*.wt.example.com", "--store", "ledns", "--yes",
                          "--timeout", "2", probe_port=dflt.port)
            took = time.time() - t0
        finally:
            dflt.close()
        check("rc 1 + NOT YET + Traefik's default certificate named", rc == 1 and "NOT YET" in out
              and "default certificate" in out, out[-500:])
        check("prints how to undo (--restore <backup>)", "--restore " + backups in out, out[-300:])
        check("the timeout is bounded", took < 30, took)
        c = [ln.split()[0] for ln in calls(fake).splitlines() if ln.split()[0] in ("stop", "start")]
        check("Traefik was started again (never left stopped)", c == ["stop", "start"], c)
        check("the wildcard (quoted name) matched its SAN", store_names(os.path.join(acme, "acme-dns.json"), "ledns") == [])

        print("── --prune-unrouted")
        write_json(os.path.join(acme, "acme.json"), store("le", [entry("auth.example.com", [], 60),
                                                                 entry("old.example.com", [], 20)]))
        write_json(os.path.join(acme, "acme-dns.json"), store("ledns", [entry("wt.example.com", ["*.wt.example.com"], 80)]))
        reset_calls(fake)
        snap = snapshot(acme)
        rc, out = run(inst, fake, "--prune-unrouted")
        check("dry run by default: lists old.example.com only", rc == 0 and "WOULD REMOVE old.example.com" in out
              and "auth.example.com" not in out and "wt.example.com" not in out and "dry run" in out, out)
        check("dry run changed nothing and stopped nothing", snapshot(acme) == snap and "stop" not in calls(fake))
        open(os.path.join(fake, "no-labels"), "w").close()
        rc, out = run(inst, fake, "--prune-unrouted", "--yes")
        check("router labels unknown → refuses (rc 5)", rc == 5 and "refusing to prune" in out, out[-300:])
        check("…without stopping Traefik", "stop" not in calls(fake))
        os.unlink(os.path.join(fake, "no-labels"))
        rc, out = run(inst, fake, "--prune-unrouted", "--yes")
        check("--yes removes it", rc == 0 and "REMOVED old.example.com" in out
              and store_names(os.path.join(acme, "acme.json"), "le") == ["auth.example.com"], out[-300:])
        check("the routed entries stay", store_names(os.path.join(acme, "acme-dns.json"), "ledns") == ["wt.example.com"])
        rc, out = run(inst, fake, "--prune-unrouted", "--yes")
        check("idempotent: a second run has nothing to prune", rc == 0 and "Nothing to prune" in out, out[-200:])

        print("── backup retention + restore")
        outs = []
        for i in range(6):
            write_json(os.path.join(acme, "acme.json"), store("le", [entry("auth.example.com", [], 60 + i)]))
            rc, out = run(inst, fake)
            outs.append("rc=%s %s" % (rc, " | ".join(l for l in out.splitlines() if "Backup" in l or "rror" in l)))
        names = sorted(os.listdir(backups))
        check("keeps the newest 5 backups", len(names) == 5, names)
        newest = os.path.join(backups, names[-1])
        check("the newest backup is the current store", open(os.path.join(newest, "acme.json"), "rb").read()
              == open(os.path.join(acme, "acme.json"), "rb").read(), "%s ;; %s" % (names, " ;; ".join(outs)))
        # all in ONE second (a fixed `date`): after retention removed `acme-<stamp>`, a new backup
        # must not re-use that free lower name — it would sort first (CI: 3.6.7, 3.6.9 tags)
        fdate = os.path.join(base, "fixed-date")
        os.makedirs(fdate, exist_ok=True)
        with open(os.path.join(fdate, "date"), "w") as f:
            f.write('#!/bin/sh\ncase "$*" in *%Y%m%dT*) echo 20300101T000000Z ;; *) exec /bin/date "$@" ;; esac\n')
        os.chmod(fdate, 0o755)
        os.chmod(os.path.join(fdate, "date"), 0o755)
        for i in range(8):
            write_json(os.path.join(acme, "acme.json"), store("le", [entry("auth.example.com", [], 90 + i)]))
            rc, out = run(inst, fake, extra_env={"PATH": fdate + ":" + os.environ.get("PATH", "/usr/bin:/bin")})
        same = sorted(os.listdir(backups))
        check("same second: still the newest 5, numbered upward", len(same) == 5
              and same == ["acme-20300101T000000Z-%02d" % n for n in range(4, 9)], same)
        check("same second: the newest backup is the current store",
              open(os.path.join(backups, same[-1], "acme.json"), "rb").read()
              == open(os.path.join(acme, "acme.json"), "rb").read(), same)
        names = same
        oldest = os.path.join(backups, names[0])
        rc, out = run(inst, fake, "--restore", "/etc", "--yes")
        check("--restore outside acme-backups → rc 2", rc == 2, out[-200:])
        rc, out = run(inst, fake, "--restore", oldest)
        check("--restore without --yes on a non-terminal → refuses", rc == 1, out[-200:])
        reset_calls(fake)
        rc, out = run(inst, fake, "--restore", oldest, "--yes")
        check("--restore --yes puts the backup back", rc == 0 and open(os.path.join(acme, "acme.json"), "rb").read()
              == open(os.path.join(oldest, "acme.json"), "rb").read(), out[-300:])
        check("…through a stop/start of Traefik, store 0600",
              [ln.split()[0] for ln in calls(fake).splitlines() if ln.split()[0] in ("stop", "start")] == ["stop", "start"]
              and stat.S_IMODE(os.stat(os.path.join(acme, "acme.json")).st_mode) == 0o600)

        print("── review F1: no module shadowing (the script runs as root from the caller's cwd)")
        plant = os.path.join(base, "plant")
        marker = os.path.join(base, "PWNED")
        for mod in ("json", "calendar", "re", "ssl", "tempfile", "base64"):
            open(os.path.join(plant, mod + ".py"), "w").write(
                "open(%r, 'a').write(%r)\nraise SystemExit('planted %s imported')\n" % (marker, mod + "\n", mod))
        # the trap is real: a plain `python3 -` from that directory DOES import the planted json.py
        subprocess.run(["python3", "-"], input="import json\n", text=True, cwd=plant, capture_output=True)
        check("(sanity) a plain `python3 -` from that cwd imports the planted json.py", os.path.exists(marker))
        if os.path.exists(marker):
            os.unlink(marker)
        rc, out = run(inst, fake, "--report", cwd=plant, extra_env={"PYTHONPATH": plant, "PYTHONSTARTUP": os.path.join(plant, "json.py")})
        check("--report from a cwd with json.py / calendar.py / re.py planted: works", rc == 0 and "Store le" in out, out[-300:])
        check("…and imported none of them (cd / + python3 -I)", not os.path.exists(marker),
              open(marker).read() if os.path.exists(marker) else "")

        print("── hardening: env overrides only in test mode, never under sudo; root-owned paths")
        reset_calls(fake)
        os.chmod(inst, 0o775)                         # group-writable install dir
        rc, out = run(inst, fake, "--report", test_mode=False)
        check("outside test mode: a group-writable install dir → refused (rc 2)", rc == 2
              and "must be owned by root and not writable" in out, out[-300:])
        check("…and the DOCKER_TEST_BIN / WEBTERM_* overrides were not used", calls(fake) == "", calls(fake))
        # follow-up 1: ROOT never gets test mode — not with SUDO_USER blanked, not without sudo
        # (cron, a root shell). As root we run it for real; otherwise in a user namespace where
        # we are uid 0 (`unshare -r`), when the runner allows one.
        for label, env_extra in (("SUDO_USER blanked", {"SUDO_USER": ""}), ("no sudo at all (cron, root shell)", {}),
                                 ("SUDO_USER=alice", {"SUDO_USER": "alice"})):
            reset_calls(fake)
            if IS_ROOT:
                rc, out = run(inst, fake, "--report", extra_env=env_extra, as_root=True)
                ran = True
            else:
                envr = dict(os.environ, WEBTERM_CERT_RENEW_TEST="1", FAKE_DIR=fake,
                            DOCKER_TEST_BIN=os.path.join(fake, "bin", "docker"), **env_extra)
                envr.pop("SUDO_USER", None) if "SUDO_USER" not in env_extra else None
                try:
                    p_ = subprocess.run(["unshare", "-r", "bash", os.path.join(inst, "scripts", "cert-renew.sh"),
                                         "--report"], env=envr, capture_output=True, text=True, timeout=60,
                                        stdin=subprocess.DEVNULL)
                    rc, out = p_.returncode, p_.stdout + p_.stderr
                    ran = "unshare:" not in out
                except FileNotFoundError:
                    ran = False
            if not ran:
                print("  SKIP root test mode (%s): not root and no user namespaces here" % label)
                continue
            check("as root (%s): the test switch is refused, and said so" % label,
                  "ignored when running as root" in out and rc == 2, out[-300:])
            check("…so no override was honoured (%s)" % label, calls(fake) == "", calls(fake))
        os.chmod(inst, 0o755)
        os.chmod(os.path.join(inst, "scripts", "cert-renew.sh"), 0o777)
        rc, out = run(inst, fake, "--report", test_mode=False)
        check("outside test mode: a world-writable script → refused (or a non-root owner)", rc == 2
              and "must be owned by root" in out, out[-300:])
        os.chmod(os.path.join(inst, "scripts", "cert-renew.sh"), 0o755)

        print("── follow-up 2: every parent up to /, .env and the compose file must be root's")
        if not IS_ROOT:
            print("  SKIP: needs root (a non-root runner cannot own a root-owned tree)")
        else:
            tree = tempfile.mkdtemp(prefix="cert-renew-tree-")          # root, 0700, under sticky /tmp
            mid = os.path.join(tree, "srv")
            inst2 = os.path.join(mid, "webterm")
            os.makedirs(os.path.join(inst2, "scripts"))
            os.chmod(tree, 0o755)
            os.chmod(mid, 0o755)
            os.chmod(inst2, 0o755)
            shutil.copy(os.path.join(ROOT, "docker-compose.prod.yml"), inst2)
            os.chmod(os.path.join(inst2, "docker-compose.prod.yml"), 0o644)
            envf = os.path.join(inst2, ".env")
            open(envf, "w").write("WEBTERM_DOMAIN=wt.example.com\n")
            os.chmod(envf, 0o600)
            shutil.copy(SCRIPT, os.path.join(inst2, "scripts", "cert-renew.sh"))
            os.chmod(os.path.join(inst2, "scripts", "cert-renew.sh"), 0o755)
            fk = os.path.join(tree, "fake")                            # a `docker` on PATH that sees no Traefik
            os.makedirs(os.path.join(fk, "bin"))
            open(os.path.join(fk, "no-traefik"), "w").close()
            open(os.path.join(fk, "bin", "docker"), "w").write(FAKE_DOCKER)
            os.chmod(os.path.join(fk, "bin", "docker"), 0o755)
            env2 = {"PATH": os.path.join(fk, "bin") + ":" + os.environ.get("PATH", ""), "FAKE_DIR": fk}

            def run2():
                return run(inst2, fk, "--report", test_mode=False, extra_env=env2, as_root=True)
            rc, out = run2()
            check("a root-owned tree (sticky /tmp above it, .env 0600) passes the checks",
                  "refusing" not in out and "cannot find the ACME store" in out, out[-300:])
            os.chmod(mid, 0o775)
            rc, out = run2()
            check("a group-writable PARENT → refused, named", rc == 2 and ("parent %s must be owned" % mid) in out, out[-300:])
            os.chmod(mid, 0o1777)
            rc, out = run2()
            check("…a sticky one (like /tmp) is allowed", "refusing" not in out, out[-300:])
            os.chmod(mid, 0o755)
            os.chown(mid, NOBODY, 0)
            rc, out = run2()
            check("a parent owned by someone else → refused", rc == 2 and "parent %s" % mid in out, out[-300:])
            os.chown(mid, 0, 0)
            os.chmod(envf, 0o640)
            rc, out = run2()
            check(".env 0640 with group root → accepted", "refusing" not in out, out[-300:])
            os.chown(envf, 0, NOBODY)
            rc, out = run2()
            check(".env 0640 with a non-root group → refused", rc == 2 and "readable by a non-root group" in out, out[-300:])
            os.chown(envf, 0, 0)
            os.chmod(envf, 0o660)
            rc, out = run2()
            check(".env group-writable → refused", rc == 2 and ".env must be owned by root" in out, out[-300:])
            os.chmod(envf, 0o600)
            os.chown(envf, NOBODY, NOBODY)
            rc, out = run2()
            check(".env not owned by root → refused", rc == 2 and ".env must be owned by root" in out, out[-300:])
            os.chown(envf, 0, 0)
            os.chmod(os.path.join(inst2, "docker-compose.prod.yml"), 0o666)
            rc, out = run2()
            check("docker-compose.prod.yml world-writable → refused", rc == 2
                  and "docker-compose.prod.yml must be owned by root" in out, out[-300:])
            shutil.rmtree(tree, ignore_errors=True)

        print("── no Traefik container")
        open(os.path.join(fake, "no-traefik"), "w").close()
        rc, out = run(inst, fake, "--report")
        check("cannot find the store → clear error, rc≠0", rc != 0 and "cannot find the ACME store" in out, out[-200:])
        rc, out = run(inst, fake, "--domain", "auth.example.com", "--yes",
                      extra_env={"WEBTERM_ACME_DIR": acme})
        check("--domain with no Traefik running refuses before editing", rc != 0 and "not running" in out
              and "REMOVED" not in out, out[-300:])
    finally:
        shutil.rmtree(base, ignore_errors=True)

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
