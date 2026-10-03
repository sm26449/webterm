"""Docker prin agent: când userul agentului nu e în grupul docker (permission denied pe socket),
_docker_run reîncearcă O DATĂ cu `sudo -n` (ca os_upgrade). Verificăm:
  * comandă normală reuşită → fără sudo, răspuns direct;
  * permission denied → retry `sudo -n docker …`; dacă sudo merge → răspunsul lui (transparent);
  * permission denied ŞI sudo pică (fără passwordless) → docker_list ridică ApiError docker.denied.
"""
import asyncio
import os
import sys
import tempfile

os.environ["WEBTERM_DATA_DIR"] = tempfile.mkdtemp()
os.environ.setdefault("WEBTERM_SETUP_TOKEN", "test-setup")
os.environ.setdefault("WEBTERM_PUBLIC_URL", "http://localhost:8000")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway"))

from app import api, core  # noqa: E402

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


class FakeAgent(core.AgentConnection):
    """AgentConnection fals: răspunde la run_command după un scenariu (cmd prefix → resp)."""
    def __init__(self, host_id, script):
        self.host_id = host_id
        self.forwards = {}
        self._script = script
        self.calls = []

    async def run_command(self, cmd, timeout):
        self.calls.append(cmd)
        for prefix, resp in self._script:
            if cmd.startswith(prefix):
                return resp
        return {"ok": True, "exit_code": 127, "stdout": "", "stderr": "not scripted"}


DENIED = {"ok": True, "exit_code": 1, "stdout": "",
          "stderr": "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock"}
OK_OUT = {"ok": True, "exit_code": 0, "stdout": '{"Names":"web","Image":"nginx","State":"running","Status":"Up"}', "stderr": ""}


async def main():
    # 1) comandă normală reuşită — fără sudo
    core.sources[1] = FakeAgent(1, [("docker ps", OK_OUT)])
    resp = await api._docker_run(1, ["ps", "-a"])
    check("succes direct → fără sudo", resp["exit_code"] == 0 and not any("sudo" in c for c in core.sources[1].calls))

    # 2) permission denied → retry cu sudo -n, care reuşeşte → întoarce răspunsul sudo
    core.sources[2] = FakeAgent(2, [("sudo -n docker", OK_OUT), ("docker", DENIED)])
    resp = await api._docker_run(2, ["ps", "-a"])
    check("denied → retry `sudo -n docker` reuşeşte", resp["exit_code"] == 0)
    check("a doua chemare chiar e cu sudo -n", any(c.startswith("sudo -n docker") for c in core.sources[2].calls))

    # 3) denied ŞI sudo pică → docker_list ridică ApiError docker.denied
    core.sources[3] = FakeAgent(3, [("sudo -n docker", {"ok": True, "exit_code": 1, "stdout": "", "stderr": "sudo: a password is required"}),
                                    ("docker", DENIED)])

    async def _no_stepup(*a, **k):
        return None
    orig = api._require_host_stepup
    api._require_host_stepup = _no_stepup
    raised = None
    try:
        await api.docker_list(3, "containers", user={"id": 1, "email": "a@b.co"})
    except api.ApiError as e:
        raised = e.code
    except Exception as e:  # noqa: BLE001
        raised = type(e).__name__
    finally:
        api._require_host_stepup = orig
    check("denied + sudo pică → ApiError docker.denied", raised == "docker.denied", str(raised))

    # 4) _docker_denied recunoaşte ambele forme
    check("_docker_denied prinde 'permission denied'", api._docker_denied("Permission denied ..."))
    check("_docker_denied prinde '/var/run/docker.sock'", api._docker_denied("dial unix /var/run/docker.sock"))
    check("_docker_denied NU dă fals pozitiv", not api._docker_denied("no such container"))

    print(f"\n{ok}/{total} checks passed")
    if ok != total:
        raise SystemExit(1)


asyncio.run(main())
