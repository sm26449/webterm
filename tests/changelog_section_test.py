"""scripts/changelog-section.py — the GitHub Release notes of a tag come from CHANGELOG.md.

Hermetic: a synthetic changelog (edge cases) plus the REAL CHANGELOG.md for 3.5.10–3.5.16, so a
heading written in a new shape is caught here and not as an empty release page after a tag push.
Also validates .github/workflows/release-notes.yml (YAML, trigger, permissions, pinned actions).
"""
import importlib.util
import os
import re
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SCRIPT = os.path.join(ROOT, "scripts", "changelog-section.py")
spec = importlib.util.spec_from_file_location("changelog_section", SCRIPT)
cs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cs)

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print("  %s %s%s" % ("PASS" if cond else "FAIL", name, "" if cond else "  --  %s" % detail))


SAMPLE = """# Changelog

Intro text that belongs to no release.

## [Unreleased]

### Added
- something not released yet

## [2.1.0] — 2026-01-03 · agent (12)

**This release updates the agent (11 → 12).**

### Added
- **A feature** that wraps
  onto a second line, see [docs](docs/X.md#a) and [web](https://example.org/y).
  - nested item
- second item

```sh
keep   this
  verbatim
```

| a | b |
|---|---|
| 1 | 2 |

## [2.0.1] — 2026-01-02 · agent (11)

### Fixed
- a fix

## [2.0.0] — 2026-01-01 · agent (11)

- first

[2.0.0]: https://example.org/compare/v1...v2
"""


def main():
    secs = cs.sections(SAMPLE)
    check("sections: Unreleased + 3 releases, newest first",
          [s["version"] for s in secs] == ["Unreleased", "2.1.0", "2.0.1", "2.0.0"], [s["version"] for s in secs])
    s, older = cs.find(SAMPLE, "v2.1.0")
    check("find accepts v-prefixed tags; older = next section", s["version"] == "2.1.0" and older["version"] == "2.0.1")
    check("heading parsed: date + agent", (s["date"], s["agent"]) == ("2026-01-03", 12), (s["date"], s["agent"]))
    check("body starts at the first non-blank line, stops before the next release",
          s["body"].startswith("**This release updates") and "a fix" not in s["body"] and "2.0.1" not in s["body"])
    check("title marks an agent change", cs.title(s, older) == "WebTerm 2.1.0 · agent 12", cs.title(s, older))
    s2, o2 = cs.find(SAMPLE, "2.0.1")
    check("title without an agent change has no agent", cs.title(s2, o2) == "WebTerm 2.0.1")
    s3, o3 = cs.find(SAMPLE, "2.0.0")
    check("oldest section: no older → no agent mark", o3 is None and cs.title(s3, o3) == "WebTerm 2.0.0")
    check("trailing link references dropped", s3["body"] == "- first", repr(s3["body"]))
    check("unknown version → (None, None)", cs.find(SAMPLE, "9.9.9") == (None, None))
    check("Unreleased is never the 'older' section", cs.find(SAMPLE, "2.0.0")[1] is None)

    n = cs.notes(s, "v2.1.0", "ghcr.io/o/r", "o/r")
    check("notes: wrapped list item joined into one line",
          "- **A feature** that wraps onto a second line, see" in n, n[:400])
    check("notes: nested item and second item stay separate lines",
          "\n  - nested item\n- second item\n" in n, n[:500])
    check("notes: code fence kept verbatim", "```sh\nkeep   this\n  verbatim\n```" in n)
    check("notes: table rows kept", "| a | b |\n|---|---|\n| 1 | 2 |" in n)
    check("notes: repo-relative link made absolute at the tag, external link untouched",
          "[docs](https://github.com/o/r/blob/v2.1.0/docs/X.md#a)" in n and "[web](https://example.org/y)" in n)
    check("notes: footer with image (linked to the package) and upgrade command",
          "**Image:** [`ghcr.io/o/r:v2.1.0`](https://github.com/o/r/pkgs/container/r)" in n
          and "sudo ./upgrade.sh v2.1.0" in n and "docker pull ghcr.io/o/r:v2.1.0" in n, n[-600:])
    big = dict(s, body="- x\n" * 40000)
    nb = cs.notes(big, "v2.1.0", "ghcr.io/o/r", "o/r")
    check("notes: an oversized body is cut under GitHub's limit, with a link to the file",
          len(nb) < 125000 and "truncated" in nb and "blob/v2.1.0/CHANGELOG.md" in nb, len(nb))

    # ── the real CHANGELOG ──
    with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as f:
        real = f.read()
    titles = {}
    for v in ("3.5.10", "3.5.11", "3.5.12", "3.5.13", "3.5.14", "3.5.15", "3.5.16"):
        sec, old = cs.find(real, v)
        good = sec is not None and old is not None and len(sec["body"]) > 200 and sec["agent"] is not None
        check("real CHANGELOG %s: section found, non-trivial, agent parsed" % v, good, v)
        if not good:
            continue
        titles[v] = cs.title(sec, old)
        body = cs.notes(sec, "v" + v, "ghcr.io/sm26449/webterm", "sm26449/webterm")
        check("real %s: no other release heading leaks into the notes" % v,
              not re.search(r"^## \[", body, re.M), v)
        check("real %s: no repo-relative links left" % v, not cs.REL_LINK.search(body),
              cs.REL_LINK.findall(body)[:3])
    check("real titles: 3.5.16 changed the agent (57 → 58), 3.5.10–3.5.15 did not",
          titles.get("3.5.16") == "WebTerm 3.5.16 · agent 58"
          and all(titles.get("3.5.1%d" % i) == "WebTerm 3.5.1%d" % i for i in range(0, 6)), titles)

    # ── CLI ──
    r = subprocess.run([sys.executable, SCRIPT, "v3.5.16", "--title"], capture_output=True, text=True)
    check("CLI --title", r.returncode == 0 and r.stdout.strip() == "WebTerm 3.5.16 · agent 58", r.stdout + r.stderr)
    r = subprocess.run([sys.executable, SCRIPT, "3.5.15", "--notes", "--repo", "sm26449/webterm"],
                       capture_output=True, text=True)
    check("CLI --notes: body + footer", r.returncode == 0 and "ghcr.io/sm26449/webterm:v3.5.15" in r.stdout
          and "upgrade.sh v3.5.15" in r.stdout, r.stderr)
    r = subprocess.run([sys.executable, SCRIPT, "0.0.1"], capture_output=True, text=True)
    check("CLI: unknown version → exit 1 + message", r.returncode == 1 and "no section" in r.stderr)

    # ── the workflow ──
    wf_path = os.path.join(ROOT, ".github", "workflows", "release-notes.yml")
    try:
        import yaml
    except ImportError:
        yaml = None
    with open(wf_path, encoding="utf-8") as f:
        raw = f.read()
    if yaml is None:
        print("  (PyYAML missing — structural checks on the raw text only)")
        check("workflow: tag trigger + contents: write (raw)", "tags: ['v*']" in raw and "contents: write" in raw)
    else:
        wf = yaml.safe_load(raw)
        on = wf.get("on") or wf.get(True)          # YAML 1.1 reads a bare `on` as True
        check("workflow: YAML loads; push on tags v*", on["push"]["tags"] == ["v*"] and "branches" not in on["push"], on)
        inputs = on["workflow_dispatch"]["inputs"]
        check("workflow: workflow_dispatch backfill input, default 10",
              str(inputs["backfill"]["default"]) == "10", inputs)
        check("workflow: contents: write (and nothing else)", wf["permissions"] == {"contents": "write"},
              wf["permissions"])
        jobs = wf["jobs"]
        check("workflow: runners pinned to ubuntu-24.04", all(j["runs-on"] == "ubuntu-24.04" for j in jobs.values()))
    uses = re.findall(r"uses:\s*(\S+)", raw)
    check("workflow: every action pinned to a full commit SHA",
          uses and all(re.search(r"@[0-9a-f]{40}$", u) for u in uses), uses)
    check("workflow: uses this script and gh release (no third-party release action)",
          "scripts/changelog-section.py" in raw and "gh release create" in raw and "gh release edit" in raw)

    print("\n%d/%d teste trecute" % (ok, total))
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
