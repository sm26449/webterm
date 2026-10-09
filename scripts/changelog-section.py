#!/usr/bin/env python3
"""Extract one release's section from CHANGELOG.md — for the GitHub Release of a tag.

    changelog-section.py 3.5.16                 # the section body (Markdown), as written
    changelog-section.py v3.5.16 --title        # "WebTerm 3.5.16 · agent 58"
    changelog-section.py 3.5.16 --notes --image ghcr.io/sm26449/webterm
                                                # body + footer (image, upgrade command)

Used by .github/workflows/release-notes.yml. Stdlib only. Exit 1 when the version has no section
(a release without notes is a mistake worth a red run, not an empty page).

The title names the agent only when the release CHANGES it, i.e. its `· agent (N)` differs from
the next older section's: that is the line an operator needs before upgrading (hosts update their
agent on reconnect), and repeating "agent 57" on every patch would hide it.
"""
import argparse
import os
import re
import sys

HEADING = re.compile(r"^## \[(?P<version>[^\]]+)\](?P<rest>.*)$")
AGENT = re.compile(r"agent\s*\((?P<n>\d+)\)")
DATE = re.compile(r"(\d{4}-\d{2}-\d{2})")
LINK_REF = re.compile(r"^\[[^\]]+\]:\s*\S+")
# a Markdown link whose target is a path in the repository (`[x](docs/TRANSFERS.md#copy)`): fine in
# CHANGELOG.md, broken on a release page (it would resolve under /releases/tag/)
REL_LINK = re.compile(r"\]\((?!https?://|mailto:|#|/)([^)\s]+)\)")
# GitHub refuses a release body over 125000 characters
BODY_MAX = 120_000


def sections(text: str) -> list:
    """[{version, date, agent, body}] in file order (newest first). `[Unreleased]` included."""
    out = []
    cur = None
    for line in text.splitlines():
        m = HEADING.match(line)
        if m:
            if cur:
                out.append(cur)
            rest = m.group("rest")
            a = AGENT.search(rest)
            d = DATE.search(rest)
            cur = {"version": m.group("version").strip(), "date": d.group(1) if d else None,
                   "agent": int(a.group("n")) if a else None, "lines": []}
            continue
        if cur is None:
            continue
        if line.startswith("## "):          # an unexpected level-2 heading ends the section too
            out.append(cur)
            cur = None
            continue
        cur["lines"].append(line)
    if cur:
        out.append(cur)
    for s in out:
        lines = s.pop("lines")
        # trailing link reference definitions (`[3.5.16]: https://…`) belong to the file, not the
        # release; so do the blank lines around the body
        while lines and (not lines[-1].strip() or LINK_REF.match(lines[-1])):
            lines.pop()
        while lines and not lines[0].strip():
            lines.pop(0)
        s["body"] = "\n".join(lines)
    return out


def norm(version: str) -> str:
    return version[1:] if version.startswith("v") else version


def find(text: str, version: str):
    """(section, next older section or None); (None, None) when the version is not there."""
    v = norm(version)
    secs = sections(text)
    for i, s in enumerate(secs):
        if s["version"] == v:
            older = next((o for o in secs[i + 1:] if o["version"].lower() != "unreleased"), None)
            return s, older
    return None, None


def agent_changed(sec: dict, older) -> bool:
    if sec.get("agent") is None:
        return False
    if older is None or older.get("agent") is None:
        return False
    return sec["agent"] != older["agent"]


def title(sec: dict, older) -> str:
    t = "WebTerm %s" % sec["version"]
    if agent_changed(sec, older):
        t += " · agent %d" % sec["agent"]
    return t


def absolutize(body: str, repo: str, tag: str) -> str:
    """Repository-relative links → https://github.com/<repo>/blob/<tag>/<path>."""
    return REL_LINK.sub(lambda m: "](https://github.com/%s/blob/%s/%s)" % (repo, tag, m.group(1)), body)


BLOCK_START = re.compile(r"^(\s*([-*+]|\d+[.)])\s|#|>|\||```|~~~|---\s*$|\s{4,}\S)")


def unwrap(body: str) -> str:
    """Join the hard-wrapped lines of a paragraph / list item into one line. CHANGELOG.md is wrapped
    at ~100 columns, and a release page renders every newline as a line break (like a comment),
    which would show each entry as a ragged column. List markers, headings, quotes, tables, code
    fences (whose content is kept verbatim) and blank lines all start a new line."""
    out = []
    fence = False
    for line in body.split("\n"):
        st = line.strip()
        if st.startswith("```") or st.startswith("~~~"):
            fence = not fence
            out.append(line)
            continue
        if fence or not st or not out:
            out.append(line)
            continue
        prev = out[-1].strip()
        joinable = (prev and not BLOCK_START.match(line) and not prev.startswith(("#", "|", "```", "~~~"))
                    and not re.match(r"^---\s*$", prev) and not out[-1].endswith("  "))
        if joinable:
            out[-1] = out[-1].rstrip() + " " + st
        else:
            out.append(line)
    return "\n".join(out)


def footer(tag: str, image: str, repo: str) -> str:
    pkg = "https://github.com/%s/pkgs/container/%s" % (repo, image.rsplit("/", 1)[-1])
    return "\n".join([
        "---",
        "",
        "**Image:** [`%s:%s`](%s) — `docker pull %s:%s`" % (image, tag, pkg, image, tag),
        "",
        "**Upgrade** an installation (backup, pull, pin by digest, health gate, automatic rollback):",
        "",
        "```sh",
        "cd /opt/webterm && sudo ./upgrade.sh %s" % tag,
        "```",
        "",
        "Fresh install, verification of the image signature and rollback: "
        "[docs/INSTALL.md](https://github.com/%s/blob/%s/docs/INSTALL.md) · "
        "[docs/RUNBOOK.md](https://github.com/%s/blob/%s/docs/RUNBOOK.md)." % (repo, tag, repo, tag),
    ])


def notes(sec: dict, tag: str, image: str, repo: str = "sm26449/webterm") -> str:
    body = unwrap(absolutize(sec["body"], repo, tag))
    if len(body) > BODY_MAX:
        cut = body.rfind("\n", 0, BODY_MAX)
        body = body[:cut if cut > 0 else BODY_MAX] + (
            "\n\n*…truncated — the full entry is in "
            "[CHANGELOG.md](https://github.com/%s/blob/%s/CHANGELOG.md).*" % (repo, tag))
    return body + "\n\n" + footer(tag, image, repo) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("version", help="3.5.16 or v3.5.16")
    ap.add_argument("--changelog", default=os.path.join(os.path.dirname(__file__), "..", "CHANGELOG.md"))
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--title", action="store_true", help="print the release title")
    g.add_argument("--notes", action="store_true", help="print body + footer (image, upgrade command)")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "sm26449/webterm"),
                    help="owner/name, for absolute links")
    ap.add_argument("--image", default=None, help="image name without tag (default ghcr.io/<repo>)")
    a = ap.parse_args(argv)
    with open(a.changelog, encoding="utf-8") as f:
        text = f.read()
    sec, older = find(text, a.version)
    if sec is None or not sec["body"].strip():
        print("no section for %s in %s" % (a.version, a.changelog), file=sys.stderr)
        return 1
    tag = "v" + norm(a.version)
    if a.title:
        print(title(sec, older))
    elif a.notes:
        image = (a.image or "ghcr.io/%s" % a.repo).lower()
        sys.stdout.write(notes(sec, tag, image, a.repo))
    else:
        print(sec["body"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
