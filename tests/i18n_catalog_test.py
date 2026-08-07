"""Cataloagele de limbă sunt simetrice, iar cheile folosite în UI există.

Paritatea era ținută cu disciplină, nu cu unelte: `strings` e tipat `Record<string, string>`,
deci TypeScript nu poate ști nimic despre chei. Am verificat: un build cu o cheie prezentă
doar într-un catalog ȘI un `t('cheie.cu.typo')` trece verde — iar utilizatorul vede numele
cheii în interfață, în ambele limbi.

Testul verifică trei lucruri, toate ieftine:
  1. cele două cataloage au exact aceleași chei;
  2. fiecare `t('literal')` din componente există în catalog;
  3. interpolările `{var}` sunt aceleași în ambele limbi (altfel o limbă randează `{name}`).

Cheile construite dinamic (`t('color.' + x)`) nu pot fi verificate static și sunt sărite —
sunt recunoscute după faptul că literalul se termină cu punct sau conține concatenare.
"""
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SRC = os.path.join(ROOT, "frontend", "src")

ok = 0
total = 0


def check(name, cond, detail=""):
    global ok, total
    total += 1
    ok += 1 if cond else 0
    print(f"  {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  --  {detail}"))


KEY_RE = re.compile(r"^\s*'([a-zA-Z0-9_.]+)':\s*(.*)$", re.M)
VAR_RE = re.compile(r"\{([a-zA-Z0-9_]+)\}")

# Formele de plural pe care CLDR le cere pentru fiecare limbă. Engleza are două (one/other),
# româna trei (1 / 2–19 / 20+ cu „de"). Deci cataloagele NU pot fi identice cheie-cu-cheie
# pe familiile de plural — comparăm bazele, şi cerem ca fiecare limbă să aibă exact formele
# de care are ea nevoie. `t()` alege forma prin Intl.PluralRules.
PLURAL_FORMS = {"en": {"one", "other"}, "ro": {"one", "few", "other"}}
_SUFFIXES = {"one", "two", "few", "many", "other", "zero"}


def split_plural(key):
    """('a.b.one') → ('a.b', 'one');  ('a.b') → ('a.b', None)"""
    base, _, last = key.rpartition(".")
    return (base, last) if base and last in _SUFFIXES else (key, None)


def catalog(lang):
    path = os.path.join(SRC, "lang", f"{lang}.ts")
    with open(path, encoding="utf-8") as f:
        return dict(KEY_RE.findall(f.read()))


def main():
    en, ro = catalog("en"), catalog("ro")
    check("catalogul en nu e gol (testul nu e o glumă)", len(en) > 100, str(len(en)))

    # familiile de plural se compară pe bază, nu pe variantă
    base_en = {split_plural(k)[0] for k in en}
    base_ro = {split_plural(k)[0] for k in ro}
    only_en = sorted(base_en - base_ro)
    only_ro = sorted(base_ro - base_en)
    check("aceleași chei (familiile de plural comparate pe bază)", not only_en and not only_ro,
          f"doar en: {only_en[:8]} | doar ro: {only_ro[:8]}")

    # fiecare familie de plural trebuie să aibă exact formele cerute de limba ei
    for lang, cat in (("en", en), ("ro", ro)):
        fams = {}
        for k in cat:
            b, sfx = split_plural(k)
            if sfx:
                fams.setdefault(b, set()).add(sfx)
        bad = {b: sorted(f) for b, f in fams.items() if f != PLURAL_FORMS[lang]}
        check(f"{lang}: formele de plural sunt complete ({sorted(PLURAL_FORMS[lang])})",
              not bad, str(bad))

    # duplicate: TypeScript le semnalează (TS1117), dar numai dacă cineva rulează build-ul
    for lang in ("en", "ro"):
        with open(os.path.join(SRC, "lang", f"{lang}.ts"), encoding="utf-8") as f:
            keys = [m[0] for m in KEY_RE.findall(f.read())]
        dups = sorted({k for k in keys if keys.count(k) > 1})
        check(f"fără chei duplicate în {lang}.ts", not dups, str(dups[:8]))

    # interpolările trebuie să coincidă, altfel o limbă randează literalmente `{name}`
    mismatched = []
    for k in set(en) & set(ro):
        if VAR_RE.findall(en[k]) and sorted(VAR_RE.findall(en[k])) != sorted(VAR_RE.findall(ro[k])):
            mismatched.append(k)
    check("aceleași interpolări {var} în ambele limbi", not mismatched, str(sorted(mismatched)[:8]))

    # fiecare t('literal') folosit trebuie să existe
    used = set()
    for base, _, files in os.walk(SRC):
        if os.path.join("src", "lang") in base:
            continue
        for fn in files:
            if not fn.endswith((".ts", ".tsx")):
                continue
            with open(os.path.join(base, fn), encoding="utf-8") as f:
                for m in re.finditer(r"\bt\(\s*'([a-zA-Z0-9_.]+)'\s*[,)]", f.read()):
                    key = m.group(1)
                    # chei dinamice (`t('color.' + c)`) şi apeluri către alt `t`
                    if key.endswith(".") or "." not in key:
                        continue
                    used.add(key)
    # o cheie folosită cu `count` trăieşte doar ca variante `.one`/`.other`
    have = set(en) | {split_plural(k)[0] for k in en if split_plural(k)[1]}
    missing = sorted(used - have)
    check("fiecare t('cheie') folosită există în catalog", not missing, str(missing[:8]))

    # Codurile de eroare trimise de server trebuie să existe în catalog. Fără garda asta,
    # `errText` cade tăcut pe mesajul englezesc şi nimeni nu observă că traducerea lipseşte —
    # exact tiparul „poartă care raportează verde fără să verifice".
    import re as _re
    api_src = open(os.path.join(ROOT, "gateway", "app", "api.py"), encoding="utf-8").read()
    codes = set(_re.findall(r'ApiError\(\s*\d{3}\s*,\s*"([a-zA-Z0-9_.]+)"', api_src))
    check("serverul chiar trimite coduri (testul nu e gol)", len(codes) > 5, str(len(codes)))
    for lang, cat in (("en", en), ("ro", ro)):
        missing = sorted(c for c in codes if ("err." + c) not in cat)
        check(f"{lang}: fiecare cod de eroare are cheie în catalog", not missing, str(missing[:8]))

    print(f"\n{ok}/{total} teste trecute")
    return ok == total


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
