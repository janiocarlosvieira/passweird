#!/usr/bin/env python3
# tools/generate_vectors_v3.py
# Passweird - Golden vector generator for the v3 engine (ADR-0009)
# Licensed under the GNU General Public License v3.0
"""
Generates tests/vectors/v3/*.json from the Python implementation.

Same contract as tools/generate_vectors.py: Python is normative, the files are
what a port must reproduce, and CI fails if they are stale.

    python tools/generate_vectors_v3.py            # rewrite the files
    python tools/generate_vectors_v3.py --check    # fail if any is stale

Each builder lives next to the code it pins and is registered in BUILDERS.
"""
import argparse
import json
import pathlib
import sys

from passweird.v3 import canon

OUTPUT_DIR = pathlib.Path(__file__).resolve().parent.parent / "tests" / "vectors" / "v3"
FORMAT_VERSION = 1


# --- §1: canonical form ------------------------------------------------------

def _canon_case(field, value, note=None, **extra):
    """Runs the real function: the vector records what it does, accept or reject."""
    functions = {
        "master": canon.master, "access_password": canon.access_password,
        "boost": canon.boost, "user_id": canon.user_id, "login": canon.login,
        "site": canon.site, "counter": canon.counter, "classes": canon.classes,
    }
    repeat = extra.pop("repeat", None)
    if repeat:
        # Long inputs are stored as (unit, count) so the file stays readable.
        case = {"field": field, "input_repeat": [value, repeat], **extra}
        value = value * repeat
    else:
        case = {"field": field, "input": value, **extra}
    if note:
        case["note"] = note
    try:
        if field == "length":
            case["expected"] = canon.length(value, extra["classes"])
        else:
            result = functions[field](value)
            if repeat:
                assert result == value
                case["expected_same_as_input"] = True
            else:
                case["expected"] = result
    except canon.CanonicalError:
        case["reject"] = True
    return case


def build_canonical():
    c = _canon_case
    nfd_e = "café"          # e + combining acute
    cases = [
        # master: NFC and nothing else
        c("master", "correct horse"),
        c("master", "  leading and trailing kept  ", "no trimming"),
        c("master", "MiXeD Case", "no case change"),
        c("master", nfd_e, "NFD input becomes NFC"),
        c("master", "café", "already NFC, same bytes as the previous case"),
        c("master", "ﬁ", "NFC, not NFKC: the ligature is kept"),
        c("master", "señhã-mestra-ç∂é"),
        c("master", "地球"),
        c("master", ""),
        c("master", "line\nbreak", "C0 control"),
        c("master", "tab\tinside", "C0 control"),
        c("master", "nul\u0000byte"),
        c("master", "del\u007f"),
        c("master", "x", "exactly the LP limit", repeat=65535),
        c("master", "x", "one byte over the LP limit", repeat=65536),
        c("master", "é", "65536 bytes in UTF-8", repeat=32768),
        c("access_password", "abre o diário"),
        c("access_password", ""),
        # boost: whitespace and ASCII case are not part of the secret
        c("boost", "cavalo bateria grampo correto girassol"),
        c("boost", "  Cavalo   Bateria\tGrampo \n correto  GIRASSOL  ", "phone-keyboard spelling of the same boost"),
        c("boost", "cavalo bateria grampo", "no-break and em space are whitespace"),
        c("boost", "ÁGUA É Vida", "only ASCII letters are lowered"),
        c("boost", "agua" + "́", "NFC applied"),
        c("boost", "   \t  "),
        c("boost", ""),
        c("boost", "a\u0000b"),
        c("boost", "a​b", "zero-width space is not White_Space: kept"),
        # user id
        c("user_id", "  Fulano.Silva@Example.COM "),
        c("user_id", "fulano.silva@example.com"),
        c("user_id", "JOSÉ@exemplo.br", "non-ASCII letters keep their case"),
        c("user_id", "   "),
        c("user_id", "a\nb"),
        # login
        c("login", ""),
        c("login", "   ", "trims to empty, which means no login"),
        c("login", " Fulano "),
        c("login", "Fulano@Example.com"),
        c("login", "a\u007fb"),
        # site
        c("site", "github.com"),
        c("site", "https://WWW.GitHub.com:443/login?x=1"),
        c("site", "  GitHub.COM.  "),
        c("site", "http://user:pass@example.org:8080/path#frag"),
        c("site", "accounts.google.com", "no public suffix list: subdomain is kept"),
        c("site", "www.example.com"),
        c("site", "www.www.example.com", "every leading www. is stripped, so the form is a fixed point"),
        c("site", "www", "nothing to strip"),
        c("site", "www.", "trailing dot goes first, then nothing to strip"),
        c("site", "ufpb-sigaa", "free-form context"),
        c("site", "my_server.lan"),
        c("site", "192.168.0.1:8443"),
        c("site", "ｇｉｔｈｕｂ.com", "NFKC folds full-width letters"),
        c("site", "xn--bcher-kva.de", "the accepted form of a non-ASCII host"),
        c("site", "bücher.de", "non-ASCII host is rejected"),
        c("site", "地球-サーバー"),
        c("site", "example.com/"),
        c("site", "example.com?x"),
        c("site", "example.com#x"),
        c("site", "ssh://git@host.example:22"),
        c("site", "host.example:"),
        c("site", ""),
        c("site", "   "),
        c("site", "https://"),
        c("site", "minha conta", "inner whitespace"),
        c("site", "-leading-hyphen.com"),
        c("site", "trailing-hyphen-"),
        c("site", ".hidden"),
        c("site", "a"),
        c("site", "a!b"),
        c("site", "[::1]:8080"),
        c("site", "user@"),
        # counter
        c("counter", 1), c("counter", 2**32 - 1), c("counter", 0), c("counter", -1), c("counter", 2**32),
        # classes
        c("classes", 15), c("classes", 4), c("classes", 0), c("classes", 16),
        # length depends on the classes
        c("length", 18, classes=15), c("length", 8, classes=15), c("length", 7, classes=15),
        c("length", 128, classes=15), c("length", 129, classes=15),
        c("length", 6, classes=4, note="digits only: minimum is 6"),
        c("length", 5, classes=4),
        c("length", 6, classes=5, note="digits plus lower is not digits only"),
    ]
    return {
        "format_version": FORMAT_VERSION,
        "spec": "ADR-0009 §1",
        "description": (
            "Canonical form of every input. A case has either 'expected' or "
            "'reject': true; a port must reject exactly the same inputs."
        ),
        "whitespace_codepoints": sorted(ord(ch) for ch in canon.WHITESPACE),
        "cases": cases,
    }


BUILDERS = {
    "canonical.json": build_canonical,
}


def render(data):
    return json.dumps(data, indent=1, ensure_ascii=False, sort_keys=False) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Generate or check the v3 golden vectors.")
    parser.add_argument("--check", action="store_true",
                        help="verify the committed files match what would be generated")
    args = parser.parse_args()

    stale = []
    for name, builder in BUILDERS.items():
        path = OUTPUT_DIR / name
        rendered = render(builder())
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != rendered:
                stale.append(name)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
        print(f"Wrote {path}")

    if args.check:
        if stale:
            print(
                "STALE: " + ", ".join(stale) + " do not match the current implementation.\n"
                "If a derivation changed on purpose, regenerate and treat the diff as the "
                "compatibility break it is.",
                file=sys.stderr,
            )
            return 1
        print(f"OK: {len(BUILDERS)} v3 vector file(s) up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
