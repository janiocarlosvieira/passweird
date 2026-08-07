#!/usr/bin/env python3
# tools/generate_vectors.py
# Passweird - Golden derivation vector generator
# Licensed under the GNU General Public License v3.0
"""
Generates tests/vectors/derivation-v1.json from the Python implementation.

Why this exists
---------------
Passweird's outputs are pure functions of the user's inputs, so a second
implementation (see ADR-0008) is only useful if it reproduces this one bit for
bit, permanently. "Almost right" is just wrong, and the user discovers it when
they are locked out of an account.

Hoping two implementations agree is not a strategy. This file makes agreement
mechanically checkable: Python is normative and emits the vectors, and every
implementation - including this one - must satisfy them for CI to pass.

Each case carries the **intermediate** values (master_hash, app_hash, the raw
HKDF bytes and the compliance nonce), not just the final output, so a failure
in another language localizes to a stage instead of reporting only "password
differs".

Note on circularity: these vectors are generated *from* the reference
implementation, so a bug here becomes the specification. That is what "normative
reference" means, and it is why the vectors complement the behavioural tests
rather than replacing them.

Usage:
    python tools/generate_vectors.py            # writes the file
    python tools/generate_vectors.py --check    # verifies it is up to date
"""
import argparse
import json
import pathlib
import string
import sys

from passweird import crypto

FORMAT_VERSION = 1
OUTPUT = pathlib.Path(__file__).resolve().parent.parent / "tests" / "vectors" / "derivation-v1.json"

# Multi-byte UTF-8 on purpose: encoding must match across languages, and this is
# where a platform that quietly uses UTF-16 or a system charset would diverge.
UNICODE_MASTER = "señhã-mestra-ç∂é"
UNICODE_CONTEXT = "地球-サーバー"


def _charset(use_upper=True, use_lower=True, use_digits=True, use_special=True):
    """Mirrors generate_password_hkdf's charset construction (crypto.py:169-173).

    Order is load-bearing: the charset is built by concatenation and indexed by
    `byte % len`, so any reordering changes every password ever generated.
    """
    return (
        (string.ascii_lowercase if use_lower else "")
        + (string.ascii_uppercase if use_upper else "")
        + (string.digits if use_digits else "")
        + ("!@#$%^&*()_+-=." if use_special else "")
    )


def _replay_password(master_hash, app_hash, length, temporal_salt, classes):
    """
    Replays the compliance loop to expose the nonce and raw bytes that
    generate_password_hkdf keeps internal, then self-checks the reconstruction
    against the real function. If this generator ever drifts from crypto.py, the
    assertion below fails here rather than silently emitting wrong vectors.
    """
    charset = _charset(**classes)
    prk = master_hash.encode()
    nonce = 0
    while True:
        info = f"{app_hash}:{length}:{temporal_salt}:{nonce}".encode()
        raw = crypto.hkdf_expand(prk, info, length)
        password = "".join(charset[b % len(charset)] for b in raw)

        lowers = string.ascii_lowercase if classes["use_lower"] else ""
        uppers = string.ascii_uppercase if classes["use_upper"] else ""
        digits = string.digits if classes["use_digits"] else ""
        specials = "!@#$%^&*()_+-=." if classes["use_special"] else ""

        ok = (
            (any(c in lowers for c in password) if classes["use_lower"] else True)
            and (any(c in uppers for c in password) if classes["use_upper"] else True)
            and (any(c in digits for c in password) if classes["use_digits"] else True)
            and (any(c in specials for c in password) if classes["use_special"] else True)
        )
        if ok:
            return nonce, raw.hex(), password
        nonce += 1


def _password_case(label, master_password, context, length=18, temporal_salt="", **classes):
    classes = {
        "use_upper": classes.get("use_upper", True),
        "use_lower": classes.get("use_lower", True),
        "use_digits": classes.get("use_digits", True),
        "use_special": classes.get("use_special", True),
    }
    master_hash = crypto.modified_hash(master_password)
    app_hash = crypto.modified_hash(context)

    nonce, raw_hex, replayed = _replay_password(
        master_hash, app_hash, length, temporal_salt, classes
    )
    expected = crypto.generate_password(
        "v2", master_hash, app_hash, length, temporal_salt=temporal_salt, **classes
    )
    # Self-check: the replay must agree with the real implementation.
    assert replayed == expected, f"{label}: replay diverged from generate_password"

    return {
        "label": label,
        "master_password": master_password,
        "context": context,
        "length": length,
        "temporal_salt": temporal_salt,
        **classes,
        "master_hash": master_hash,
        "app_hash": app_hash,
        "compliance_nonce": nonce,
        "raw_hkdf_hex": raw_hex,
        "expected_password": expected,
    }


def _find_compliance_loop_cases(target=3, max_scan=400):
    """
    Finds contexts where the compliance loop actually advances the nonce.

    This is a live branch, not a theoretical one - at length 8 it fires often -
    and it is the single easiest thing for a second implementation to get wrong
    while still producing plausible-looking passwords.
    """
    found = []
    master_hash = crypto.modified_hash("compliance-probe")
    classes = {"use_upper": True, "use_lower": True, "use_digits": True, "use_special": True}
    for i in range(max_scan):
        context = f"ctx-{i}"
        app_hash = crypto.modified_hash(context)
        nonce, _, _ = _replay_password(master_hash, app_hash, 8, "", classes)
        if nonce > 0:
            found.append((context, nonce))
            if len(found) >= target:
                break
    return found


def build():
    vectors = {
        "format_version": FORMAT_VERSION,
        "engine_version": "v2",
        "description": (
            "Golden derivation vectors for Passweird. Python is the normative "
            "implementation (ADR-0008); every port must reproduce these exactly. "
            "Intermediate values are included so a failure localizes to a stage."
        ),
        "encoding_notes": [
            "All strings are UTF-8. Hashes are lowercase hex.",
            "Password indexing iterates raw bytes as UNSIGNED 0..255. On the JVM "
            "Byte is signed (-128..127) and % preserves the sign, which silently "
            "produces a different but still plausible-looking password.",
            "Charset order is lowercase + uppercase + digits + \"!@#$%^&*()_+-=.\" "
            "and is load-bearing.",
            "TOTP secrets are RFC 4648 Base32 with padding stripped.",
        ],
    }

    # --- modified_hash: the entry point of every derivation ---
    vectors["modified_hash"] = [
        {"label": "ascii", "input": "minhasenha", "expected": crypto.modified_hash("minhasenha")},
        {"label": "empty", "input": "", "expected": crypto.modified_hash("")},
        {"label": "unicode-multibyte", "input": UNICODE_MASTER,
         "expected": crypto.modified_hash(UNICODE_MASTER)},
        {"label": "long", "input": "x" * 512, "expected": crypto.modified_hash("x" * 512)},
        {"label": "spaces-and-punctuation", "input": "correct horse battery staple!",
         "expected": crypto.modified_hash("correct horse battery staple!")},
    ]

    # --- blend_secondary_factor: keyfile / FIDO2 blending ---
    vectors["blend_secondary_factor"] = [
        {
            "label": label,
            "base_hash": crypto.modified_hash("master"),
            "factor_hex": factor.hex(),
            "expected": crypto.blend_secondary_factor(crypto.modified_hash("master"), factor),
        }
        for label, factor in [
            ("short", b"physical factor bytes"),
            ("empty", b""),
            ("high-bytes", bytes(range(256))),
        ]
    ]

    # --- hkdf_expand: including lengths that cross the 64-byte block boundary ---
    prk = crypto.modified_hash("master").encode()
    vectors["hkdf_expand"] = [
        {
            "label": label,
            "prk_utf8": crypto.modified_hash("master"),
            "info_utf8": info,
            "length": length,
            "expected_hex": crypto.hkdf_expand(prk, info.encode(), length).hex(),
        }
        for label, info, length in [
            ("single-byte", "ctx:test", 1),
            ("exactly-one-block", "ctx:test", 64),
            ("crosses-block-boundary", "ctx:test", 65),
            ("three-blocks", "ctx:test", 200),
            ("unicode-info", f"{UNICODE_CONTEXT}:ssl_seed:", 32),
        ]
    ]

    # --- passwords: the dominant use case and the biggest divergence risk ---
    cases = [
        _password_case("default-18-all-classes", "minhasenha", "github"),
        _password_case("min-length-8", "minhasenha", "github", length=8),
        _password_case("long-64", "minhasenha", "github", length=64),
        _password_case("with-temporal-salt", "minhasenha", "github",
                       temporal_salt="cavalo bateria grampo correto girassol trombone"),
        _password_case("unicode-master", UNICODE_MASTER, "github"),
        _password_case("unicode-context", "minhasenha", UNICODE_CONTEXT),
        _password_case("unicode-both-and-salt", UNICODE_MASTER, UNICODE_CONTEXT,
                       temporal_salt=UNICODE_MASTER),
        _password_case("no-special", "minhasenha", "github", use_special=False),
        _password_case("no-digits", "minhasenha", "github", use_digits=False),
        _password_case("no-upper", "minhasenha", "github", use_upper=False),
        _password_case("no-lower", "minhasenha", "github", use_lower=False),
        _password_case("digits-only-min-6", "minhasenha", "github", length=6,
                       use_upper=False, use_lower=False, use_special=False),
        _password_case("lowercase-only", "minhasenha", "github",
                       use_upper=False, use_digits=False, use_special=False),
    ]
    for context, nonce in _find_compliance_loop_cases():
        cases.append(
            _password_case(
                f"compliance-loop-{context}-nonce-{nonce}", "compliance-probe", context, length=8
            )
        )
    vectors["password"] = cases

    # --- TOTP ---
    vectors["totp"] = [
        {
            "label": label,
            "master_password": mp,
            "context": ctx,
            "temporal_salt": salt,
            "master_hash": crypto.modified_hash(mp),
            "app_hash": crypto.modified_hash(ctx),
            "expected_base32": crypto.generate_deterministic_totp_secret(
                crypto.modified_hash(mp), crypto.modified_hash(ctx), salt
            ),
        }
        for label, mp, ctx, salt in [
            ("basic", "minhasenha", "github", ""),
            ("with-temporal", "minhasenha", "github", "2026-rotation"),
            ("unicode", UNICODE_MASTER, UNICODE_CONTEXT, ""),
        ]
    ]

    # --- log summaries: needed by --audit and the ADR-0007 verification ---
    vectors["summaries"] = [
        {
            "label": "summarize_hash",
            "input": crypto.modified_hash("master"),
            "expected": crypto.summarize_hash(crypto.modified_hash("master")),
        },
        {
            "label": "summarize_password_hash",
            "input": "SomePassword123!",
            "expected": crypto.summarize_password_hash("SomePassword123!"),
        },
    ]

    return vectors


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--check", action="store_true",
                        help="verify the committed file matches what would be generated")
    args = parser.parse_args()

    vectors = build()
    rendered = json.dumps(vectors, indent=2, ensure_ascii=False, sort_keys=False) + "\n"

    if args.check:
        if not OUTPUT.exists():
            print(f"MISSING: {OUTPUT}", file=sys.stderr)
            return 1
        if OUTPUT.read_text(encoding="utf-8") != rendered:
            print(
                f"STALE: {OUTPUT} does not match the current implementation.\n"
                "If a derivation changed on purpose, regenerate it and treat the diff "
                "as the compatibility break it is.",
                file=sys.stderr,
            )
            return 1
        print(f"OK: {OUTPUT} is up to date")
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(rendered, encoding="utf-8")
    print(f"Wrote {OUTPUT}")
    total = 0
    for name, group in vectors.items():
        # Only groups of case objects; encoding_notes is prose, not test data.
        if isinstance(group, list) and group and isinstance(group[0], dict):
            print(f"  {name}: {len(group)} cases")
            total += len(group)
    print(f"  total: {total} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
