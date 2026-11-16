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

from passweird.v3 import canon, derive, journal, keys

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
        c("boost", "país", "diacritics are removed: same boost as the next case"),
        c("boost", "pais"),
        c("boost", "açucar", "cedilla is U+0327, inside the removed block"),
        c("boost", "acucar"),
        c("boost", "açúcar coração avó avô maçã pão", "acute, tilde, circumflex, cedilla"),
        c("boost", "acucar coracao avo avo maca pao"),
        c("boost", "ÁGUA É Vida", "marks go before the lowering, so this is 'agua e vida'"),
        c("boost", "agua" + "́", "a mark typed as a separate code point"),
        c("boost", "ÃO", "decomposed input"),
        c("boost", "ǘ ệ", "several marks on one letter are all removed"),
        c("boost", "smørrebrød straße", "no decomposition: kept, and not lowered beyond ASCII"),
        c("boost", "a᪰b", "a combining mark outside U+0300-U+036F is kept"),
        c("boost", "̧́", "only marks: empty after removal"),
        c("boost", " ́ ", "a lone mark between spaces: empty after removal"),
        c("boost", "a ́ b", "a lone mark between words leaves ONE space: marks go before the collapse"),
        c("boost", "á ̧ ́b̃", "marks on both sides of the gap"),
        c("boost", "́ pais ́", "marks at the ends do not shield the spaces from trimming"),
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
        "boost_removed_codepoints": {"first": 0x0300, "last": 0x036F,
                                     "count": len(canon.COMBINING_DIACRITICS)},
        "cases": cases,
    }


# --- §2-§5: stretching, expansion, sampling ----------------------------------

# Three full-cost Argon2id cases. Everything else starts from a given K0 so a
# port does not pay 256 MiB per case.
STRETCH_INPUTS = [
    ("ascii", "minha senha mestra", "cavalo bateria grampo correto girassol", "fulano@example.com"),
    ("unicode", "señhã-mestra-ç∂é 地球", "água pão maçã coração avó", "José@Exemplo.BR"),
    ("needs-canonicalisation", "café ", "  Cavalo   Bateria\tGrampo ", "  Fulano@Example.COM "),
]

FIXED_K0 = bytes(range(64))
FIXED_KEYFILE = bytes(range(100, 132))


def _stretch_case(label, master, boost, user_id):
    m, b, u = canon.master(master), canon.boost(boost), canon.user_id(user_id)
    k0 = derive.stretch(m, b, u)
    prk = derive.extract(k0)
    return {
        "label": label,
        "master": master, "boost": boost, "user_id": user_id,
        "canonical": {"master": m, "boost": b, "user_id": u},
        "argon2_password_hex": derive.stretch_input(m, b).hex(),
        "argon2_salt_hex": derive.salt_for(u).hex(),
        "k0_hex": bytes(k0).hex(),
        "prk_none_hex": bytes(prk).hex(),
        "fingerprint": derive.fingerprint(prk),
        "password_github": derive.password(prk, "github.com"),
    }


def _password_case(prk, label, site, login="", counter=1, length=18, classes=15):
    extra = derive.password_extra(length, classes)
    stream = derive.okm(prk, "password", derive.PASSWORD_STREAM_BYTES, site, login, counter, extra)
    pw, trace = derive.sample_password(stream, length, classes)
    assert pw == derive.password(prk, site, login, counter, length, classes)
    return {
        "label": label, "site": site, "login": login, "counter": counter,
        "length": length, "classes": classes,
        "info_hex": derive.info("password", site, login, counter, extra).hex(),
        "stream_first_64_hex": stream[:64].hex(),
        "stream_sha256": __import__("hashlib").sha256(stream).hexdigest(),
        **trace,
        "expected_password": pw,
    }


def _find(prk, predicate, limit=5000, **kw):
    """First site name whose derivation satisfies predicate(trace)."""
    for i in range(limit):
        case = _password_case(prk, "", f"probe-{i}.example", **kw)
        if predicate(case):
            return case
    raise AssertionError("no probe site satisfied the predicate")


def build_derivation():
    prk_none = derive.extract(FIXED_K0)
    prk_key = derive.extract(FIXED_K0, derive.FACTOR_KEYFILE, FIXED_KEYFILE)

    passwords = [
        _password_case(prk_none, "default", "github.com"),
        _password_case(prk_none, "with-login", "github.com", login="fulano"),
        _password_case(prk_none, "counter-2", "github.com", counter=2),
        _password_case(prk_none, "counter-max", "github.com", counter=2**32 - 1),
        _password_case(prk_none, "length-8", "github.com", length=8),
        _password_case(prk_none, "length-128", "github.com", length=128),
        _password_case(prk_none, "no-specials", "github.com", classes=7),
        _password_case(prk_none, "no-digits", "github.com", classes=11),
        _password_case(prk_none, "no-upper", "github.com", classes=13),
        _password_case(prk_none, "no-lower", "github.com", classes=14),
        _password_case(prk_none, "digits-only-6", "github.com", length=6, classes=4),
        _password_case(prk_none, "lower-only", "github.com", classes=1),
        _password_case(prk_none, "specials-only", "github.com", classes=8),
        _password_case(prk_none, "free-form-site", "ufpb-sigaa"),
        _password_case(prk_none, "punycode-site", "xn--bcher-kva.de", login="josé"),
        _password_case(prk_key, "keyfile-factor", "github.com"),
    ]
    probe = _find(prk_none, lambda c: c["candidate_rejections"] >= 3, length=8)
    probe["label"] = "class-rejection-3-or-more"
    passwords.append(probe)
    probe = _find(prk_none, lambda c: c["candidate_rejections"] == 0 and c["byte_rejections"] == 0)
    probe["label"] = "no-rejection-at-all"
    passwords.append(probe)
    probe = _find(prk_none, lambda c: c["byte_rejections"] >= 6)
    probe["label"] = "byte-rejection-6-or-more"
    passwords.append(probe)

    site_args = dict(site="example.org", login="fulano", counter=3)
    purposes = []
    for purpose, prk_name, length, kwargs in [
        ("totp", "keyfile", 20, site_args),
        ("ssh-ed25519", "none", 32, site_args),
        ("ssh-checkint", "none", 4, site_args),
        ("tls-ed25519", "none", 32, site_args),
        ("tls-serial", "none", 19, site_args),
        ("tls-rsa-p", "none", 128, dict(site_args, extra=derive.rsa_extra(2048, 0))),
        ("tls-rsa-p", "none", 128, dict(site_args, extra=derive.rsa_extra(2048, 1))),
        ("tls-rsa-q", "none", 128, dict(site_args, extra=derive.rsa_extra(2048, 0))),
        ("tls-rsa-p", "none", 256, dict(site_args, extra=derive.rsa_extra(4096, 0))),
        ("pgp-ed25519", "none", 32, site_args),
        ("pgp-ctime", "none", 4, site_args),
        ("fingerprint", "none", 3, {}),
        ("journal-recovery", "none", 32, dict(extra=bytes(range(16)))),
        ("keyfile-wrap", "none", 32, {}),
    ]:
        prk = prk_key if prk_name == "keyfile" else prk_none
        extra = kwargs.get("extra", b"")
        purposes.append({
            "purpose": purpose, "prk": prk_name, "length": length,
            "site": kwargs.get("site", ""), "login": kwargs.get("login", ""),
            "counter": kwargs.get("counter", 0), "extra_hex": extra.hex(),
            "info_hex": derive.info(purpose, **kwargs).hex(),
            "expected_hex": derive.okm(prk, purpose, length, **kwargs).hex(),
        })

    return {
        "format_version": FORMAT_VERSION,
        "spec": "ADR-0009 §2-§5",
        "alg": derive.ALG,
        "argon2": {
            "type": "argon2id", "version": derive.ARGON2_VERSION,
            "time_cost": derive.ARGON2_TIME_COST, "memory_kib": derive.ARGON2_MEMORY_KIB,
            "parallelism": derive.ARGON2_PARALLELISM, "tag_bytes": derive.K0_BYTES,
        },
        "encoding_notes": [
            "LP(x) = U16 big-endian length || bytes; strings are UTF-8.",
            "Sampling reads the stream as UNSIGNED bytes 0..255.",
            "Charset order is lower + upper + digits + \"!@#$%^&*()_+-=.\" and is load-bearing.",
            "A candidate password missing an enabled class is discarded whole; the next one "
            "continues from the same stream position.",
        ],
        "encoding": [
            {"lp_of_utf8": text, "expected_hex": derive.lp(text).hex()}
            for text in ["", "a", "ç", "地球", derive.ALG]
        ],
        "stretch": [_stretch_case(*args) for args in STRETCH_INPUTS],
        "fixed_k0_hex": FIXED_K0.hex(),
        "fixed_keyfile_hex": FIXED_KEYFILE.hex(),
        "extract": [
            {"kind": "none", "factor_hex": "",
             "factor_tag_hex": derive.factor_tag().hex(), "prk_hex": bytes(prk_none).hex()},
            {"kind": "keyfile", "factor_hex": FIXED_KEYFILE.hex(),
             "factor_tag_hex": derive.factor_tag(derive.FACTOR_KEYFILE, FIXED_KEYFILE).hex(),
             "prk_hex": bytes(prk_key).hex()},
        ],
        "purposes": purposes,
        "passwords": passwords,
        "fingerprint": {"prk": "none", "expected": derive.fingerprint(prk_none)},
        "totp": [
            {"prk": "none", "site": "github.com", "login": "", "counter": 1,
             "expected_base32": derive.totp_secret(prk_none, "github.com")},
            {"prk": "keyfile", "site": "example.org", "login": "fulano", "counter": 3,
             "expected_base32": derive.totp_secret(prk_key, "example.org", "fulano", 3)},
        ],
    }


# --- §6-§7: key hierarchy, streams and merge ---------------------------------

DEV_A, DEV_B, DEV_C = "aa" * 16, "bb" * 16, "cc" * 16
JOURNAL_ID = bytes(range(0x10, 0x20))
DEK = bytes(range(0x40, 0x60))


def _put(ts, counter=1, length=18, classes=15, parents=(), site="example.org", login="", **free):
    return journal.make_put(ts, site, login, counter, length, classes, parents,
                            free.get("notes", ""), free.get("totp", ""), free.get("keys", ()), free.get("x"))


def _del(ts, parents=(), site="example.org", login=""):
    return journal.make_delete(ts, site, login, parents)


def _scenario(name, why, streams):
    records = []
    for device, items in streams.items():
        for seq, record in enumerate(items):
            records.append(dict(record, device=device, seq=seq))
    folded = journal.fold(records)
    return {
        "name": name, "why": why, "streams": streams,
        "expected": [folded[key].as_dict() for key in sorted(folded)],
    }


def build_journal():
    prk_none = derive.extract(FIXED_K0)
    small = (1024, 1, 1)
    salt, nonce = bytes(range(0x80, 0xA0)), bytes(range(0xC0, 0xCC))
    keys_small = keys.build_keys_file(JOURNAL_ID, DEK, "abre o diário", small, salt, nonce)
    keys_default = keys.build_keys_file(JOURNAL_ID, DEK, "abre o diário", keys.DEFAULT_ACCESS_PARAMS, salt, nonce)
    recovery = keys.build_recovery(JOURNAL_ID, DEK, prk_none, nonce)
    keyfile = keys.build_keyfile(prk_none, FIXED_KEYFILE, nonce)

    stream_records = [
        _put(1_700_000_000_000, notes="conta principal", totp="Aegis no celular",
             keys=["YubiKey 5C azul", "reserva no cofre"], x={"origem": "v2"}),
        _put(1_700_000_000_500, counter=2, parents=[[DEV_A, 0]], notes="ção ✓ " + "n" * 300),
        _del(1_700_000_001_000, parents=[[DEV_A, 1]]),
    ]
    stream_nonces = [bytes([i]) * 12 for i in (1, 2, 3)]
    stream = journal.build_stream(DEK, JOURNAL_ID, bytes.fromhex(DEV_A), stream_records, stream_nonces)

    a0 = _put(100, counter=3)
    scenarios = [
        _scenario("linear-single-device", "one device, each record lists the previous one", {
            DEV_A: [_put(100), _put(200, counter=2, parents=[[DEV_A, 0]]),
                    _put(300, counter=2, parents=[[DEV_A, 1]], notes="trocada em março")],
        }),
        _scenario("identical-concurrent-bump",
                  "both devices go 3 -> 4 offline: same password, nothing to resolve", {
            DEV_A: [a0, _put(200, counter=4, parents=[[DEV_A, 0]])],
            DEV_B: [_put(210, counter=4, parents=[[DEV_A, 0]])],
        }),
        _scenario("divergent-bump",
                  "A went to 5, B to 4, B wrote last: counter is the maximum and the entry is in conflict", {
            DEV_A: [a0, _put(200, counter=4, parents=[[DEV_A, 0]]), _put(300, counter=5, parents=[[DEV_A, 1]])],
            DEV_B: [_put(400, counter=4, parents=[[DEV_A, 0]], notes="escrito por B")],
        }),
        _scenario("divergent-bump-resolved", "a record listing both heads clears the conflict", {
            DEV_A: [a0, _put(200, counter=4, parents=[[DEV_A, 0]]), _put(300, counter=5, parents=[[DEV_A, 1]])],
            DEV_B: [_put(400, counter=4, parents=[[DEV_A, 0]])],
            DEV_C: [_put(500, counter=5, parents=[[DEV_A, 2], [DEV_B, 0]])],
        }),
        _scenario("concurrent-length-change",
                  "same counter, different length: derivation differs, so it is a conflict", {
            DEV_A: [a0, _put(200, counter=3, length=20, parents=[[DEV_A, 0]])],
            DEV_B: [_put(250, counter=3, length=16, parents=[[DEV_A, 0]])],
        }),
        _scenario("conflict-heads-in-merge-order",
                  "heads and candidates follow (ts, device, seq), not device id: bb… comes first here", {
            DEV_A: [a0, _put(300, counter=5, parents=[[DEV_A, 0]])],
            DEV_B: [_put(200, counter=4, parents=[[DEV_A, 0]])],
        }),
        _scenario("concurrent-notes-only", "free-form fields differ: last writer wins, no conflict", {
            DEV_A: [a0, _put(200, counter=3, parents=[[DEV_A, 0]], notes="nota de A")],
            DEV_B: [_put(250, counter=3, parents=[[DEV_A, 0]], notes="nota de B")],
        }),
        _scenario("timestamp-tie", "equal ts: device id, then seq, breaks the tie", {
            DEV_B: [_put(100, notes="B vence o empate")],
            DEV_A: [_put(100, notes="A perde o empate")],
        }),
        _scenario("deleted", "a deleted entry keeps its counter as a floor", {
            DEV_A: [_put(100), _put(200, counter=2, parents=[[DEV_A, 0]]), _del(300, parents=[[DEV_A, 1]])],
        }),
        _scenario("delete-then-recreate", "re-creating with counter 1 does not go back to a retired password", {
            DEV_A: [_put(100), _put(200, counter=3, parents=[[DEV_A, 0]]), _del(300, parents=[[DEV_A, 1]])],
            DEV_B: [_put(400, counter=1, parents=[[DEV_A, 2]])],
        }),
        _scenario("concurrent-delete-and-edit", "the later record decides whether the entry exists", {
            DEV_A: [a0, _del(200, parents=[[DEV_A, 0]])],
            DEV_B: [_put(300, counter=3, parents=[[DEV_A, 0]], notes="ainda em uso")],
        }),
        _scenario("logins-are-separate-entries", "same site, different login", {
            DEV_A: [_put(100, login="fulano"), _put(110, login="beltrano", counter=7), _put(120)],
        }),
        _scenario("parent-in-a-stream-not-yet-synced", "an unknown parent is not an error", {
            DEV_B: [_put(400, counter=2, parents=[[DEV_C, 9]])],
        }),
        _scenario("delete-without-a-put", "a delete for an entry never seen created yields nothing", {
            DEV_A: [_del(100)],
        }),
    ]

    integrity = []
    for name, lengths, seen, own, pending_ok in [
        ("first-run", {DEV_A: 2}, {}, DEV_B, False),
        ("in-sync", {DEV_A: 2, DEV_B: 1}, {DEV_A: 2, DEV_B: 1}, DEV_B, False),
        ("other-device-advanced", {DEV_A: 5, DEV_B: 1}, {DEV_A: 2, DEV_B: 1}, DEV_B, False),
        ("stream-shrank", {DEV_A: 1, DEV_B: 1}, {DEV_A: 2, DEV_B: 1}, DEV_B, False),
        ("stream-vanished", {DEV_B: 1}, {DEV_A: 2, DEV_B: 1}, DEV_B, False),
        ("own-stream-shrank", {DEV_B: 0}, {DEV_B: 1}, DEV_B, False),
        ("cloned-install", {DEV_B: 3}, {DEV_B: 1}, DEV_B, False),
        ("interrupted-own-write", {DEV_B: 2}, {DEV_B: 1}, DEV_B, True),
    ]:
        try:
            outcome = journal.check_integrity(lengths, seen, own, pending_ok) or "ok"
        except journal.JournalError as exc:
            outcome = exc.code
        integrity.append({"name": name, "lengths": lengths, "seen": seen, "own": own,
                          "own_write_pending_matches": pending_ok, "expected": outcome})

    return {
        "format_version": FORMAT_VERSION,
        "spec": "ADR-0009 §6-§7",
        "journal_id_hex": JOURNAL_ID.hex(),
        "dek_hex": DEK.hex(),
        "prk_none_from_fixed_k0_hex": bytes(prk_none).hex(),
        "access_slot": [
            {"label": "small-parameters", "access_password": "abre o diário",
             "argon2": {"memory_kib": small[0], "time_cost": small[1], "parallelism": small[2]},
             "kek_hex": keys.access_kek("abre o diário", salt, small).hex(),
             "keys_file_hex": keys_small.hex()},
            {"label": "default-parameters", "access_password": "abre o diário",
             "argon2": dict(zip(("memory_kib", "time_cost", "parallelism"), keys.DEFAULT_ACCESS_PARAMS)),
             "kek_hex": keys.access_kek("abre o diário", salt, keys.DEFAULT_ACCESS_PARAMS).hex(),
             "keys_file_hex": keys_default.hex()},
        ],
        "recovery": {
            "kek_hex": keys.recovery_kek(prk_none, JOURNAL_ID).hex(),
            "blob_hex": recovery.hex(),
            "text": keys.recovery_to_text(recovery),
        },
        "keyfile": {
            "wrap_key_hex": keys.keyfile_wrap_key(prk_none).hex(),
            "factor_hex": FIXED_KEYFILE.hex(),
            "file_hex": keyfile.hex(),
        },
        "stream": {
            "device_id_hex": DEV_A,
            "stream_key_hex": journal.stream_key(DEK, JOURNAL_ID, bytes.fromhex(DEV_A)).hex(),
            "nonces_hex": [n.hex() for n in stream_nonces],
            "records": stream_records,
            "plaintexts_hex": [journal.encode_record(r).hex() for r in stream_records],
            "file_hex": stream.hex(),
        },
        "next_timestamp": [
            {"now_ms": now, "highest_seen": seen, "expected":
                journal.next_timestamp(now, [{"ts": seen}] if seen is not None else [])}
            for now, seen in [(1000, None), (1000, 500), (1000, 1000), (5, 1_000_000), (1000, 999)]
        ],
        "merge": scenarios,
        "integrity": integrity,
    }


BUILDERS = {
    "canonical.json": build_canonical,
    "derivation.json": build_derivation,
    "journal.json": build_journal,
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
