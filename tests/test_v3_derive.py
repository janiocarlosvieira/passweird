# ADR-0009 §2-§5 - stretching, expansion and sampling.
#
# Three kinds of evidence, deliberately separate:
#   1. golden vectors      - what this implementation does, pinned for ports;
#   2. independent checks  - Argon2id against a second implementation and the
#                            RFC 9106 test vector, HKDF against Wycheproof;
#   3. properties          - uniformity, class compliance, fail-closed paths.
import collections
import hashlib
import json
import math
import pathlib
import re

import pytest

from passweird.v3 import canon, derive
from v3_support import load

VECTORS = load("derivation.json")
FIXED_K0 = bytes.fromhex(VECTORS["fixed_k0_hex"])
FIXED_KEYFILE = bytes.fromhex(VECTORS["fixed_keyfile_hex"])
WYCHEPROOF = (
    pathlib.Path(__file__).resolve().parent / "vectors" / "third_party" / "wycheproof" / "hkdf_sha512_test.json"
)


def _prk(name):
    if name == "keyfile":
        return derive.extract(FIXED_K0, derive.FACTOR_KEYFILE, FIXED_KEYFILE)
    return derive.extract(FIXED_K0)


# --- 1. golden vectors -------------------------------------------------------

def test_frozen_identifier_matches_the_parameters():
    assert VECTORS["alg"] == derive.ALG
    a = VECTORS["argon2"]
    assert derive.ALG == (
        f"passweird-v3/argon2id-v{a['version']}-m{a['memory_kib']}-t{a['time_cost']}"
        f"-p{a['parallelism']}/hkdf-sha512"
    )
    assert (derive.ARGON2_VERSION, derive.ARGON2_MEMORY_KIB, derive.ARGON2_TIME_COST,
            derive.ARGON2_PARALLELISM, derive.K0_BYTES) == (
        a["version"], a["memory_kib"], a["time_cost"], a["parallelism"], a["tag_bytes"])


@pytest.mark.parametrize("case", VECTORS["encoding"], ids=lambda c: repr(c["lp_of_utf8"])[:20])
def test_lp_encoding_vectors(case):
    assert derive.lp(case["lp_of_utf8"]).hex() == case["expected_hex"]


@pytest.fixture(scope="module")
def stretched():
    """The full-cost Argon2id runs, done once for the whole module."""
    out = {}
    for case in VECTORS["stretch"]:
        c = case["canonical"]
        out[case["label"]] = bytes(derive.stretch(c["master"], c["boost"], c["user_id"]))
    return out


@pytest.mark.parametrize("case", VECTORS["stretch"], ids=lambda c: c["label"])
def test_stretch_vectors(case, stretched):
    assert canon.master(case["master"]) == case["canonical"]["master"]
    assert canon.boost(case["boost"]) == case["canonical"]["boost"]
    assert canon.user_id(case["user_id"]) == case["canonical"]["user_id"]
    c = case["canonical"]
    assert derive.stretch_input(c["master"], c["boost"]).hex() == case["argon2_password_hex"]
    assert derive.salt_for(c["user_id"]).hex() == case["argon2_salt_hex"]
    k0 = stretched[case["label"]]
    assert k0.hex() == case["k0_hex"]
    prk = derive.extract(k0)
    assert bytes(prk).hex() == case["prk_none_hex"]
    assert derive.fingerprint(prk) == case["fingerprint"]
    assert derive.password(prk, "github.com") == case["password_github"]


@pytest.mark.parametrize("case", VECTORS["extract"], ids=lambda c: c["kind"])
def test_extract_vectors(case):
    factor = bytes.fromhex(case["factor_hex"])
    assert derive.factor_tag(case["kind"], factor).hex() == case["factor_tag_hex"]
    assert bytes(derive.extract(FIXED_K0, case["kind"], factor)).hex() == case["prk_hex"]


@pytest.mark.parametrize("case", VECTORS["purposes"],
                         ids=lambda c: f"{c['purpose']}-{c['length']}-{c['extra_hex'][:12]}")
def test_purpose_vectors(case):
    kwargs = dict(site=case["site"], login=case["login"], counter=case["counter"],
                  extra=bytes.fromhex(case["extra_hex"]))
    assert derive.info(case["purpose"], **kwargs).hex() == case["info_hex"]
    assert derive.okm(_prk(case["prk"]), case["purpose"], case["length"], **kwargs).hex() == case["expected_hex"]


@pytest.mark.parametrize("case", VECTORS["passwords"], ids=lambda c: c["label"])
def test_password_vectors(case):
    prk = _prk("keyfile" if case["label"] == "keyfile-factor" else "none")
    extra = derive.password_extra(case["length"], case["classes"])
    args = (case["site"], case["login"], case["counter"])
    assert derive.info("password", *args, extra).hex() == case["info_hex"]
    stream = derive.okm(prk, "password", derive.PASSWORD_STREAM_BYTES, *args, extra)
    assert stream[:64].hex() == case["stream_first_64_hex"]
    assert hashlib.sha256(stream).hexdigest() == case["stream_sha256"]
    pw, trace = derive.sample_password(stream, case["length"], case["classes"])
    assert pw == case["expected_password"]
    for key in ("byte_rejections", "candidate_rejections", "stream_bytes_used"):
        assert trace[key] == case[key]
    assert derive.password(prk, *args, case["length"], case["classes"]) == case["expected_password"]


def test_vectors_exercise_both_rejection_paths():
    assert any(c["candidate_rejections"] >= 3 for c in VECTORS["passwords"])
    assert any(c["byte_rejections"] >= 6 for c in VECTORS["passwords"])
    assert any(c["byte_rejections"] == 0 and c["candidate_rejections"] == 0 for c in VECTORS["passwords"])


def test_fingerprint_and_totp_vectors():
    assert derive.fingerprint(_prk("none")) == VECTORS["fingerprint"]["expected"]
    for case in VECTORS["totp"]:
        assert derive.totp_secret(_prk(case["prk"]), case["site"], case["login"], case["counter"]) == \
            case["expected_base32"]


# --- 2. independent checks ---------------------------------------------------

def _second_argon2id():
    try:
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    except ImportError:
        pytest.skip("needs cryptography>=44 for an independent Argon2id (OpenSSL)")
    return Argon2id


def test_second_argon2id_implementation_reproduces_rfc_9106():
    """Anchors the reference used for the cross-check to RFC 9106 §5.3."""
    Argon2id = _second_argon2id()
    tag = Argon2id(salt=b"\x02" * 16, length=32, iterations=3, lanes=4, memory_cost=32,
                   ad=b"\x04" * 12, secret=b"\x03" * 8).derive(b"\x01" * 32)
    assert tag.hex() == "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"


@pytest.mark.parametrize("case", VECTORS["stretch"], ids=lambda c: c["label"])
def test_argon2id_cross_check_at_full_parameters(case, stretched):
    """argon2-cffi (libargon2) and cryptography (OpenSSL) must agree on K0."""
    Argon2id = _second_argon2id()
    other = Argon2id(
        salt=bytes.fromhex(case["argon2_salt_hex"]), length=derive.K0_BYTES,
        iterations=derive.ARGON2_TIME_COST, lanes=derive.ARGON2_PARALLELISM,
        memory_cost=derive.ARGON2_MEMORY_KIB,
    ).derive(bytes.fromhex(case["argon2_password_hex"]))
    assert other == stretched[case["label"]]
    assert other.hex() == case["k0_hex"]


def _wycheproof_cases():
    data = json.loads(WYCHEPROOF.read_text(encoding="utf-8"))
    assert data["algorithm"] == "HKDF-SHA-512"
    return [t for group in data["testGroups"] for t in group["tests"]]


@pytest.mark.parametrize("case", _wycheproof_cases(), ids=lambda c: f"tc{c['tcId']}")
def test_hkdf_sha512_against_wycheproof(case):
    ikm, salt, info = (bytes.fromhex(case[k]) for k in ("ikm", "salt", "info"))
    if case["result"] == "invalid":
        with pytest.raises(derive.DerivationError):
            derive.hkdf_expand(derive.hkdf_extract(salt, ikm), info, case["size"])
        return
    okm = derive.hkdf_expand(derive.hkdf_extract(salt, ikm), info, case["size"])
    assert okm.hex() == case["okm"]


def test_wycheproof_file_is_the_expected_one():
    cases = _wycheproof_cases()
    assert len(cases) == 83
    assert {c["result"] for c in cases} == {"valid", "invalid"}


# --- 3. properties -----------------------------------------------------------

def _chi_square_critical(dof, z=4.753):
    """Wilson-Hilferty approximation; z=4.753 is the one-sided 1e-6 quantile."""
    return dof * (1 - 2 / (9 * dof) + z * math.sqrt(2 / (9 * dof))) ** 3


def _keystream(label, n):
    return hashlib.shake_256(label.encode()).digest(n)


@pytest.mark.parametrize("n", [10, 15, 26, 52, 62, 77])
def test_uniform_passes_chi_square(n):
    """The inputs are fixed, so this is deterministic, not a flaky statistical test."""
    samples = 200_000
    stream = derive.ByteStream(_keystream(f"chi-{n}", samples * 2))
    counts = collections.Counter(stream.uniform(n) for _ in range(samples))
    expected = samples / n
    chi2 = sum((counts[i] - expected) ** 2 / expected for i in range(n))
    assert chi2 < _chi_square_critical(n - 1), f"chi2={chi2:.1f} for n={n}"


def test_the_chi_square_test_would_catch_the_v2_modulo():
    """Power check: the same test rejects `b % n`, the v2 mapping."""
    n, samples = 77, 200_000
    counts = collections.Counter(b % n for b in _keystream("chi-77", samples))
    expected = samples / n
    chi2 = sum((counts[i] - expected) ** 2 / expected for i in range(n))
    assert chi2 > 10 * _chi_square_critical(n - 1)


@pytest.mark.parametrize("n", [1, 2, 10, 15, 26, 62, 77, 255, 256])
def test_uniform_is_exactly_uniform_over_all_byte_values(n):
    stream = derive.ByteStream(bytes(range(256)))
    counts = collections.Counter()
    try:
        while True:
            counts[stream.uniform(n)] += 1
    except derive.DerivationError:
        pass
    assert len(counts) == n
    assert len(set(counts.values())) == 1
    assert stream.byte_rejections == 256 % n


def test_first_character_distribution_passes_chi_square():
    """End to end through HKDF and the class filter, at length 18 with all classes."""
    prk = _prk("none")
    charset = derive.charset_for(15)
    samples = 20_000
    counts = collections.Counter(derive.password(prk, f"s{i}.example")[0] for i in range(samples))
    expected = samples / len(charset)
    chi2 = sum((counts[ch] - expected) ** 2 / expected for ch in charset)
    assert chi2 < _chi_square_critical(len(charset) - 1)


@pytest.mark.parametrize("classes", range(1, 16))
def test_every_enabled_class_is_present_and_no_other(classes):
    prk = _prk("none")
    groups = {1: derive.CHARSET_LOWER, 2: derive.CHARSET_UPPER, 4: derive.CHARSET_DIGITS,
              8: derive.CHARSET_SPECIALS}
    for i in range(40):
        pw = derive.password(prk, f"site-{i}.example", length=8, classes=classes)
        assert len(pw) == 8
        for bit, chars in groups.items():
            assert any(ch in chars for ch in pw) == bool(classes & bit)


def test_sampling_fails_closed_when_the_stream_runs_out():
    with pytest.raises(derive.DerivationError):
        derive.sample_password(b"\xff" * 4096, 18, 15)     # every byte is rejected for n=77
    with pytest.raises(derive.DerivationError):
        derive.sample_password(b"\x00" * 4096, 18, 15)     # 'aaaa…' never has all classes


def test_profiles_are_not_correlated():
    """v2 finding 5: the same bytes must never feed two different charsets."""
    prk = _prk("none")
    a = derive.okm(prk, "password", 64, "github.com", "", 1, derive.password_extra(18, 15))
    b = derive.okm(prk, "password", 64, "github.com", "", 1, derive.password_extra(18, 7))
    c = derive.okm(prk, "password", 64, "github.com", "", 1, derive.password_extra(19, 15))
    assert len({a, b, c}) == 3


def test_every_input_changes_the_password():
    prk = _prk("none")
    base = dict(site="github.com", login="fulano", counter=1, length=18, classes=15)
    seen = {derive.password(prk, **base)}
    for change in (dict(site="gitlab.com"), dict(login="beltrano"), dict(login=""), dict(counter=2),
                   dict(length=19), dict(classes=7)):
        seen.add(derive.password(prk, **{**base, **change}))
    seen.add(derive.password(_prk("keyfile"), **base))
    assert len(seen) == 8


def test_info_fields_cannot_be_shifted_into_each_other():
    """The ADR-0004 ambiguity class: no split of the same text yields the same info."""
    assert derive.info("password", "ab", "c") != derive.info("password", "a", "bc")
    assert derive.info("password", "a", "", 1, b"x") != derive.info("password", "a", "x", 1, b"")
    assert derive.stretch_input("ab", "c") != derive.stretch_input("a", "bc")


def test_master_and_boost_are_stretched_together(stretched):
    """Moving a character across the master/boost boundary changes K0."""
    moved = bytes(derive.stretch("minha senha mestr", "acavalo bateria grampo correto girassol",
                                 "fulano@example.com"))
    assert moved != stretched["ascii"]


def test_factor_rules():
    with pytest.raises(derive.DerivationError):
        derive.factor_tag("keyfile", b"short")
    with pytest.raises(derive.DerivationError):
        derive.factor_tag("none", b"x")
    with pytest.raises(derive.DerivationError):
        derive.factor_tag("fido2", b"x" * 32)
    with pytest.raises(derive.DerivationError):
        derive.extract(b"too short")


def test_fingerprint_shape():
    assert re.fullmatch(r"([bdfghjklmnprstvz][aeio]){2}-([bdfghjklmnprstvz][aeio]){2}",
                        derive.fingerprint(_prk("none")))
    assert derive.fingerprint(_prk("none")) != derive.fingerprint(derive.extract(bytes(64)))


def test_session_canonicalises_and_wipes(stretched):
    case = next(c for c in VECTORS["stretch"] if c["label"] == "needs-canonicalisation")
    session = derive.Session.open(case["master"], case["boost"], case["user_id"])
    assert session.fingerprint == case["fingerprint"]
    assert session.password("https://www.GitHub.com/login") == case["password_github"]
    with pytest.raises(canon.CanonicalError):
        session.password("github.com", length=7)
    k0, prk = session._k0, session.prk_none
    session.close()
    assert not any(k0) and not any(prk)


def test_session_keyfile_changes_site_outputs_but_not_the_fingerprint():
    session = derive.Session(bytearray(FIXED_K0), "u")
    before, fp = session.password("github.com"), session.fingerprint
    session.use_keyfile(FIXED_KEYFILE)
    assert session.password("github.com") != before
    assert session.fingerprint == fp
