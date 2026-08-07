"""
Validates the implementation against the committed golden derivation vectors.

These vectors (ADR-0008) are the contract every Passweird implementation must
satisfy, this one included. Their primary purpose is to make a future Kotlin port
verifiable rather than hopeful, but they earn their keep immediately: any change
that alters a derivation now fails here, loudly, instead of silently changing
every password a user has already deployed.

A failure in this file is never "fix the test". It means a derivation changed,
and the only two valid responses are to revert it, or to treat it as the
compatibility break it is and regenerate the vectors deliberately:

    python tools/generate_vectors.py
"""
import base64
import json
import pathlib

import pytest

from passweird import crypto

VECTORS_PATH = pathlib.Path(__file__).parent / "vectors" / "derivation-v1.json"
VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def _cases(group):
    """Yields pytest params labelled by case, so failures name the scenario."""
    return [pytest.param(case, id=case["label"]) for case in VECTORS[group]]


def test_vector_file_metadata():
    assert VECTORS["format_version"] == 1
    assert VECTORS["engine_version"] == "v2"


@pytest.mark.parametrize("case", _cases("modified_hash"))
def test_modified_hash_vectors(case):
    assert crypto.modified_hash(case["input"]) == case["expected"]


@pytest.mark.parametrize("case", _cases("blend_secondary_factor"))
def test_blend_secondary_factor_vectors(case):
    factor = bytes.fromhex(case["factor_hex"])
    assert crypto.blend_secondary_factor(case["base_hash"], factor) == case["expected"]


@pytest.mark.parametrize("case", _cases("hkdf_expand"))
def test_hkdf_expand_vectors(case):
    result = crypto.hkdf_expand(
        case["prk_utf8"].encode(), case["info_utf8"].encode(), case["length"]
    )
    assert result.hex() == case["expected_hex"]
    assert len(result) == case["length"]


@pytest.mark.parametrize("case", _cases("password"))
def test_password_vectors(case):
    master_hash = crypto.modified_hash(case["master_password"])
    app_hash = crypto.modified_hash(case["context"])

    # Intermediates are asserted separately so a divergence localizes to a stage
    # instead of only reporting that the final password differs.
    assert master_hash == case["master_hash"], "master_hash stage"
    assert app_hash == case["app_hash"], "app_hash stage"

    password = crypto.generate_password(
        "v2",
        master_hash,
        app_hash,
        case["length"],
        temporal_salt=case["temporal_salt"],
        use_upper=case["use_upper"],
        use_lower=case["use_lower"],
        use_digits=case["use_digits"],
        use_special=case["use_special"],
    )
    assert password == case["expected_password"]
    assert len(password) == case["length"]


@pytest.mark.parametrize("case", _cases("password"))
def test_password_raw_hkdf_stage_vectors(case):
    """
    Pins the HKDF output at the *final* compliance nonce. This is the stage where
    a port with signed bytes still produces a plausible password, so pinning the
    bytes catches it one step before the visible symptom.
    """
    info = f"{case['app_hash']}:{case['length']}:{case['temporal_salt']}:{case['compliance_nonce']}"
    raw = crypto.hkdf_expand(case["master_hash"].encode(), info.encode(), case["length"])
    assert raw.hex() == case["raw_hkdf_hex"]


@pytest.mark.parametrize("case", _cases("totp"))
def test_totp_vectors(case):
    secret = crypto.generate_deterministic_totp_secret(
        crypto.modified_hash(case["master_password"]),
        crypto.modified_hash(case["context"]),
        case["temporal_salt"],
    )
    assert secret == case["expected_base32"]
    # Base32 without padding, and decodable back to the 160-bit TOTP seed.
    assert "=" not in secret
    assert len(base64.b32decode(secret + "=" * (-len(secret) % 8))) == 20


def test_summary_vectors():
    by_label = {c["label"]: c for c in VECTORS["summaries"]}
    hash_case = by_label["summarize_hash"]
    assert crypto.summarize_hash(hash_case["input"]) == hash_case["expected"]
    pwd_case = by_label["summarize_password_hash"]
    assert crypto.summarize_password_hash(pwd_case["input"]) == pwd_case["expected"]


# --- Coverage guarantees -----------------------------------------------------
# The vectors are only worth what they cover. These assertions keep the file
# honest if someone regenerates it after changing the case list.

def test_vectors_cover_bytes_above_127():
    """
    The signed-byte trap: on the JVM, Byte is -128..127 and % preserves the sign,
    so `charset[b % len]` yields negative indices for any byte above 127. Roughly
    half of every derivation is affected, and the wrong result still looks like a
    valid password. Vectors that never exceed 127 would not catch it.
    """
    total = high = 0
    for case in VECTORS["password"]:
        raw = bytes.fromhex(case["raw_hkdf_hex"])
        total += len(raw)
        high += sum(1 for b in raw if b > 127)
    assert total > 0
    assert high / total > 0.25, f"only {high}/{total} bytes above 127"


def test_vectors_cover_the_compliance_loop():
    """The retry branch is live, not theoretical - it must be pinned."""
    nonces = [c["compliance_nonce"] for c in VECTORS["password"]]
    assert any(n > 0 for n in nonces), "no case exercises the compliance loop"


def test_vectors_cover_non_ascii_inputs():
    """UTF-8 encoding must match across languages; ASCII-only vectors hide that."""
    assert any(
        not c["master_password"].isascii()
        or not c["context"].isascii()
        or not c["temporal_salt"].isascii()
        for c in VECTORS["password"]
    )


def test_vectors_cover_every_character_class_toggle():
    """Charset construction is by concatenation, so each toggle shifts every index."""
    for flag in ("use_upper", "use_lower", "use_digits", "use_special"):
        assert any(not c[flag] for c in VECTORS["password"]), f"no case disables {flag}"


def test_vectors_cover_multi_block_hkdf():
    """HMAC-SHA512 yields 64 bytes per block; the counter loop needs exercising."""
    assert any(c["length"] > 64 for c in VECTORS["hkdf_expand"])


def test_vector_labels_are_unique():
    for group, cases in VECTORS.items():
        if isinstance(cases, list) and cases and isinstance(cases[0], dict):
            labels = [c["label"] for c in cases]
            assert len(labels) == len(set(labels)), f"duplicate labels in {group}"
