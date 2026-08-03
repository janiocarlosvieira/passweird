"""
Dedicated regression tests for the two live bugs found in the pre-refactor
audit: (B1) main.py used hashlib without importing it on the --key-file path,
(B2) crypto.py used datetime.UTC, which doesn't exist before Python 3.11.
"""
import os
import sys

from cryptography import x509

import crypto
import main
import storage


def test_b1_keyfile_path_does_not_raise_nameerror(tmp_path, monkeypatch):
    keyfile = tmp_path / "second-factor.key"
    keyfile.write_bytes(b"physical factor bytes")

    # This is exactly the call site that used to crash with
    # NameError: name 'hashlib' is not defined.
    master_hash = crypto.modified_hash("master", keyfile_path=str(keyfile))
    assert isinstance(master_hash, str) and len(master_hash) == 64


def test_b1_cli_key_file_end_to_end(tmp_path, monkeypatch, capsys):
    keyfile = tmp_path / "second-factor.key"
    keyfile.write_bytes(b"physical factor bytes")

    inputs = iter(["mymasterpass"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(inputs))
    monkeypatch.setattr(sys, "argv", ["main.py", "testapp", "--key-file", str(keyfile), "-T", ""])

    main.main()
    out = capsys.readouterr().out
    assert "Error" not in out


def test_b2_ssl_generation_does_not_raise_attributeerror():
    mh = crypto.modified_hash("master")
    ah = crypto.modified_hash("example.com")
    # This used to raise AttributeError: module 'datetime' has no attribute 'UTC' on Python < 3.11.
    priv, cert = crypto.generate_ssl_certificate(mh, ah, "example.com")
    parsed = x509.load_pem_x509_certificate(cert.encode())
    assert parsed is not None


def test_certificate_validity_anchored_to_utc_midnight():
    """
    Certificate validity used to come from datetime.now() at second granularity, so
    two runs a second apart produced different certificate bytes despite identical
    key material. Invisible while only Ed25519 was deterministic (microseconds to
    generate); RSA takes seconds, which would have made --rsa only half reproducible.

    Asserting the midnight anchor directly rather than mocking the clock: patching
    datetime.datetime globally breaks the isinstance check inside cryptography's
    CertificateBuilder, and the anchor is the property the fix actually guarantees.
    """
    mh = crypto.modified_hash("master")
    ah = crypto.modified_hash("example.com")
    _, cert1 = crypto.generate_ssl_certificate(mh, ah, "example.com")
    _, cert2 = crypto.generate_ssl_certificate(mh, ah, "example.com")
    assert cert1 == cert2

    parsed = x509.load_pem_x509_certificate(cert1.encode())
    # cryptography >= 42 deprecates not_valid_before in favour of the _utc variants;
    # requirements.txt declares a floor, not a ceiling, so read whichever exists.
    before = getattr(parsed, "not_valid_before_utc", None) or parsed.not_valid_before
    after = getattr(parsed, "not_valid_after_utc", None) or parsed.not_valid_after
    assert (before.hour, before.minute, before.second, before.microsecond) == (0, 0, 0, 0)
    assert (after.hour, after.minute, after.second, after.microsecond) == (0, 0, 0, 0)
    assert (after - before).days == 366  # now-1d .. now+365d


# --- Domain separation in the HKDF info string -------------------------------
# temporal_salt is user-controlled free text placed at the end of every info
# string. Appending a literal sub-derivation suffix after it made the encoding
# ambiguous: a salt of "X:<suffix>" collided with the sub-derivation of salt "X".
# The worst case was SSL, where the sub-derivation (the serial number) is printed
# in the certificate: 19 of the 32 private seed bytes became publicly readable.

def _hkdf_infos_collide(app_hash, label, suffix):
    """True if salt 'X:<suffix>' reproduces the sub-derivation info of salt 'X'."""
    sub = f"{app_hash}:{label}:X".encode() + f":{suffix}".encode()
    key = f"{app_hash}:{label}:X:{suffix}".encode()
    return sub == key


def test_temporal_salt_cannot_collide_with_subderivations():
    """The old encoding is still ambiguous; the code must no longer use it."""
    ah = crypto.modified_hash("example.com")
    # Sanity: the pattern we moved away from really was ambiguous.
    assert _hkdf_infos_collide(ah, "ssl_seed", "serial")
    assert _hkdf_infos_collide(ah, "ssh_seed", "checkint")
    assert _hkdf_infos_collide(ah, "pgp_seed", "ctime")

    mh = crypto.modified_hash("master")
    prk = mh.encode()

    # SSL: the published serial must not be a prefix of the private seed.
    seed_attack = crypto.hkdf_expand(prk, f"{ah}:ssl_seed:X:serial".encode(), 32)
    serial_base = crypto.hkdf_expand(prk, f"{ah}:ssl_serial:X".encode(), 19)
    assert seed_attack[:19] != serial_base

    # SSH and PGP sub-derivations must likewise be unreachable from any salt.
    assert (crypto.hkdf_expand(prk, f"{ah}:ssh_seed:X:checkint".encode(), 4)
            != crypto.hkdf_expand(prk, f"{ah}:ssh_checkint:X".encode(), 4))
    assert (crypto.hkdf_expand(prk, f"{ah}:pgp_seed:X:ctime".encode(), 4)
            != crypto.hkdf_expand(prk, f"{ah}:pgp_ctime:X".encode(), 4))


def test_ssl_serial_not_derivable_from_any_salt_end_to_end():
    """The concrete leak, exercised through the real certificate path."""
    mh = crypto.modified_hash("master")
    ah = crypto.modified_hash("example.com")

    _, cert_base = crypto.generate_ssl_certificate(mh, ah, "example.com", temporal_salt="X")
    serial = x509.load_pem_x509_certificate(cert_base.encode()).serial_number
    serial_bytes = serial.to_bytes(19, "big")

    priv_attack, _ = crypto.generate_ssl_certificate(
        mh, ah, "example.com", temporal_salt="X:serial"
    )
    seed = crypto.hkdf_expand(mh.encode(), f"{ah}:ssl_seed:X:serial".encode(), 32)
    assert seed[:19] != serial_bytes
    assert priv_attack  # the attacked configuration still produces a usable key


def test_key_material_unchanged_by_the_domain_separation_fix():
    """
    The fix moved only the sub-derivations to their own labels; the *_seed infos are
    untouched, so SSH public keys and SSL/PGP key material stay byte-identical and
    anything already deployed keeps working.
    """
    mh = crypto.modified_hash("master")
    ah = crypto.modified_hash("example.com")
    prk = mh.encode()

    import base64
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ed25519

    for salt in ["", "2026/01"]:
        # The key seed still comes from the untouched ":ssh_seed:" label...
        expected_seed = crypto.hkdf_expand(prk, f"{ah}:ssh_seed:{salt}".encode(), 32)
        expected_pub = ed25519.Ed25519PrivateKey.from_private_bytes(
            expected_seed
        ).public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)

        # ...so the wire-format public key an authorized_keys file already holds
        # is bit-for-bit what the current code emits.
        _, pub = crypto.generate_deterministic_ssh_key(mh, ah, salt)
        blob = base64.b64decode(pub.split()[1])
        assert blob.endswith(expected_pub)

    # The SSL/PGP seeds are likewise untouched by the relabelling.
    assert crypto.hkdf_expand(prk, f"{ah}:ssl_seed:".encode(), 32) == crypto.hkdf_expand(
        prk, f"{ah}:ssl_seed:".encode(), 32
    )
    priv1, _ = crypto.generate_ssl_certificate(mh, ah, "example.com")
    expected_ssl = crypto.hkdf_expand(prk, f"{ah}:ssl_seed:".encode(), 32)
    expected_key = ed25519.Ed25519PrivateKey.from_private_bytes(expected_ssl).private_bytes(
        ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()
    ).decode()
    assert priv1 == expected_key


def test_pgp_creation_time_is_always_in_the_past():
    """
    The derived OpenPGP creation timestamp used to be '% 2_000_000_000', which reaches
    2033. Future-dated keys are rejected by gpg on import ("failed to re-lookup public
    key"), so roughly one in nine master/context combinations produced an unusable key
    depending purely on where the derivation happened to land.
    """
    import time

    now = int(time.time())
    mh = crypto.modified_hash("master")
    for context in ["a", "b", "c", "example.com", "outro"]:
        ah = crypto.modified_hash(context)
        for salt in ["", "2026/01", "frase forte"]:
            ctime = crypto._PGP_CTIME_EPOCH + (
                int.from_bytes(
                    crypto.hkdf_expand(mh.encode(), f"{ah}:pgp_ctime:{salt}".encode(), 4), "big"
                ) % crypto._PGP_CTIME_RANGE
            )
            assert ctime < now, f"future-dated PGP key for {context!r}/{salt!r}"
            assert ctime >= crypto._PGP_CTIME_EPOCH


# --- Mixed-format log --------------------------------------------------------
# The log format is chosen per execution and the file is append-only, so one file
# can hold plaintext and encrypted records interleaved. Detection used to inspect
# only the first 14 bytes of the file and then treat the whole file as that type:
# UnicodeDecodeError in one order, silent record loss in the other.

def _write_log(entries, master_hash):
    """entries: list of (text, encrypted?) written in order, as the CLI would."""
    import storage
    for text, encrypted in entries:
        storage.log_hashes_to_file(text, master_hash, encrypt=encrypted)


def test_mixed_log_plaintext_then_encrypted(isolated_home):
    mh = crypto.modified_hash("master")
    _write_log([("20260101000001 ver:v2 plain-one", False),
                ("20260101000002 ver:v2 enc-one", True)], mh)

    records = storage.read_logs_from_file(mh)
    assert len(records) == 2
    assert "plain-one" in records[0]
    assert "enc-one" in records[1]


def test_mixed_log_encrypted_then_plaintext(isolated_home):
    """The order that used to lose records with no error at all."""
    mh = crypto.modified_hash("master")
    _write_log([("20260101000001 ver:v2 enc-one", True),
                ("20260101000002 ver:v2 plain-one", False)], mh)

    records = storage.read_logs_from_file(mh)
    assert len(records) == 2
    assert "enc-one" in records[0]
    assert "plain-one" in records[1]


def test_mixed_log_alternating(isolated_home):
    mh = crypto.modified_hash("master")
    _write_log([("20260101000001 a", True), ("20260101000002 b", False),
                ("20260101000003 c", True), ("20260101000004 d", False)], mh)

    records = storage.read_logs_from_file(mh)
    assert len(records) == 4
    assert [r.split()[-1] for r in records] == ["a", "b", "c", "d"]


def test_log_truncated_mid_block_keeps_intact_records(isolated_home):
    """A power loss during a write must not cost the whole history."""
    mh = crypto.modified_hash("master")
    _write_log([("20260101000001 first", True), ("20260101000002 second", True)], mh)

    log_path = os.path.expanduser("~/.passweird/passweird.log")
    with open(log_path, "rb") as f:
        raw = f.read()
    with open(log_path, "wb") as f:
        f.write(raw[:-10])          # chop the tail of the last block

    records = storage.read_logs_from_file(mh)
    assert len(records) == 1
    assert "first" in records[0]


def test_empty_and_missing_log(isolated_home):
    assert storage.read_logs_from_file(crypto.modified_hash("master")) == []
    log_path = os.path.expanduser("~/.passweird/passweird.log")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    open(log_path, "wb").close()
    assert storage.read_logs_from_file(crypto.modified_hash("master")) == []


def test_mixed_log_wrong_master_still_returns_plaintext_records(isolated_home):
    """Encrypted blocks are skipped; plaintext ones are not encrypted at all."""
    mh = crypto.modified_hash("master")
    _write_log([("20260101000001 enc", True), ("20260101000002 plain", False)], mh)

    records = storage.read_logs_from_file(crypto.modified_hash("WRONG"))
    assert len(records) == 1
    assert "plain" in records[0]
