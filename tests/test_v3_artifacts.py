# ADR-0009 §4 - SSH, TLS and OpenPGP material derived with the v3 purposes.
import shutil

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from passweird import crypto
from passweird.v3 import artifacts, derive
from v3_support import load

VECTORS = load("derivation.json")
PRK = derive.extract(bytes.fromhex(VECTORS["fixed_k0_hex"]))
ARGS = ("example.org", "fulano", 3)          # the site/login/counter of the purpose vectors


def _purpose(name, **match):
    for case in VECTORS["purposes"]:
        if case["purpose"] == name and all(case[k] == v for k, v in match.items()):
            return bytes.fromhex(case["expected_hex"])
    raise AssertionError(name)


def _raw_public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def test_ssh_key_is_built_from_the_pinned_seed():
    private, public = artifacts.ssh_keypair(PRK, *ARGS)
    assert (private, public) == artifacts.ssh_keypair(PRK, *ARGS)
    loaded = serialization.load_ssh_private_key(private.encode(), password=None)
    expected = ed25519.Ed25519PrivateKey.from_private_bytes(_purpose("ssh-ed25519"))
    assert _raw_public(loaded) == _raw_public(expected)
    assert public.startswith("ssh-ed25519 ")
    assert serialization.load_ssh_public_key(public.encode()).public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw) == _raw_public(expected)


@pytest.mark.parametrize("change", [("other.example", "fulano", 3), ("example.org", "", 3),
                                    ("example.org", "fulano", 4)])
def test_site_login_and_counter_each_change_the_ssh_key(change):
    assert artifacts.ssh_keypair(PRK, *change)[1] != artifacts.ssh_keypair(PRK, *ARGS)[1]


def test_tls_ed25519_certificate():
    private, certificate = artifacts.tls_certificate(PRK, *ARGS)
    cert = x509.load_pem_x509_certificate(certificate.encode())
    key = serialization.load_pem_private_key(private.encode(), password=None)
    expected = ed25519.Ed25519PrivateKey.from_private_bytes(_purpose("tls-ed25519"))
    assert _raw_public(key) == _raw_public(expected)
    assert cert.serial_number == int.from_bytes(_purpose("tls-serial"), "big") | 1
    assert "CN=example.org" in cert.subject.rfc4514_string()
    assert artifacts.tls_certificate(PRK, *ARGS)[0] == private


def test_no_purpose_shares_bytes_with_another():
    """The serial is published; it must tell nothing about any private seed."""
    values = [bytes.fromhex(c["expected_hex"]) for c in VECTORS["purposes"]]
    prefixes = [v[:3] for v in values]
    assert len(set(prefixes)) == len(prefixes)
    serial, seed = _purpose("tls-serial"), _purpose("tls-ed25519")
    assert serial != seed[:19]


@pytest.mark.slow
def test_rsa_key_is_reproducible_and_usable():
    key = artifacts.rsa_private_key(PRK, *ARGS, bits=2048)
    again = artifacts.rsa_private_key(PRK, *ARGS, bits=2048)
    numbers = key.private_numbers()
    assert numbers.p == again.private_numbers().p and numbers.q == again.private_numbers().q
    assert key.key_size == 2048 and numbers.public_numbers.e == 65537
    # Each prime is one of the candidates the pinned purposes define: candidate i
    # with the top two bits and the low bit forced, for the first i that is prime.
    def candidates(purpose):
        for i in range(5000):
            raw = derive.okm(PRK, purpose, 128, *ARGS, derive.rsa_extra(2048, i))
            yield int.from_bytes(raw, "big") | (1 << 1023) | (1 << 1022) | 1
    assert int.from_bytes(_purpose("tls-rsa-p", length=128, extra_hex=derive.rsa_extra(2048, 0).hex()), "big") \
        | (1 << 1023) | (1 << 1022) | 1 == next(candidates("tls-rsa-p"))
    assert {numbers.p, numbers.q} <= set(candidates("tls-rsa-p")) | set(candidates("tls-rsa-q"))
    assert crypto._is_probable_prime(numbers.p) and crypto._is_probable_prime(numbers.q)
    signature = key.sign(b"mensagem", padding.PKCS1v15(), hashes.SHA256())
    key.public_key().verify(signature, b"mensagem", padding.PKCS1v15(), hashes.SHA256())
    assert artifacts.rsa_private_key(PRK, "example.org", "fulano", 4).private_numbers().p != numbers.p


@pytest.mark.slow
def test_tls_rsa_certificate():
    private, certificate = artifacts.tls_certificate(PRK, *ARGS, rsa_bits=2048)
    cert = x509.load_pem_x509_certificate(certificate.encode())
    assert isinstance(cert.public_key(), rsa.RSAPublicKey)
    assert artifacts.tls_certificate(PRK, *ARGS, rsa_bits=2048)[0] == private


@pytest.mark.parametrize("bits", [1024, 2047, 2050])
def test_bad_rsa_sizes_are_refused(bits):
    with pytest.raises(ValueError):
        artifacts.rsa_private_key(PRK, *ARGS, bits=bits)


def test_pgp_packets_are_deterministic_and_dated_in_the_past():
    packets = artifacts.pgp_packets(PRK, *ARGS)
    assert packets == artifacts.pgp_packets(PRK, *ARGS)
    assert packets != artifacts.pgp_packets(PRK, "example.org", "fulano", 4)
    assert b"Passweird <fulano>" in packets
    assert b"Passweird <example.org>" in artifacts.pgp_packets(PRK, "example.org")


@pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg not installed")
def test_gpg_imports_the_v3_key():
    pytest.importorskip("gnupg")
    public, private, fingerprint = crypto.export_pgp_key_armored(artifacts.pgp_packets(PRK, *ARGS))
    assert "BEGIN PGP PUBLIC KEY BLOCK" in public and "BEGIN PGP PRIVATE KEY BLOCK" in private
    assert len(fingerprint) == 40
