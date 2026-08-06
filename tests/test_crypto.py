import os
from passweird import crypto


import pyotp
import pytest



def test_hkdf_expand_deterministic_and_length():
    a = crypto.hkdf_expand(b"prk", b"info", 50)
    b = crypto.hkdf_expand(b"prk", b"info", 50)
    assert a == b
    assert len(a) == 50
    assert crypto.hkdf_expand(b"prk", b"other-info", 50) != a


def test_generate_password_hkdf_deterministic():
    mh = crypto.modified_hash("master")
    ah = crypto.modified_hash("app")
    p1 = crypto.generate_password_hkdf(mh, ah, 18)
    p2 = crypto.generate_password_hkdf(mh, ah, 18)
    assert p1 == p2
    assert len(p1) == 18


def test_generate_password_hkdf_character_classes():
    mh = crypto.modified_hash("master")
    ah = crypto.modified_hash("app")
    pwd = crypto.generate_password_hkdf(mh, ah, 18)
    assert any(c.islower() for c in pwd)
    assert any(c.isupper() for c in pwd)
    assert any(c.isdigit() for c in pwd)
    assert any(c in "!@#$%^&*()_+-=." for c in pwd)

    pwd_digits_only = crypto.generate_password_hkdf(
        mh, ah, 8, use_upper=False, use_lower=False, use_special=False, use_digits=True
    )
    assert pwd_digits_only.isdigit()


def test_generate_password_hkdf_numeric_min_length_six():
    mh = crypto.modified_hash("master")
    ah = crypto.modified_hash("app")
    pwd = crypto.generate_password_hkdf(mh, ah, 6, use_upper=False, use_lower=False, use_special=False)
    assert len(pwd) == 6
    with pytest.raises(ValueError):
        crypto.generate_password_hkdf(mh, ah, 5, use_upper=False, use_lower=False, use_special=False)


def test_generate_password_hkdf_min_length_eight_with_letters():
    mh = crypto.modified_hash("master")
    ah = crypto.modified_hash("app")
    with pytest.raises(ValueError):
        crypto.generate_password_hkdf(mh, ah, 7)


def test_generate_password_rejects_non_v2():
    mh = crypto.modified_hash("master")
    ah = crypto.modified_hash("app")
    with pytest.raises(ValueError):
        crypto.generate_password("v1", mh, ah, 18)


def test_modified_hash_plain_deterministic():
    assert crypto.modified_hash("master") == crypto.modified_hash("master")
    assert crypto.modified_hash("master") != crypto.modified_hash("other")


def test_modified_hash_generic_keyfile_blend(tmp_path):
    keyfile = tmp_path / "generic.key"
    keyfile.write_bytes(b"arbitrary external file bytes")
    mh = crypto.modified_hash("master")
    h1 = crypto.modified_hash("master", keyfile_path=str(keyfile))
    h2 = crypto.modified_hash("master", keyfile_path=str(keyfile))
    assert h1 == h2
    assert h1 != mh


def test_modified_hash_missing_keyfile_raises():
    with pytest.raises(FileNotFoundError):
        crypto.modified_hash("master", keyfile_path="/no/such/keyfile")


def test_random_keyfile_roundtrip(tmp_path):
    mh = crypto.modified_hash("master")
    path = tmp_path / "random.key"
    crypto.generate_random_keyfile(mh, str(path))
    h1 = crypto.modified_hash("master", keyfile_path=str(path))
    h2 = crypto.modified_hash("master", keyfile_path=str(path))
    assert h1 == h2

    with pytest.raises(ValueError):
        crypto.modified_hash("WRONG-master", keyfile_path=str(path))


def test_hybrid_keyfile_regenerable_from_recovery_phrase(tmp_path):
    mh = crypto.modified_hash("master")
    path_a = tmp_path / "hybrid_a.key"
    path_b = tmp_path / "hybrid_b.key"
    crypto.generate_hybrid_keyfile(mh, "recovery phrase", str(path_a))
    crypto.generate_hybrid_keyfile(mh, "recovery phrase", str(path_b))

    h_a = crypto.modified_hash("master", keyfile_path=str(path_a))
    h_b = crypto.modified_hash("master", keyfile_path=str(path_b))
    assert h_a == h_b

    crypto.generate_hybrid_keyfile(mh, "different phrase", str(path_b))
    h_b_diff = crypto.modified_hash("master", keyfile_path=str(path_b))
    assert h_b_diff != h_a


def test_blend_secondary_factor_deterministic():
    base = crypto.modified_hash("master")
    b1 = crypto.blend_secondary_factor(base, b"some external secret")
    b2 = crypto.blend_secondary_factor(base, b"some external secret")
    assert b1 == b2
    assert b1 != base
    assert crypto.blend_secondary_factor(base, b"different secret") != b1


def test_generate_deterministic_ssh_key():
    mh = crypto.modified_hash("master")
    ah = crypto.modified_hash("app")
    priv1, pub1 = crypto.generate_deterministic_ssh_key(mh, ah, "2026/01")
    priv2, pub2 = crypto.generate_deterministic_ssh_key(mh, ah, "2026/01")
    assert priv1 == priv2
    assert pub1 == pub2
    priv3, _ = crypto.generate_deterministic_ssh_key(mh, ah, "2026/02")
    assert priv3 != priv1


def test_generate_ssl_certificate_deterministic_and_parseable():
    from cryptography import x509

    mh = crypto.modified_hash("master")
    ah = crypto.modified_hash("example.com")
    priv1, cert1 = crypto.generate_ssl_certificate(mh, ah, "example.com")
    priv2, cert2 = crypto.generate_ssl_certificate(mh, ah, "example.com")
    assert priv1 == priv2
    assert cert1 == cert2

    parsed = x509.load_pem_x509_certificate(cert1.encode())
    assert parsed.subject.rfc4514_string().find("example.com") != -1


def test_generate_deterministic_totp_secret():
    mh = crypto.modified_hash("master")
    ah = crypto.modified_hash("app")
    s1 = crypto.generate_deterministic_totp_secret(mh, ah)
    s2 = crypto.generate_deterministic_totp_secret(mh, ah)
    assert s1 == s2
    totp = pyotp.TOTP(s1)
    code = totp.now()
    assert code.isdigit() and len(code) == 6


def test_generate_deterministic_pgp_key_and_gpg_import():
    gnupg = pytest.importorskip("gnupg")
    if not any(os.access(os.path.join(p, "gpg"), os.X_OK) for p in os.environ.get("PATH", "").split(os.pathsep)):
        pytest.skip("gpg binary not available")

    mh = crypto.modified_hash("master")
    ah = crypto.modified_hash("app")
    raw1 = crypto.generate_deterministic_pgp_key(mh, ah)
    raw2 = crypto.generate_deterministic_pgp_key(mh, ah)
    assert raw1 == raw2

    pub, priv, fpr = crypto.export_pgp_key_armored(raw1)
    assert "BEGIN PGP PUBLIC KEY BLOCK" in pub
    assert "BEGIN PGP PRIVATE KEY BLOCK" in priv
    assert len(fpr) == 40


class _FakeFido2Client:
    """Minimal stand-in for fido2.client.Fido2Client, since no physical
    security key is available in this environment."""

    def __init__(self):
        self._secrets = {}

    def make_credential(self, options):
        class _CredData:
            credential_id = b"fake-credential-id-0123456789"

        class _AuthData:
            credential_data = _CredData()

        class _Attestation:
            auth_data = _AuthData()

        class _Result:
            attestation_object = _Attestation()

        return _Result()

    def get_assertion(self, options):
        salt = options["extensions"]["prf"]["eval"]["first"]
        cred_id = options["allow_credentials"][0]["id"]
        key = (cred_id, salt)
        if key not in self._secrets:
            self._secrets[key] = os.urandom(32)

        class _Result:
            extension_results = {"prf": {"results": {"first": self._secrets[key]}}}

        return _Result()


def test_fido2_derive_secret_deterministic_with_mocked_client():
    client = _FakeFido2Client()
    credential_id = crypto.register_fido2_credential(client=client)
    salt = b"x" * 32
    secret1 = crypto.derive_fido2_secret(credential_id, salt, client=client)
    secret2 = crypto.derive_fido2_secret(credential_id, salt, client=client)
    assert secret1 == secret2

    other_salt = b"y" * 32
    secret3 = crypto.derive_fido2_secret(credential_id, other_salt, client=client)
    assert secret3 != secret1


# --- Deterministic RSA -------------------------------------------------------
# Key generation costs ~1s, so anything that can share a key uses this fixture
# instead of deriving its own.

@pytest.fixture(scope="module")
def rsa_master_hash():
    return crypto.modified_hash("master")


@pytest.fixture(scope="module")
def rsa_app_hash():
    return crypto.modified_hash("example.com")


@pytest.fixture(scope="module")
def rsa_key_2048(rsa_master_hash, rsa_app_hash):
    return crypto.generate_deterministic_rsa_key(rsa_master_hash, rsa_app_hash, 2048)


def test_deterministic_rsa_key_reproducible(rsa_master_hash, rsa_app_hash, rsa_key_2048):
    again = crypto.generate_deterministic_rsa_key(rsa_master_hash, rsa_app_hash, 2048)
    first, second = rsa_key_2048.private_numbers(), again.private_numbers()
    assert first.p == second.p
    assert first.q == second.q
    assert first.d == second.d
    assert first.public_numbers.n == second.public_numbers.n


def test_deterministic_rsa_key_varies_by_context(rsa_master_hash, rsa_key_2048):
    baseline = rsa_key_2048.private_numbers().public_numbers.n
    other_context = crypto.generate_deterministic_rsa_key(rsa_master_hash, crypto.modified_hash("other.com"), 2048)
    assert other_context.private_numbers().public_numbers.n != baseline


def test_deterministic_rsa_key_varies_by_master_hash(rsa_app_hash, rsa_key_2048):
    baseline = rsa_key_2048.private_numbers().public_numbers.n
    other_master = crypto.generate_deterministic_rsa_key(
        crypto.modified_hash("different master"), rsa_app_hash, 2048
    )
    assert other_master.private_numbers().public_numbers.n != baseline


def test_deterministic_rsa_key_structure(rsa_key_2048):
    import math

    numbers = rsa_key_2048.private_numbers()
    p, q, d = numbers.p, numbers.q, numbers.d
    n, e = numbers.public_numbers.n, numbers.public_numbers.e

    assert e == crypto.RSA_PUBLIC_EXPONENT == 65537
    assert n == p * q
    assert n.bit_length() == 2048
    assert p != q
    assert math.gcd(e, p - 1) == 1
    assert math.gcd(e, q - 1) == 1
    # FIPS 186-5 minimum distance, otherwise Fermat factors the modulus.
    assert abs(p - q) > 2 ** (1024 - 100)
    assert (d * e) % math.lcm(p - 1, q - 1) == 1


def test_deterministic_rsa_primes_are_prime(rsa_key_2048):
    """Cross-checks our Miller-Rabin against sympy's independent Baillie-PSW."""
    sympy = pytest.importorskip("sympy")
    numbers = rsa_key_2048.private_numbers()
    assert sympy.isprime(numbers.p)
    assert sympy.isprime(numbers.q)


def test_deterministic_rsa_key_signs_and_verifies(rsa_key_2048):
    """Proves the CRT parameters are correct and that OpenSSL accepts the key."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    message = b"passweird deterministic rsa"
    signature = rsa_key_2048.sign(message, padding.PKCS1v15(), hashes.SHA256())
    rsa_key_2048.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())


@pytest.mark.parametrize("bad_bits", [0, 1024, 2049, 2050, -2048])
def test_deterministic_rsa_key_rejects_bad_sizes(rsa_master_hash, rsa_app_hash, bad_bits):
    with pytest.raises(ValueError):
        crypto.generate_deterministic_rsa_key(rsa_master_hash, rsa_app_hash, bad_bits)


@pytest.mark.slow
def test_deterministic_rsa_key_3072(rsa_master_hash, rsa_app_hash):
    """Covers a half-size that is not 1024 bits."""
    key = crypto.generate_deterministic_rsa_key(rsa_master_hash, rsa_app_hash, 3072)
    numbers = key.private_numbers()
    assert numbers.public_numbers.n.bit_length() == 3072
    assert numbers.public_numbers.n == numbers.p * numbers.q


def test_ssl_certificate_rsa_reproducible(rsa_master_hash, rsa_app_hash):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    priv1, cert1 = crypto.generate_ssl_certificate(rsa_master_hash, rsa_app_hash, "example.com", use_rsa=True)
    priv2, cert2 = crypto.generate_ssl_certificate(rsa_master_hash, rsa_app_hash, "example.com", use_rsa=True)
    assert priv1 == priv2
    assert cert1 == cert2

    parsed = x509.load_pem_x509_certificate(cert1.encode())
    loaded = serialization.load_pem_private_key(priv1.encode(), password=None)
    assert parsed.public_key().public_numbers().n == loaded.private_numbers().public_numbers.n
    assert parsed.signature_algorithm_oid._name == "sha256WithRSAEncryption"


def test_ssl_certificate_rsa_differs_from_ed25519(rsa_master_hash, rsa_app_hash):
    _, rsa_cert = crypto.generate_ssl_certificate(rsa_master_hash, rsa_app_hash, "example.com", use_rsa=True)
    _, ed_cert = crypto.generate_ssl_certificate(rsa_master_hash, rsa_app_hash, "example.com")
    assert rsa_cert != ed_cert


# --- Primality helper --------------------------------------------------------

@pytest.mark.parametrize("value", [2, 3, 5, 7, 97, 65537, 104729, 2 ** 61 - 1])
def test_is_probable_prime_accepts_primes(value):
    assert crypto._is_probable_prime(value)


@pytest.mark.parametrize(
    "value",
    [
        -7, 0, 1, 4, 9, 100, 65536,
        561, 1105, 1729, 2465, 2821, 6601,   # Carmichael numbers
        3215031751,                           # strong pseudoprime to bases 2,3,5,7
        2 ** 61 - 3,
    ],
)
def test_is_probable_prime_rejects_composites(value):
    assert not crypto._is_probable_prime(value)


def test_miller_rabin_bases_are_deterministic_and_in_range():
    n = 2 ** 127 - 1
    first = crypto._miller_rabin_bases(n, 8)
    assert first == crypto._miller_rabin_bases(n, 8)
    assert len(first) == 8
    assert all(2 <= base <= n - 2 for base in first)
    assert crypto._miller_rabin_bases(n - 2, 8) != first


def test_derive_prime_is_deterministic_and_sized():
    prk = crypto.modified_hash("master").encode()
    first = crypto._derive_prime(prk, b"label", 256)
    assert first == crypto._derive_prime(prk, b"label", 256)
    assert first.bit_length() == 256
    assert crypto._is_probable_prime(first)
    assert crypto._derive_prime(prk, b"other-label", 256) != first


def test_derive_prime_honours_avoid_distance():
    prk = crypto.modified_hash("master").encode()
    p = crypto._derive_prime(prk, b"label", 256)
    # Asking for a prime that must stay far from p, using the same label: the
    # rejection loop has to walk past the candidate it would otherwise return.
    q = crypto._derive_prime(prk, b"label", 256, avoid=p)
    assert q != p
    assert abs(q - p) >= 2 ** (256 - 100)


# --- Temporal salt on the certificate path -----------------------------------
# The context name is published in the certificate CN, so the temporal secret is
# the only unpredictable derivation input that does not leak with the artifact.

def test_ssl_temporal_salt_changes_ed25519_key(rsa_master_hash, rsa_app_hash):
    priv_none, _ = crypto.generate_ssl_certificate(rsa_master_hash, rsa_app_hash, "example.com")
    priv_a, _ = crypto.generate_ssl_certificate(
        rsa_master_hash, rsa_app_hash, "example.com", temporal_salt="2026/01"
    )
    priv_b, _ = crypto.generate_ssl_certificate(
        rsa_master_hash, rsa_app_hash, "example.com", temporal_salt="2026/02"
    )
    assert len({priv_none, priv_a, priv_b}) == 3


def test_ssl_temporal_salt_changes_rsa_key(rsa_master_hash, rsa_app_hash):
    baseline = crypto.generate_deterministic_rsa_key(rsa_master_hash, rsa_app_hash, 2048)
    salted = crypto.generate_deterministic_rsa_key(
        rsa_master_hash, rsa_app_hash, 2048, temporal_salt="2026/01"
    )
    assert (salted.private_numbers().public_numbers.n
            != baseline.private_numbers().public_numbers.n)


def test_ssl_temporal_salt_is_reproducible(rsa_master_hash, rsa_app_hash):
    """Same salt must round-trip to the same key, or rotation is not usable."""
    first = crypto.generate_deterministic_rsa_key(
        rsa_master_hash, rsa_app_hash, 2048, temporal_salt="minha frase longa"
    )
    second = crypto.generate_deterministic_rsa_key(
        rsa_master_hash, rsa_app_hash, 2048, temporal_salt="minha frase longa"
    )
    assert first.private_numbers().p == second.private_numbers().p


def test_ssl_cn_is_independent_of_derivation(rsa_master_hash, rsa_app_hash):
    """
    The CN is cosmetic; the key comes from app_hash. Two certificates that differ
    only in CN must therefore carry the same key — this is the property that makes
    the CN leak harmless to the derivation, and dangerous as a secrecy assumption.
    """
    priv1, _ = crypto.generate_ssl_certificate(rsa_master_hash, rsa_app_hash, "example.com")
    priv2, _ = crypto.generate_ssl_certificate(rsa_master_hash, rsa_app_hash, "outro-nome.com")
    assert priv1 == priv2
