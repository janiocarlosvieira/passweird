# Passweird v3 - SSH, TLS and OpenPGP key material (ADR-0009 §4)
# Licensed under the GNU General Public License v3.0
"""
Derives the seeds with the v3 purposes and hands them to the format builders
in passweird.crypto, which are shared with the v2 engine and derive nothing
themselves. This is the only v3 module that imports a v2 one.

Every seed is bound to (site, login, counter) through the length-prefixed
info of §4, so no field can be shifted into another and each purpose has its
own label: the ambiguity ADR-0004 fixed by convention cannot be expressed.

A published public key remains an offline oracle for master + boost
(ADR-0003), now at full Argon2id cost per guess.
"""
from cryptography.hazmat.primitives.asymmetric import ed25519

from .. import crypto
from . import derive

MIN_RSA_BITS = 2048


def ssh_keypair(prk, site, login="", counter=1):
    """Returns (private_openssh, public_openssh) for an Ed25519 key."""
    seed = derive.okm(prk, "ssh-ed25519", 32, site, login, counter)
    checkint = derive.okm(prk, "ssh-checkint", 4, site, login, counter)
    return crypto.openssh_keypair_from_seed(seed, checkint)


def rsa_private_key(prk, site, login="", counter=1, bits=MIN_RSA_BITS):
    if bits < MIN_RSA_BITS or bits % 16 != 0:
        raise ValueError(f"RSA key size must be at least {MIN_RSA_BITS} bits and a multiple of 16 (got {bits})")
    half = bits // 2

    def source(purpose):
        return lambda candidate: derive.okm(prk, purpose, bits // 16, site, login, counter,
                                            derive.rsa_extra(bits, candidate))

    p = crypto.derive_prime_from_candidates(source("tls-rsa-p"), half)
    q = crypto.derive_prime_from_candidates(source("tls-rsa-q"), half, avoid=p)
    return crypto.rsa_key_from_primes(p, q, bits)


def tls_certificate(prk, site, login="", counter=1, rsa_bits=None):
    """Returns (private_key_pem, certificate_pem), self-signed, CN = site."""
    if rsa_bits:
        private_key = rsa_private_key(prk, site, login, counter, rsa_bits)
    else:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
            derive.okm(prk, "tls-ed25519", 32, site, login, counter))
    serial = derive.okm(prk, "tls-serial", 19, site, login, counter)
    return crypto.self_signed_certificate(private_key, site, serial, use_rsa=bool(rsa_bits))


def pgp_packets(prk, site, login="", counter=1):
    """Raw OpenPGP packets for crypto.export_pgp_key_armored()."""
    seed = derive.okm(prk, "pgp-ed25519", 32, site, login, counter)
    ctime = derive.okm(prk, "pgp-ctime", 4, site, login, counter)
    return crypto.pgp_packets_from_seed(seed, ctime, f"Passweird <{login or site}>")

