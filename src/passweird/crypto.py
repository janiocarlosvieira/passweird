# crypto.py
# Passweird - Deterministic Key, Identity, and RAM Security Engine
# Licensed under the GNU General Public License v3.0

import hashlib
import hmac
import math
import string
import datetime
import ctypes
import os
import base64
import struct
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def wipe_string_from_ram(target_string):
    """
    Low-level RAM wiping mechanism. Overwrites the memory buffer of the 
    string with null bytes to prevent sensitive keys from lingering in memory.
    """
    if not isinstance(target_string, str):
        return
    offset = ctypes.sizeof(ctypes.c_size_t) * 2 + ctypes.sizeof(ctypes.c_void_p)
    location = id(target_string) + offset
    length = len(target_string)
    ctypes.memset(location, 0, length)

KEYFILE_MAGIC = b"PWKF1\n"

def blend_secondary_factor(base_hash, factor_bytes):
    """
    Blends arbitrary secondary-factor entropy (keyfile bytes, a FIDO2 hmac-secret
    output, etc.) into an already-computed hash — the same formula modified_hash
    uses internally for its keyfile branch, factored out so other factors (e.g.
    FIDO2, which needs the app_hash before it can compute its salt, so it can't
    be applied inside modified_hash itself) can reuse it consistently.
    """
    blended = base_hash.encode() + hashlib.sha256(factor_bytes).digest()
    return hashlib.sha256(blended).hexdigest()

def modified_hash(value, keyfile_path=None):
    """
    Custom pre-hashing execution to protect the master key in local memory.
    If a keyfile is provided, it blends physical entropy into the hash derivation.
    Keyfiles written by generate_random_keyfile/generate_hybrid_keyfile are
    encrypted at rest (detected via KEYFILE_MAGIC) and are decrypted here using
    the pre-blend hash as the AES key; a wrong master password therefore fails
    decryption loudly instead of silently degrading to an unblended hash.
    """
    first_hash = hashlib.sha256(value.encode()).hexdigest()
    hash_wo_last = first_hash[:-1]
    derived = hashlib.sha256(hash_wo_last.encode()).hexdigest()

    if keyfile_path:
        if not os.path.exists(keyfile_path):
            raise FileNotFoundError(f"Keyfile not found: {keyfile_path}")
        with open(keyfile_path, "rb") as kf:
            raw = kf.read()
        if raw.startswith(KEYFILE_MAGIC):
            keyfile_entropy = bytes.fromhex(decrypt_data(derived, raw[len(KEYFILE_MAGIC):]))
        else:
            keyfile_entropy = raw
        derived = blend_secondary_factor(derived, keyfile_entropy)

    return derived

def _write_encrypted_keyfile(master_hash, raw_entropy, output_path):
    """Writes raw_entropy to output_path encrypted at rest under KEYFILE_MAGIC,
    using master_hash as the AES key (same value modified_hash's keyfile-read
    branch decrypts with) — see modified_hash() for the read side."""
    payload = encrypt_data(master_hash, raw_entropy.hex())
    with open(output_path, "wb") as kf:
        kf.write(KEYFILE_MAGIC + payload)

def generate_random_keyfile(master_hash, output_path, size=64):
    """
    Writes a purely random secret (os.urandom) to output_path, encrypted at
    rest with the current master_hash. Pure "something you have" factor:
    losing the file (without a separate backup) means losing the factor
    permanently, same security model as a hardware token.
    """
    _write_encrypted_keyfile(master_hash, os.urandom(size), output_path)

def generate_hybrid_keyfile(master_hash, recovery_phrase, output_path):
    """
    Generates a 512-byte deterministic keyfile derived from the master hash +
    a recovery phrase (HKDF), written encrypted at rest (same envelope as
    generate_random_keyfile). Regenerable purely from memory (master password
    + recovery phrase) if the physical file/device is lost.
    """
    raw_entropy = hkdf_expand(master_hash.encode(), recovery_phrase.encode(), 512)
    _write_encrypted_keyfile(master_hash, raw_entropy, output_path)

def derive_encryption_key(master_hash, salt, iterations=100_000):
    """Derives a strong 256-bit AES key using PBKDF2-HMAC-SHA256 from the master key."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations
    )
    return kdf.derive(master_hash.encode())

def encrypt_data(master_hash, plain_text):
    """Encrypts local payloads using state-of-the-art AES-256-GCM."""
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_encryption_key(master_hash, salt)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(plain_text.encode()) + encryptor.finalize()
    return salt + iv + encryptor.tag + ciphertext

def decrypt_data(master_hash, encrypted_bytes):
    """Decrypts GCM payloads, validating payload integrity natively."""
    try:
        salt = encrypted_bytes[:16]
        iv = encrypted_bytes[16:28]
        tag = encrypted_bytes[28:44]
        ciphertext = encrypted_bytes[44:]
        key = derive_encryption_key(master_hash, salt)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode('utf-8')
    except Exception:
        raise ValueError("Decryption failed. Invalid master key or corrupted data.")

def summarize_hash(hash_value):
    """Returns a short 20-character summary of a hash for safe logging."""
    return hash_value[:10] + hash_value[-10:]

def summarize_password_hash(password):
    """Hashes a password and returns its 20-character visual summary."""
    pwd_hash = hashlib.sha256(password.encode()).hexdigest()
    return summarize_hash(pwd_hash)

def hkdf_expand(prk, info, length):
    """Standard HKDF-Expand function (RFC 5869) using HMAC-SHA512 primitives."""
    hash_len = 64
    if length > 255 * hash_len:
        raise ValueError("Requested length too large for HKDF-Expand.")
    
    t = b""
    okm = b""
    i = 1
    while len(okm) < length:
        ctx = t + info + bytes([i])
        t = hmac.new(prk, ctx, hashlib.sha512).digest()
        okm += t
        i += 1
    return okm[:length]

def generate_password_hkdf(master_hash, app_hash, length=18, 
                           use_upper=True, use_lower=True, use_digits=True, use_special=True, 
                           temporal_salt=""):
    """
    Generates deterministic passwords using HKDF-SHA512 with a compliance loop.
    Guarantees selected character classes without manual byte structural replacement.
    """
    is_numeric_only = use_digits and not (use_upper or use_lower or use_special)
    min_len = 6 if is_numeric_only else 8
    
    if length < min_len:
        raise ValueError(f"Minimum recommended length is {min_len} characters.")
        
    lowers = string.ascii_lowercase if use_lower else ''
    uppers = string.ascii_uppercase if use_upper else ''
    digits = string.digits if use_digits else ''
    specials = "!@#$%^&*()_+-=." if use_special else ''
    charset = lowers + uppers + digits + specials
    
    if not charset:
        raise ValueError("At least one character type must be enabled.")

    prk = master_hash.encode()
    nonce = 0
    while True:
        info = f"{app_hash}:{length}:{temporal_salt}:{nonce}".encode()
        raw_bytes = hkdf_expand(prk, info, length)
        password = ''.join(charset[b % len(charset)] for b in raw_bytes)
        
        has_lower = any(c in lowers for c in password) if use_lower else True
        has_upper = any(c in uppers for c in password) if use_upper else True
        has_digits = any(c in digits for c in password) if use_digits else True
        has_special = any(c in specials for c in password) if use_special else True
        
        if has_lower and has_upper and has_digits and has_special:
            return password
            
        nonce += 1

def generate_password(version, master_hash, app_hash, length=18, temporal_salt="", **kwargs):
    """Router architecture to maintain cryptographic engine versioning control."""
    if version == 'v2':
        return generate_password_hkdf(master_hash, app_hash, length, temporal_salt=temporal_salt, **kwargs)
    else:
        raise ValueError("This cryptographic engine only supports standardized v2 (HKDF).")

def _ssh_string(data):
    """SSH wire-format 'string': 4-byte big-endian length + raw bytes."""
    return len(data).to_bytes(4, "big") + data

def generate_deterministic_ssh_key(master_hash, app_hash, temporal_salt=""):
    """
    Derives a standard Ed25519 SSH Key Pair deterministically from a 32-byte
    seed. The OpenSSH private key container is assembled by hand (rather than
    via cryptography's private_bytes(..., format=OpenSSH, ...)) because that
    serializer embeds two random 32-bit "checkint" values on every call —
    they're only required to match each other, not to be random, but their
    randomness silently breaks the determinism guarantee this whole tool is
    built on. Verified importable via `ssh-keygen`/`ssh-add`.
    """
    prk = master_hash.encode()
    info = f"{app_hash}:ssh_seed:{temporal_salt}".encode()
    seed = hkdf_expand(prk, info, 32)

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    pubkey_blob = _ssh_string(b"ssh-ed25519") + _ssh_string(pub_bytes)

    # Own label rather than info + b":checkint": temporal_salt is user-controlled free
    # text and sits at the end of info, so appending a literal suffix after it makes the
    # encoding ambiguous — a salt of "X:checkint" would derive its key from exactly the
    # bytes that a salt of "X" derives its checkint from. See _derive_prime for the
    # general rule: nothing is ever appended after the salt.
    checkint = hkdf_expand(prk, f"{app_hash}:ssh_checkint:{temporal_salt}".encode(), 4)
    privkey_blob = (
        checkint + checkint
        + _ssh_string(b"ssh-ed25519")
        + _ssh_string(pub_bytes)
        + _ssh_string(seed + pub_bytes)
        + _ssh_string(b"")  # comment
    )
    pad_len = (-len(privkey_blob)) % 8
    privkey_blob += bytes(range(1, pad_len + 1))

    container = (
        b"openssh-key-v1\x00"
        + _ssh_string(b"none")   # cipher
        + _ssh_string(b"none")   # kdf
        + _ssh_string(b"")       # kdf options
        + (1).to_bytes(4, "big")  # number of keys
        + _ssh_string(pubkey_blob)
        + _ssh_string(privkey_blob)
    )

    b64 = base64.b64encode(container).decode()
    wrapped = "\n".join(b64[i:i + 70] for i in range(0, len(b64), 70))
    private_openssh = f"-----BEGIN OPENSSH PRIVATE KEY-----\n{wrapped}\n-----END OPENSSH PRIVATE KEY-----\n"

    public_openssh = f"ssh-ed25519 {base64.b64encode(pubkey_blob).decode()}\n"

    return private_openssh, public_openssh

RSA_PUBLIC_EXPONENT = 65537

def _sieve_small_primes(limit):
    """Classic sieve of Eratosthenes, used to build the trial-division table."""
    flags = bytearray([1]) * limit
    flags[0] = flags[1] = 0
    for i in range(2, int(limit ** 0.5) + 1):
        if flags[i]:
            flags[i * i::i] = bytearray(len(range(i * i, limit, i)))
    return [i for i, is_prime in enumerate(flags) if is_prime]

# Computed once at import (~10ms). Trial division against every prime below 65536
# rejects roughly 84% of odd candidates before a single modular exponentiation is
# performed, and that is what keeps deterministic RSA generation in the
# sub-second range for 2048-bit keys.
_SMALL_PRIMES = _sieve_small_primes(65536)

# Fixed bases first: they are a very strong filter and cost nothing to hardcode.
_MR_FIXED_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)

def _miller_rabin_bases(n, count):
    """
    Derives Miller-Rabin bases deterministically from n itself. Using secrets/random
    here would silently destroy reproducibility — the whole point of this module — so
    the bases have to be a pure function of the candidate.

    Deriving them from n (rather than fixing them) matters because the candidate is
    ultimately steered by a user-supplied context string: with a published fixed base
    set, someone could grind contexts until they hit a strong pseudoprime that passes
    all of them. Making the bases unpredictable-until-n-is-known forces that search to
    be redone per candidate.
    """
    digest = hashlib.sha512(n.to_bytes((n.bit_length() + 7) // 8, "big")).digest()
    return [
        2 + int.from_bytes(hashlib.sha512(digest + bytes([i])).digest(), "big") % (n - 4)
        for i in range(count)
    ]

def _is_probable_prime(n, extra_rounds=12):
    """
    Trial division followed by Miller-Rabin with 12 fixed + 12 derived bases.
    24 rounds puts the false-positive probability around 2^-48; the only party
    harmed by a composite slipping through would be the user whose key it is.
    """
    if n < 2:
        return False
    for small in _SMALL_PRIMES:
        if n == small:
            return True
        if n % small == 0:
            return False

    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    def is_witness(a):
        """True when a proves n composite."""
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return False
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                return False
        return True

    # Base 2 runs first on purpose: nearly every candidate that survives trial
    # division dies here, so the remaining bases are rarely reached.
    for base in _MR_FIXED_BASES:
        if is_witness(base):
            return False
    for base in _miller_rabin_bases(n, extra_rounds):
        if is_witness(base):
            return False
    return True

def _derive_prime(prk, label, bits, avoid=None):
    """
    Derives a prime of exactly `bits` bits from the HKDF stream by rejection
    sampling: every rejected candidate bumps a counter that feeds back into the
    HKDF info, producing a fresh independent candidate.

    Rejection rather than "walk upwards to the next prime": incremental search
    picks a prime with probability proportional to the gap preceding it, which
    over-samples primes that follow large gaps. FIPS 186-5 B.3.3 forbids it, and
    measurements showed no speed advantage anyway.
    """
    counter = 0
    min_distance = 1 << (bits - 100)
    while True:
        raw = hkdf_expand(prk, label + b":%d" % counter, bits // 8)
        counter += 1
        candidate = int.from_bytes(raw, "big")
        # Top two bits: guarantee p*q lands on the full requested bit length.
        # Bottom bit: odd. Note there is deliberately no modular reduction into a
        # range here — 'mod' over a span that is not a power of two would bias the
        # low end of that span.
        candidate |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1

        # gcd(e, p-1) must be 1 or the private exponent does not exist.
        if (candidate - 1) % RSA_PUBLIC_EXPONENT == 0:
            continue
        # FIPS 186-5 minimum distance between the two primes; a small |p-q| makes
        # the modulus trivially factorable by Fermat's method.
        if avoid is not None and abs(candidate - avoid) < min_distance:
            continue
        if _is_probable_prime(candidate):
            return candidate

def generate_deterministic_rsa_key(master_hash, app_hash, rsa_bits=2048, temporal_salt=""):
    """
    Derives a reproducible RSA key pair from the master hash.

    RSA key generation has exactly one source of randomness — the choice of p and q —
    so replacing the CSPRNG with the HKDF stream this module already uses makes the
    whole key deterministic. cryptography/OpenSSL offers no seeded rsa.generate_private_key(),
    hence the primes are derived here and the key is assembled through RSAPrivateNumbers;
    that constructor validates the CRT parameters, which doubles as a free self-check.

    Cost on a plain CPU, pure CPython: ~0.2s at 2048 bits, ~2s at 4096 bits. The spread
    is wide (prime gaps are luck of the draw), not a function of the hardware.
    """
    if rsa_bits < 2048 or rsa_bits % 16 != 0:
        raise ValueError(
            f"RSA key size must be at least 2048 bits and a multiple of 16 (got {rsa_bits})."
        )

    prk = master_hash.encode()
    half = rsa_bits // 2
    # Distinct HKDF labels rather than mangling the user's input (e.g. reversing the
    # keyword) to get the second prime: same pattern as :ssh_seed:/:ssl_seed/:serial,
    # and unlike an ad-hoc transform it gives a principled independence argument.
    #
    # temporal_salt matters more here than anywhere else in the project: the context
    # is printed in the certificate's CN, so against anyone holding the certificate it
    # contributes no guessing entropy at all. The temporal secret is the only
    # unpredictable input that does not leak with the artifact.
    base_info = f"{app_hash}:rsa_seed:{temporal_salt}".encode()

    p = _derive_prime(prk, base_info + b":p", half)
    q = _derive_prime(prk, base_info + b":q", half, avoid=p)
    if p < q:
        p, q = q, p

    n = p * q
    if n.bit_length() != rsa_bits:
        raise ValueError(f"Derived modulus has {n.bit_length()} bits, expected {rsa_bits}.")

    lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    d = pow(RSA_PUBLIC_EXPONENT, -1, lam)

    return rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=rsa.rsa_crt_dmp1(d, p),
        dmq1=rsa.rsa_crt_dmq1(d, q),
        iqmp=rsa.rsa_crt_iqmp(p, q),
        public_numbers=rsa.RSAPublicNumbers(RSA_PUBLIC_EXPONENT, n),
    ).private_key()

def generate_ssl_certificate(master_hash, app_hash, domain_context, use_rsa=False,
                             rsa_bits=2048, temporal_salt=""):
    """
    Generates a deterministic self-signed SSL/TLS Certificate using Ed25519 or RSA.

    Derivation keys off app_hash (like every other generator here); domain_context is
    only what goes into the certificate's Common Name. Those are separate arguments
    because the CN is published with the certificate, so it cannot be relied on for
    any secrecy — which is precisely why temporal_salt is part of the derivation.
    """
    prk = master_hash.encode()
    info = f"{app_hash}:ssl_seed:{temporal_salt}".encode()

    if use_rsa:
        private_key = generate_deterministic_rsa_key(master_hash, app_hash, rsa_bits, temporal_salt)
    else:
        seed = hkdf_expand(prk, info, 32)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain_context),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Passweird Self-Signed CA"),
    ])
    
    # Anchored to UTC midnight, not the current instant: X.509 validity fields have
    # one-second granularity, so two runs even a second apart used to emit different
    # certificate bytes despite identical key material. That was invisible while only
    # Ed25519 was deterministic (it generates in microseconds), but RSA generation
    # takes 0.2-4s, which would have made "--rsa is reproducible" a half-truth.
    # Truncating to the day makes the certificate byte-identical for any run within
    # the same UTC day; the key material itself is always identical.
    now = datetime.datetime.now(datetime.timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    # Deterministic serial number (derived from the same seed material) so the
    # certificate is reproducible run-to-run for the Ed25519 path; x509.random_serial_number()
    # would silently break determinism despite the key material being reproducible.
    #
    # Own label rather than info + b":serial": temporal_salt is user-controlled and ends
    # info, so a literal suffix after it is ambiguous. With the old encoding, a salt of
    # "X:serial" produced a private key whose first 19 bytes were exactly the serial
    # number published in the certificate generated with a salt of "X" — 152 of the 256
    # private seed bits, readable by anyone holding that certificate.
    serial_seed = hkdf_expand(prk, f"{app_hash}:ssl_serial:{temporal_salt}".encode(), 19)
    serial_number = int.from_bytes(serial_seed, "big") | 1

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        serial_number
    ).not_valid_before(
        now - datetime.timedelta(days=1)
    ).not_valid_after(
        now + datetime.timedelta(days=365)
    ).sign(private_key, None if not use_rsa else hashes.SHA256())
    
    # PKCS8 (not TraditionalOpenSSL) because TraditionalOpenSSL does not support Ed25519 keys.
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    return private_pem, cert_pem

def generate_deterministic_totp_secret(master_hash, app_hash, temporal_salt=""):
    """
    Derives a 160-bit (20-byte) TOTP seed deterministically (same pattern as
    generate_deterministic_ssh_key) and returns it Base32-encoded, ready to be
    used as a standard TOTP shared secret (RFC 6238).
    """
    prk = master_hash.encode()
    info = f"{app_hash}:totp_seed:{temporal_salt}".encode()
    raw = hkdf_expand(prk, info, 20)
    return base64.b32encode(raw).decode().rstrip("=")

# --- Minimal hand-rolled OpenPGP v4 (RFC 4880 + EdDSA/RFC4880bis) packet builders ---
# Only the fields required for a valid, importable Ed25519 secret key + self-signed
# User ID are implemented; formatting/armor correctness is delegated to `gpg` itself
# (via python-gnupg) once these raw packets are handed off for import/export.

_ED25519_OID = bytes.fromhex("2B06010401DA470F01")  # 1.3.6.1.4.1.11591.15.1

def _pgp_packet(tag, body):
    """New-format OpenPGP packet header (RFC 4880 4.2.2) + body."""
    header = bytes([0xC0 | tag])
    length = len(body)
    if length < 192:
        header += bytes([length])
    elif length < 8384:
        length -= 192
        header += bytes([(length >> 8) + 192, length & 0xFF])
    else:
        header += bytes([0xFF]) + length.to_bytes(4, "big")
    return header + body

def _pgp_subpacket(sp_type, body):
    """Signature subpacket (RFC 4880 5.2.3.1), including its own length prefix."""
    length = len(body) + 1
    if length < 192:
        length_bytes = bytes([length])
    elif length < 8384:
        length -= 192
        length_bytes = bytes([(length >> 8) + 192, length & 0xFF])
    else:
        length_bytes = bytes([0xFF]) + length.to_bytes(4, "big")
    return length_bytes + bytes([sp_type]) + body

def _pgp_mpi(data):
    """Multi-precision integer encoding (RFC 4880 3.2): 2-byte bit-length + bytes."""
    data = data.lstrip(b"\x00") or b"\x00"
    bitlen = (len(data) - 1) * 8 + (data[0].bit_length() if data[0] else 0)
    return struct.pack(">H", bitlen) + data

# Fixed window for the derived OpenPGP creation timestamp: 2000-01-01 plus up to
# 20 years. Permanently in the past, and independent of the wall clock so the
# fingerprint stays stable forever.
_PGP_CTIME_EPOCH = 946684800   # 2000-01-01T00:00:00Z
_PGP_CTIME_RANGE = 631152000   # 20 years in seconds

def generate_deterministic_pgp_key(master_hash, app_hash, temporal_salt="", uid="Passweird <generated@passweird.local>"):
    """
    Deterministically derives an Ed25519 seed (same hkdf_expand pattern as SSH/SSL/TOTP)
    and hand-assembles the minimal set of raw OpenPGP v4 packets needed for a valid,
    self-certified secret key: Secret-Key (tag 5) + User-ID (tag 13) + self-signature
    (tag 2). The creation timestamp is itself derived from the hash (not wall-clock
    time) so the whole key, including its fingerprint, is fully reproducible.
    Returns raw (non-armored) OpenPGP packet bytes, ready for gnupg.GPG().import_keys().
    """
    prk = master_hash.encode()
    info = f"{app_hash}:pgp_seed:{temporal_salt}".encode()
    seed = hkdf_expand(prk, info, 32)

    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key()
    pubkey_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    # Deterministic creation time, derived from the same seed material rather than
    # wall-clock "now" (the fingerprint/Key ID are computed over this timestamp too).
    # Own label, not info + b":ctime" — see the checkint note in
    # generate_deterministic_ssh_key for why a suffix after the salt is ambiguous.
    #
    # Mapped into a fixed past window rather than "% 2_000_000_000", which reached
    # 2033 and so produced a future-dated key for roughly one in nine inputs — gpg
    # refuses to import those ("failed to re-lookup public key"). The window cannot
    # follow the wall clock either: the timestamp is hashed into the fingerprint and
    # Key ID, so a drifting bound would silently change the key's identity over time.
    creation_time = _PGP_CTIME_EPOCH + (
        int.from_bytes(hkdf_expand(prk, f"{app_hash}:pgp_ctime:{temporal_salt}".encode(), 4), "big")
        % _PGP_CTIME_RANGE
    )

    pubkey_body = (
        bytes([4]) + creation_time.to_bytes(4, "big") + bytes([22])
        + bytes([len(_ED25519_OID)]) + _ED25519_OID
        + _pgp_mpi(b"\x40" + pubkey_bytes)
    )

    fingerprint = hashlib.sha1(bytes([0x99]) + len(pubkey_body).to_bytes(2, "big") + pubkey_body).digest()
    key_id = fingerprint[-8:]

    secret_mpi = _pgp_mpi(seed)
    checksum = sum(secret_mpi) & 0xFFFF
    secret_key_body = pubkey_body + bytes([0]) + secret_mpi + checksum.to_bytes(2, "big")

    uid_bytes = uid.encode("utf-8")

    hashed_subpackets = _pgp_subpacket(2, creation_time.to_bytes(4, "big")) + _pgp_subpacket(27, bytes([0x03]))
    unhashed_subpackets = _pgp_subpacket(16, key_id)

    sig_prefix = (
        bytes([4, 0x13, 22, 8]) + len(hashed_subpackets).to_bytes(2, "big") + hashed_subpackets
    )
    trailer = bytes([4, 0xFF]) + len(sig_prefix).to_bytes(4, "big")

    pubkey_preimage = bytes([0x99]) + len(pubkey_body).to_bytes(2, "big") + pubkey_body
    uid_preimage = bytes([0xB4]) + len(uid_bytes).to_bytes(4, "big") + uid_bytes
    digest = hashlib.sha256(pubkey_preimage + uid_preimage + sig_prefix + trailer).digest()

    signature_raw = private_key.sign(digest)
    sig_mpis = _pgp_mpi(signature_raw[:32]) + _pgp_mpi(signature_raw[32:])

    sig_body = (
        sig_prefix
        + len(unhashed_subpackets).to_bytes(2, "big") + unhashed_subpackets
        + digest[:2]
        + sig_mpis
    )

    return (
        _pgp_packet(5, secret_key_body)
        + _pgp_packet(13, uid_bytes)
        + _pgp_packet(2, sig_body)
    )

def export_pgp_key_armored(raw_packets):
    """
    Imports the raw packets from generate_deterministic_pgp_key() into a
    throwaway GnuPG keyring (via the `gpg` binary through python-gnupg) purely
    to get ASCII-armored public/private key blocks out, then discards the
    keyring — mirrors --ssh/--ssl's "print, don't silently mutate system
    state" behavior. Returns (public_armored, private_armored, fingerprint).
    """
    import gnupg
    import tempfile
    with tempfile.TemporaryDirectory(prefix="passweird_gpg_") as home:
        os.chmod(home, 0o700)
        gpg = gnupg.GPG(gnupghome=home)
        result = gpg.import_keys(raw_packets)
        if not result.fingerprints:
            raise ValueError(f"GPG import failed: {result.stderr}")
        fpr = result.fingerprints[0]
        public_armored = gpg.export_keys(fpr)
        private_armored = gpg.export_keys(fpr, secret=True, passphrase='', expect_passphrase=False)
        return public_armored, private_armored, fpr

# --- FIDO2 (YubiKey and similar) hardware-backed optional factor ---
# Uses the WebAuthn "prf" extension (standardized wrapper around CTAP2's
# hmac-secret): the same (physical device, credential, salt) triple always
# yields the same secret from the authenticator — a determinstic "something
# you have" factor, requiring a physical touch on the device every time by
# design (this is not silent/background — that's the point of a 2nd factor).

def _connect_fido2_client(rp_id="passweird.local"):
    """Isolates the actual hardware I/O so tests can monkeypatch this single
    function instead of needing a real physical security key."""
    from fido2.hid import CtapHidDevice
    from fido2.client import Fido2Client, UserInteraction

    devices = list(CtapHidDevice.list_devices())
    if not devices:
        raise RuntimeError("No FIDO2 device detected. Connect your security key and try again.")

    class _CliInteraction(UserInteraction):
        def prompt_up(self):
            print("Touch your FIDO2 security key now...")

        def request_pin(self, permissions, rp_id):
            import getpass
            return getpass.getpass("FIDO2 PIN: ")

        def request_uv(self, permissions, rp_id):
            return True

    return Fido2Client(devices[0], f"https://{rp_id}", user_interaction=_CliInteraction())

def register_fido2_credential(user_name="passweird-user", rp_id="passweird.local", client=None):
    """
    Creates a new resident FIDO2 credential with the PRF extension requested
    (requires a physical touch). Returns the raw credential_id bytes — only
    this ID should be persisted (~/.passweird/fido2.cred), never a secret.
    """
    client = client or _connect_fido2_client(rp_id)
    options = {
        "rp": {"id": rp_id, "name": "Passweird"},
        "user": {
            "id": hashlib.sha256(user_name.encode()).digest(),
            "name": user_name,
            "displayName": user_name,
        },
        "challenge": os.urandom(32),
        "pubKeyCredParams": [{"type": "public-key", "alg": -8}, {"type": "public-key", "alg": -7}],
        "extensions": {"prf": {}},
    }
    result = client.make_credential(options)
    return result.attestation_object.auth_data.credential_data.credential_id

def derive_fido2_secret(credential_id, salt, rp_id="passweird.local", client=None):
    """
    Requests the PRF/hmac-secret output for (credential_id, salt) from a
    connected FIDO2 authenticator (requires a physical touch). The same
    device + credential + salt always returns the same 32-byte secret.
    """
    client = client or _connect_fido2_client(rp_id)
    options = {
        "rp_id": rp_id,
        "challenge": os.urandom(32),
        "allow_credentials": [{"type": "public-key", "id": credential_id}],
        "extensions": {"prf": {"eval": {"first": salt}}},
    }
    result = client.get_assertion(options)
    return result.extension_results["prf"]["results"]["first"]