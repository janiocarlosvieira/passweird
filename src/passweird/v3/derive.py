# Passweird v3 - stretching, expansion and sampling (ADR-0009 §2-§5)
# Licensed under the GNU General Public License v3.0
"""
The frozen part of v3. Every function here takes inputs that are ALREADY in
canonical form (see canon.py); `Session.open` is the entry point that
canonicalises and then derives.

Nothing in this module reads or writes a file, and nothing it returns may be
stored: K0 and every PRK can regenerate all of the user's passwords.
"""
import base64
import hashlib
import hmac

from . import canon

# Changing ANY parameter means changing this string, which changes the salt
# and every HKDF info, and therefore every output. That is the mechanism by
# which the parameters are frozen (§2).
ALG = "passweird-v3/argon2id-v19-m262144-t3-p4/hkdf-sha512"

ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 262144
ARGON2_PARALLELISM = 4
ARGON2_VERSION = 0x13
K0_BYTES = 64

HASH_LEN = 64                      # SHA-512
PASSWORD_STREAM_BYTES = 4096
PASSWORD_TEMPLATE = 1

CHARSET_LOWER = "abcdefghijklmnopqrstuvwxyz"
CHARSET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CHARSET_DIGITS = "0123456789"
CHARSET_SPECIALS = "!@#$%^&*()_+-=."

FACTOR_NONE = "none"
FACTOR_KEYFILE = "keyfile"
KEYFILE_BYTES = 32

_FP_CONSONANTS = "bdfghjklmnprstvz"
_FP_VOWELS = "aeio"


class DerivationError(Exception):
    """A derivation that must fail closed rather than fall back."""


# --- §2: encoding ------------------------------------------------------------

def u8(n):
    return n.to_bytes(1, "big")


def u16(n):
    return n.to_bytes(2, "big")


def u32(n):
    return n.to_bytes(4, "big")


def u64(n):
    return n.to_bytes(8, "big")


def lp(x):
    """Length-prefixed field: U16(len) || bytes. Strings are UTF-8."""
    if isinstance(x, str):
        x = x.encode("utf-8")
    if len(x) > 0xFFFF:
        raise DerivationError("field longer than 65535 bytes")
    return u16(len(x)) + bytes(x)


# --- RFC 5869 over HMAC-SHA512 -----------------------------------------------

def hkdf_extract(salt, ikm):
    return hmac.new(bytes(salt), bytes(ikm), hashlib.sha512).digest()


def hkdf_expand(prk, info, length):
    if length > 255 * HASH_LEN:
        raise DerivationError("requested length too large for HKDF-Expand")
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(bytes(prk), block + info + bytes([counter]), hashlib.sha512).digest()
        okm += block
        counter += 1
    return okm[:length]


# --- §3: stretching ----------------------------------------------------------

def salt_for(user_id):
    return hashlib.sha256(lp(ALG) + lp("salt") + lp(user_id)).digest()


def stretch_input(master, boost):
    return lp(master) + lp(boost)


def stretch(master, boost, user_id):
    """
    K0 = Argon2id over master and boost TOGETHER. Neither can be tested
    without the other, and every guess pays the full memory-hard cost.
    Returns a bytearray so the caller can zero it.
    """
    from argon2.low_level import Type, hash_secret_raw

    k0 = hash_secret_raw(
        secret=stretch_input(master, boost),
        salt=salt_for(user_id),
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=K0_BYTES,
        type=Type.ID,
        version=ARGON2_VERSION,
    )
    return bytearray(k0)


def factor_tag(kind=FACTOR_NONE, factor_bytes=b""):
    if kind == FACTOR_NONE:
        if factor_bytes:
            raise DerivationError("factor 'none' takes no bytes")
    elif kind == FACTOR_KEYFILE:
        if len(factor_bytes) != KEYFILE_BYTES:
            raise DerivationError(f"a keyfile factor is exactly {KEYFILE_BYTES} bytes")
    else:
        raise DerivationError(f"unknown factor kind: {kind!r}")
    return hashlib.sha512(lp(ALG) + lp("factor") + lp(kind) + lp(factor_bytes)).digest()


def extract(k0, kind=FACTOR_NONE, factor_bytes=b""):
    """PRK[kind] = HKDF-Extract(salt=F, IKM=K0)."""
    if len(k0) != K0_BYTES:
        raise DerivationError("K0 has the wrong length")
    return bytearray(hkdf_extract(factor_tag(kind, factor_bytes), k0))


# --- §4: expansion -----------------------------------------------------------

def info(purpose, site="", login="", counter=0, extra=b""):
    return lp(ALG) + lp(purpose) + lp(site) + lp(login) + u32(counter) + lp(extra)


def okm(prk, purpose, length, site="", login="", counter=0, extra=b""):
    return hkdf_expand(prk, info(purpose, site, login, counter, extra), length)


def password_extra(length, classes):
    return u8(length) + u8(classes) + u8(PASSWORD_TEMPLATE)


def rsa_extra(bits, candidate):
    return u16(bits) + u32(candidate)


# --- §5: sampling ------------------------------------------------------------

def charset_for(classes):
    return (
        (CHARSET_LOWER if classes & canon.CLASS_LOWER else "")
        + (CHARSET_UPPER if classes & canon.CLASS_UPPER else "")
        + (CHARSET_DIGITS if classes & canon.CLASS_DIGITS else "")
        + (CHARSET_SPECIALS if classes & canon.CLASS_SPECIALS else "")
    )


def _enabled_classes(classes):
    return [
        chars for bit, chars in (
            (canon.CLASS_LOWER, CHARSET_LOWER), (canon.CLASS_UPPER, CHARSET_UPPER),
            (canon.CLASS_DIGITS, CHARSET_DIGITS), (canon.CLASS_SPECIALS, CHARSET_SPECIALS),
        ) if classes & bit
    ]


class ByteStream:
    """Sequential reader over a finite stream that fails closed when it ends."""

    def __init__(self, data):
        self._data = data
        self.position = 0
        self.byte_rejections = 0

    def next_byte(self):
        if self.position >= len(self._data):
            raise DerivationError("sampling stream exhausted")
        value = self._data[self.position]
        self.position += 1
        return value

    def uniform(self, n):
        """
        Unbiased integer in [0, n) for n <= 256, by rejection. `b % n` alone
        over-represents the low residues whenever 256 is not a multiple of n.
        """
        if not 1 <= n <= 256:
            raise DerivationError("uniform() needs 1 <= n <= 256")
        limit = 256 - (256 % n)
        while True:
            b = self.next_byte()
            if b < limit:
                return b % n
            self.byte_rejections += 1


def sample_password(stream_bytes, length, classes):
    """
    Uniform over the passwords of `length` that contain every enabled class:
    a candidate missing a class is discarded WHOLE and redrawn from the
    continuing stream. Returns (password, trace) where trace feeds the vectors.
    """
    charset = charset_for(classes)
    required = _enabled_classes(classes)
    stream = ByteStream(stream_bytes)
    candidate_rejections = 0
    while True:
        candidate = "".join(charset[stream.uniform(len(charset))] for _ in range(length))
        if all(any(ch in group for ch in candidate) for group in required):
            return candidate, {
                "byte_rejections": stream.byte_rejections,
                "candidate_rejections": candidate_rejections,
                "stream_bytes_used": stream.position,
            }
        candidate_rejections += 1


def password(prk, site, login="", counter=1, length=18, classes=15):
    stream = okm(prk, "password", PASSWORD_STREAM_BYTES, site, login, counter,
                 password_extra(length, classes))
    return sample_password(stream, length, classes)[0]


# --- other outputs -----------------------------------------------------------

def fingerprint(prk_none):
    """
    24 bits as four consonant-vowel syllables, e.g. 'kode-nafi'. Shown on every
    derivation and stored nowhere: it lets a person notice a typo without
    leaving anything on disk that a guess could be tested against.
    """
    raw = int.from_bytes(okm(prk_none, "fingerprint", 3), "big")
    syllables = []
    for shift in (18, 12, 6, 0):
        group = (raw >> shift) & 0x3F
        syllables.append(_FP_CONSONANTS[group >> 2] + _FP_VOWELS[group & 3])
    return "".join(syllables[:2]) + "-" + "".join(syllables[2:])


def totp_secret(prk, site, login="", counter=1):
    """160-bit TOTP seed, Base32 without padding (RFC 4648)."""
    return base64.b32encode(okm(prk, "totp", 20, site, login, counter)).decode("ascii").rstrip("=")


def wipe(buffer):
    """Best-effort zeroing of a mutable buffer. Python gives no guarantee."""
    if isinstance(buffer, bytearray):
        for i in range(len(buffer)):
            buffer[i] = 0


class Session:
    """
    The derivation tier for one run: holds K0-derived keys in memory only.

    `prk_none` is the local key (fingerprint, recovery wrap, keyfile wrap);
    `prk` is the key every site output derives from, which differs from
    `prk_none` only when a keyfile factor is in use.
    """

    def __init__(self, k0, user_id):
        self.user_id = user_id
        self._k0 = k0
        self.prk_none = extract(k0)
        self.prk = self.prk_none

    @classmethod
    def open(cls, master, boost, user_id):
        user_id = canon.user_id(user_id)
        return cls(stretch(canon.master(master), canon.boost(boost), user_id), user_id)

    def use_keyfile(self, factor_bytes):
        self.prk = extract(self._k0, FACTOR_KEYFILE, factor_bytes)

    @property
    def fingerprint(self):
        return fingerprint(self.prk_none)

    def password(self, site, login="", counter=1, length=18, classes=15):
        classes = canon.classes(classes)
        return password(self.prk, canon.site(site), canon.login(login), canon.counter(counter),
                        canon.length(length, classes), classes)

    def totp_secret(self, site, login="", counter=1):
        return totp_secret(self.prk, canon.site(site), canon.login(login), canon.counter(counter))

    def okm(self, purpose, length, site="", login="", counter=0, extra=b"", local=False):
        return okm(self.prk_none if local else self.prk, purpose, length, site, login, counter, extra)

    def close(self):
        wipe(self._k0)
        wipe(self.prk_none)
        wipe(self.prk)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
