# Passweird v3 - the journal's key hierarchy (ADR-0009 §6)
# Licensed under the GNU General Public License v3.0
"""
The journal is encrypted under a random DEK. Two things can unwrap it:

- the ACCESS slot (keys.pw3, synced): Argon2id over the access password with
  its own random salt. Opening it reveals sites, counters and notes - never a
  password - and it is an offline oracle for the access password only.
- the RECOVERY wrap: a key derived from master + boost. By construction it IS
  an offline oracle for master + boost (at full Argon2id cost), which is why
  it is printed once and kept off disk unless the user explicitly opts in.

Changing the access password rewrites the slot around the SAME DEK, so an old
copy of keys.pw3 keeps opening the journal with the old password.
"""
import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import canon, derive

MAGIC_SLOTS = b"PW3S"
MAGIC_RECOVERY = b"PW3R"
MAGIC_KEYFILE = b"PW3F"
FORMAT_VERSION = 1

JOURNAL_ID_BYTES = 16
DEK_BYTES = 32
SALT_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16

# (memory KiB, time cost, parallelism). Stored in the slot, so unlike the
# derivation parameters these can be raised later without breaking anything.
DEFAULT_ACCESS_PARAMS = (262144, 3, 4)
_MAX_MEMORY_KIB = 4 * 1024 * 1024     # refuse a slot that asks for more than 4 GiB
_MAX_TIME_COST = 64
_MAX_PARALLELISM = 64

_SLOT_HEADER_LEN = len(MAGIC_SLOTS) + 1 + JOURNAL_ID_BYTES
_SLOT_LEN = _SLOT_HEADER_LEN + 12 + SALT_BYTES + NONCE_BYTES + DEK_BYTES + TAG_BYTES


class KeyError_(Exception):
    """Base class for key-hierarchy failures."""


class WrongSecret(KeyError_):
    """The secret offered does not open this slot (or the slot was altered)."""


class MalformedKeyFile(KeyError_):
    """The bytes are not a v3 key file of the expected kind."""


def new_journal_id():
    return os.urandom(JOURNAL_ID_BYTES)


def new_dek():
    return os.urandom(DEK_BYTES)


def _seal(key, nonce, plaintext, aad):
    return AESGCM(bytes(key)).encrypt(nonce, bytes(plaintext), aad)


def _open(key, nonce, ciphertext, aad):
    try:
        return AESGCM(bytes(key)).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise WrongSecret("wrong secret, or the file was modified") from None


# --- access slot -------------------------------------------------------------

def _check_params(params):
    memory, time_cost, parallelism = params
    if not (8 * parallelism <= memory <= _MAX_MEMORY_KIB and 1 <= time_cost <= _MAX_TIME_COST
            and 1 <= parallelism <= _MAX_PARALLELISM):
        raise MalformedKeyFile("access slot has Argon2id parameters out of range")


def access_kek(access_password, salt, params):
    from argon2.low_level import Type, hash_secret_raw

    _check_params(params)
    memory, time_cost, parallelism = params
    return hash_secret_raw(
        secret=derive.lp(canon.access_password(access_password)), salt=salt,
        time_cost=time_cost, memory_cost=memory, parallelism=parallelism,
        hash_len=32, type=Type.ID, version=derive.ARGON2_VERSION,
    )


def _slot_header(journal_id):
    return MAGIC_SLOTS + derive.u8(FORMAT_VERSION) + journal_id


def _slot_aad(journal_id, params, salt):
    return _slot_header(journal_id) + b"access" + b"".join(derive.u32(v) for v in params) + salt


def build_keys_file(journal_id, dek, access_password, params=DEFAULT_ACCESS_PARAMS,
                    salt=None, nonce=None):
    """Serialises keys.pw3. `salt` and `nonce` are injectable only for vectors."""
    if len(journal_id) != JOURNAL_ID_BYTES or len(dek) != DEK_BYTES:
        raise KeyError_("journal id or DEK has the wrong length")
    salt = os.urandom(SALT_BYTES) if salt is None else salt
    nonce = os.urandom(NONCE_BYTES) if nonce is None else nonce
    kek = access_kek(access_password, salt, params)
    wrapped = _seal(kek, nonce, dek, _slot_aad(journal_id, params, salt))
    return (_slot_header(journal_id) + b"".join(derive.u32(v) for v in params)
            + salt + nonce + wrapped)


def journal_id_of_keys_file(data):
    if len(data) != _SLOT_LEN or data[:4] != MAGIC_SLOTS:
        raise MalformedKeyFile("not a Passweird v3 keys file")
    if data[4] != FORMAT_VERSION:
        raise MalformedKeyFile(f"unsupported keys file version {data[4]}")
    return data[5:_SLOT_HEADER_LEN]


def open_keys_file(data, access_password):
    """Returns (journal_id, DEK) or raises WrongSecret."""
    journal_id = journal_id_of_keys_file(data)
    pos = _SLOT_HEADER_LEN
    params = tuple(int.from_bytes(data[pos + 4 * i:pos + 4 * i + 4], "big") for i in range(3))
    pos += 12
    salt = data[pos:pos + SALT_BYTES]
    pos += SALT_BYTES
    nonce = data[pos:pos + NONCE_BYTES]
    wrapped = data[pos + NONCE_BYTES:]
    kek = access_kek(access_password, salt, params)
    return journal_id, _open(kek, nonce, wrapped, _slot_aad(journal_id, params, salt))


# --- recovery wrap -----------------------------------------------------------

def recovery_kek(prk_none, journal_id):
    return derive.okm(prk_none, "journal-recovery", 32, extra=journal_id)


def _recovery_prefix(journal_id):
    return MAGIC_RECOVERY + derive.u8(FORMAT_VERSION) + journal_id + derive.lp(derive.ALG)


def build_recovery(journal_id, dek, prk_none, nonce=None):
    nonce = os.urandom(NONCE_BYTES) if nonce is None else nonce
    prefix = _recovery_prefix(journal_id) + nonce
    return prefix + _seal(recovery_kek(prk_none, journal_id), nonce, dek, prefix)


def journal_id_of_recovery(blob):
    if blob[:4] != MAGIC_RECOVERY or len(blob) < 5 + JOURNAL_ID_BYTES:
        raise MalformedKeyFile("not a Passweird v3 recovery wrap")
    if blob[4] != FORMAT_VERSION:
        raise MalformedKeyFile(f"unsupported recovery wrap version {blob[4]}")
    return blob[5:5 + JOURNAL_ID_BYTES]


def open_recovery(blob, prk_none):
    """Returns (journal_id, DEK) or raises WrongSecret."""
    journal_id = journal_id_of_recovery(blob)
    prefix_len = len(_recovery_prefix(journal_id)) + NONCE_BYTES
    if len(blob) != prefix_len + DEK_BYTES + TAG_BYTES or not blob.startswith(_recovery_prefix(journal_id)):
        raise MalformedKeyFile("recovery wrap is for a different algorithm or is truncated")
    prefix, wrapped = blob[:prefix_len], blob[prefix_len:]
    nonce = prefix[-NONCE_BYTES:]
    return journal_id, _open(recovery_kek(prk_none, journal_id), nonce, wrapped, prefix)


def recovery_to_text(blob):
    """Base32 in groups of four, eight groups per line: meant for paper."""
    text = base64.b32encode(blob).decode("ascii").rstrip("=")
    groups = [text[i:i + 4] for i in range(0, len(text), 4)]
    return "\n".join(" ".join(groups[i:i + 8]) for i in range(0, len(groups), 8))


def recovery_from_text(text):
    compact = "".join(ch for ch in text.upper() if ch.isalnum())
    try:
        return base64.b32decode(compact + "=" * (-len(compact) % 8))
    except Exception:
        raise MalformedKeyFile("recovery text is not valid Base32") from None


# --- keyfile factor (§8) -----------------------------------------------------

def keyfile_wrap_key(prk_none):
    return derive.okm(prk_none, "keyfile-wrap", 32)


def build_keyfile(prk_none, factor_bytes=None, nonce=None):
    """A 32-byte random factor, wrapped so the file alone is useless."""
    factor_bytes = os.urandom(derive.KEYFILE_BYTES) if factor_bytes is None else factor_bytes
    if len(factor_bytes) != derive.KEYFILE_BYTES:
        raise KeyError_("a keyfile factor is exactly 32 bytes")
    nonce = os.urandom(NONCE_BYTES) if nonce is None else nonce
    prefix = MAGIC_KEYFILE + derive.u8(FORMAT_VERSION) + nonce
    return prefix + _seal(keyfile_wrap_key(prk_none), nonce, factor_bytes, prefix)


def open_keyfile(data, prk_none):
    prefix_len = len(MAGIC_KEYFILE) + 1 + NONCE_BYTES
    if data[:4] != MAGIC_KEYFILE or len(data) != prefix_len + derive.KEYFILE_BYTES + TAG_BYTES:
        raise MalformedKeyFile("not a Passweird v3 keyfile")
    if data[4] != FORMAT_VERSION:
        raise MalformedKeyFile(f"unsupported keyfile version {data[4]}")
    prefix = data[:prefix_len]
    return _open(keyfile_wrap_key(prk_none), prefix[-NONCE_BYTES:], data[prefix_len:], prefix)
