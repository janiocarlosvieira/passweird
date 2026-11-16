# Passweird v3 - drawing a boost (ADR-0009 §1)
# Licensed under the GNU General Public License v3.0
"""
The boost is the secret that keeps every password out of reach even when the
master password is weak or already known, so it is drawn by the machine: human
"free" choice clusters, and a suggested pattern helps the attacker more than
the user. The list is a UX artefact; only its size matters to the entropy.
"""
import math
import os
import secrets

DEFAULT_WORDS = 5
MINIMUM_WORDS = 4
EXPECTED_SIZE = 7776
_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "wordlist-pt.txt")

_cache = None


def words():
    global _cache
    if _cache is None:
        with open(_PATH, encoding="ascii") as handle:
            loaded = handle.read().split()
        if len(loaded) != EXPECTED_SIZE or len(set(loaded)) != EXPECTED_SIZE:
            # A shorter list would make the printed entropy a lie.
            raise RuntimeError("bundled word list is damaged: wrong number of entries")
        _cache = loaded
    return _cache


def bits_per_word():
    return math.log2(len(words()))


def generate_boost(count=DEFAULT_WORDS):
    """Returns (boost, bits). Uses the OS CSPRNG, never `random`."""
    if isinstance(count, bool) or not isinstance(count, int) or count < MINIMUM_WORDS:
        raise ValueError(f"a boost needs at least {MINIMUM_WORDS} words")
    pool = words()
    return " ".join(secrets.choice(pool) for _ in range(count)), count * bits_per_word()
