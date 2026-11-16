# ADR-0009 §1 - the list --gen-boost draws from.
import hashlib
import pathlib
import re

import pytest

from passweird.v3 import canon, wordlist

PATH = pathlib.Path(wordlist.__file__).parent / "data" / "wordlist-pt.txt"


def test_list_is_pinned():
    """The entropy printed to the user is computed from this file's size."""
    assert hashlib.sha256(PATH.read_bytes()).hexdigest() == \
        "a39da11f14e520fe1c158070da99cf344d0381a287336c72e59d3837495c1bb9"


def test_list_shape():
    words = wordlist.words()
    assert len(words) == 7776 == len(set(words))
    assert words == sorted(words)
    assert all(re.fullmatch(r"[a-z]{3,9}", w) for w in words)       # no diacritics
    assert round(wordlist.bits_per_word(), 2) == 12.92


def test_default_is_five_words_and_four_is_the_minimum():
    boost, bits = wordlist.generate_boost()
    assert len(boost.split(" ")) == 5 and round(bits, 1) == 64.6
    assert len(wordlist.generate_boost(4)[0].split(" ")) == 4
    for bad in (3, 0, -1, True, "5"):
        with pytest.raises(ValueError):
            wordlist.generate_boost(bad)


def test_generated_boost_is_already_canonical_and_random():
    drawn = {wordlist.generate_boost()[0] for _ in range(50)}
    assert len(drawn) == 50
    assert all(canon.boost(b) == b for b in drawn)
    assert all(w in set(wordlist.words()) for b in drawn for w in b.split(" "))
