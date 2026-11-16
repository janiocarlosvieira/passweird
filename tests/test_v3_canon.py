# ADR-0009 §1 - canonical form of every input.
import pytest

from passweird.v3 import canon
from v3_support import load

VECTORS = load("canonical.json")

FUNCTIONS = {
    "master": canon.master, "access_password": canon.access_password,
    "boost": canon.boost, "user_id": canon.user_id, "login": canon.login,
    "site": canon.site, "counter": canon.counter, "classes": canon.classes,
}


def _input(case):
    if "input_repeat" in case:
        unit, count = case["input_repeat"]
        return unit * count
    return case["input"]


def _apply(case):
    if case["field"] == "length":
        return canon.length(case["input"], case["classes"])
    return FUNCTIONS[case["field"]](_input(case))


def _id(case):
    return f"{case['field']}:{case.get('input', case.get('input_repeat'))!r}"[:60]


@pytest.mark.parametrize("case", VECTORS["cases"], ids=_id)
def test_canonical_vectors(case):
    if case.get("reject"):
        with pytest.raises(canon.CanonicalError):
            _apply(case)
    elif case.get("expected_same_as_input"):
        assert _apply(case) == _input(case)
    else:
        assert _apply(case) == case["expected"]


def test_vectors_contain_both_outcomes_for_every_field():
    for field in list(FUNCTIONS) + ["length"]:
        cases = [c for c in VECTORS["cases"] if c["field"] == field]
        assert any(c.get("reject") for c in cases), f"no reject case for {field}"
        assert any("expected" in c or c.get("expected_same_as_input") for c in cases), f"no accept case for {field}"


def test_whitespace_set_is_pinned():
    assert sorted(ord(ch) for ch in canon.WHITESPACE) == VECTORS["whitespace_codepoints"]


@pytest.mark.parametrize("function", [canon.master, canon.boost, canon.user_id, canon.login, canon.site])
def test_canonical_form_is_idempotent(function):
    for case in VECTORS["cases"]:
        if FUNCTIONS.get(case["field"]) is function and "expected" in case:
            assert function(case["expected"]) == case["expected"]


def test_phone_keyboard_spelling_reaches_the_same_boost():
    assert canon.boost("Cavalo  Bateria grampo ") == canon.boost("cavalo bateria grampo")


@pytest.mark.parametrize("accented, plain", [
    ("país", "pais"), ("açucar", "acucar"), ("açúcar", "acucar"), ("coração", "coracao"),
    ("avó", "avo"), ("avô", "avo"), ("ÁGUA", "agua"), ("Pão  De  Açúcar", "pao de acucar"),
    ("café", "cafe"),
])
def test_boost_ignores_diacritics(accented, plain):
    assert canon.boost(accented) == canon.boost(plain) == plain


def test_boost_removes_exactly_the_combining_diacritical_marks_block():
    assert sorted(ord(ch) for ch in canon.COMBINING_DIACRITICS) == list(range(0x0300, 0x0370))
    info = VECTORS["boost_removed_codepoints"]
    assert (info["first"], info["last"], info["count"]) == (0x0300, 0x036F, 112)
    assert canon.boost("a᪰b") == "a᪰b"          # a mark outside the block stays
    assert canon.boost("smørrebrød") == "smørrebrød"       # no decomposition: untouched
    with pytest.raises(canon.CanonicalError):
        canon.boost("́")


def test_diacritics_are_removed_from_the_boost_only():
    assert canon.master("país") == "país"
    assert canon.user_id("josé@exemplo.br") == "josé@exemplo.br"
    assert canon.login("José") == "josé"


def test_every_word_of_the_bundled_list_is_its_own_canonical_boost():
    from passweird.v3 import wordlist
    assert all(canon.boost(word) == word for word in wordlist.words())


def test_nfd_and_nfc_master_are_the_same_secret():
    assert canon.master("café") == canon.master("café")


def test_only_ascii_letters_are_lowered():
    assert canon.user_id("ÉA@X") == "Éa@x"


def test_lone_surrogate_is_rejected():
    # Cannot be stored in the JSON vectors, so it is pinned here.
    with pytest.raises(canon.CanonicalError):
        canon.master("a\ud800b")


@pytest.mark.parametrize("value", [None, 1, b"bytes"])
def test_non_text_is_rejected(value):
    with pytest.raises(canon.CanonicalError):
        canon.master(value)


@pytest.mark.parametrize("value", [True, 1.0, "1", None])
def test_counter_rejects_non_integers(value):
    with pytest.raises(canon.CanonicalError):
        canon.counter(value)


def test_login_none_means_absent():
    assert canon.login(None) == ""


def test_classes_from_flags():
    assert canon.classes_from_flags() == 15
    assert canon.classes_from_flags(lower=False, upper=False, specials=False) == canon.CLASS_DIGITS
    with pytest.raises(canon.CanonicalError):
        canon.classes_from_flags(False, False, False, False)
