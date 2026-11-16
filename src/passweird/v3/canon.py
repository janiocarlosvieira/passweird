# Passweird v3 - canonical form of every input (ADR-0009 §1)
# Licensed under the GNU General Public License v3.0
"""
Canonicalisation is part of the algorithm: two spellings that a person would
call "the same input" must reach the KDF as the same bytes, on every platform,
forever. Everything here is therefore explicit and independent of the runtime:

- the whitespace set is listed, not taken from str.isspace();
- only ASCII letters are case-mapped, because full Unicode case mapping
  changes with the Unicode version of the interpreter;
- anything the rules cannot place is rejected, never guessed.
"""
import re
import unicodedata

MAX_FIELD_BYTES = 65535  # LP() carries a 16-bit length (§2)

# Unicode White_Space property. Stable by Unicode policy; spelled out so the
# result does not depend on which Unicode tables the interpreter ships.
WHITESPACE = frozenset(
    "\u0009\u000a\u000b\u000c\u000d \u0085  "
    "           "
    "    　"
)

# Combining Diacritical Marks, U+0300..U+036F: the whole block and nothing
# else. Removed from the boost only (see boost()).
COMBINING_DIACRITICS = frozenset(chr(c) for c in range(0x0300, 0x0370))

_ASCII_LOWER = {c: c + 32 for c in range(ord("A"), ord("Z") + 1)}
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_PORT = re.compile(r":[0-9]*$")
_SITE = re.compile(r"^[a-z0-9]([a-z0-9._\-]*[a-z0-9])?$")

CLASS_LOWER, CLASS_UPPER, CLASS_DIGITS, CLASS_SPECIALS = 1, 2, 4, 8
MAX_LENGTH = 128
MAX_COUNTER = 2**32 - 1


class CanonicalError(ValueError):
    """An input that has no canonical form. The message names the field."""


def _trim(value):
    start, end = 0, len(value)
    while start < end and value[start] in WHITESPACE:
        start += 1
    while end > start and value[end - 1] in WHITESPACE:
        end -= 1
    return value[start:end]


def _strip_diacritics(value):
    """NFD, drop U+0300..U+036F, NFC. Marks outside that block and letters
    without a decomposition (ø, ß) are left as they are."""
    decomposed = unicodedata.normalize("NFD", value)
    return unicodedata.normalize("NFC", "".join(ch for ch in decomposed if ch not in COMBINING_DIACRITICS))


def _ascii_lower(value):
    return value.translate(_ASCII_LOWER)


def _check(field, value, allow_empty=False):
    if not value and not allow_empty:
        raise CanonicalError(f"{field} must not be empty")
    for ch in value:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise CanonicalError(f"{field} contains a control character (U+{ord(ch):04X})")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise CanonicalError(f"{field} is not valid Unicode text") from None
    if len(encoded) > MAX_FIELD_BYTES:
        raise CanonicalError(f"{field} is longer than {MAX_FIELD_BYTES} bytes")
    return value


def _text(field, value):
    if not isinstance(value, str):
        raise CanonicalError(f"{field} must be text")
    return value


def master(value):
    """NFC only. A master password is taken exactly as typed."""
    return _check("master", unicodedata.normalize("NFC", _text("master", value)))


def access_password(value):
    """Same rule as the master password; it only opens the journal (§6)."""
    return _check("access password", unicodedata.normalize("NFC", _text("access password", value)))


def boost(value):
    """
    NFC, diacritics removed, trimmed, whitespace runs collapsed, ASCII letters
    lowered. Phone keyboards capitalise the first word, double-space freely and
    autocorrect accents in; none of that may change every password the user
    owns. The bundled word list is deduplicated after accent stripping, so
    "pais" and "país" have to be the same boost.

    The order matters twice:
      - diacritics go BEFORE trimming and collapsing. A mark standing alone
        between two spaces ("a \u0301 b") would otherwise survive the collapse
        as a word, then vanish and leave two spaces behind: a result that is
        not its own canonical form.
      - diacritics go BEFORE the lowering: "ÁGUA" must become "agua", not "Agua".
    """
    value = _strip_diacritics(unicodedata.normalize("NFC", _text("boost", value)))
    words, current = [], []
    for ch in value:
        if ch in WHITESPACE:
            if current:
                words.append("".join(current))
                current = []
        else:
            current.append(ch)
    if current:
        words.append("".join(current))
    return _check("boost", _ascii_lower(" ".join(words)))


def user_id(value):
    value = unicodedata.normalize("NFC", _text("user id", value))
    return _check("user id", _ascii_lower(_trim(value)))


def login(value):
    """Empty means "no login"; it is a valid canonical value."""
    if value is None:
        return ""
    value = unicodedata.normalize("NFC", _text("login", value))
    return _check("login", _ascii_lower(_trim(value)), allow_empty=True)


def site(value):
    """
    Purely syntactic reduction of a URL or host name to a site identifier.

    No Public Suffix List (it changes over time and a password must not) and
    no IDNA conversion (libraries disagree): a non-ASCII host is rejected and
    the caller is asked for its xn-- form.
    """
    value = _trim(unicodedata.normalize("NFKC", _text("site", value)))
    value = _SCHEME.sub("", value, count=1)
    for stop in "/?#":
        cut = value.find(stop)
        if cut != -1:
            value = value[:cut]
    at = value.rfind("@")
    if at != -1:
        value = value[at + 1:]
    value = _PORT.sub("", value, count=1)
    value = _ascii_lower(value).rstrip(".")
    # Every leading "www." goes, not just one: a canonical form has to be a fixed
    # point, or re-canonicalising a stored site would silently rename it.
    while value.startswith("www."):
        value = value[4:]
    if not value:
        raise CanonicalError("site must not be empty")
    if not _SITE.match(value):
        if any(ord(ch) > 0x7F for ch in value):
            raise CanonicalError(
                "site contains non-ASCII characters; enter the xn-- (Punycode) form of the host name"
            )
        raise CanonicalError(
            "site must contain only a-z, 0-9, '.', '-' and '_', and start and end with a letter or digit"
        )
    return _check("site", value)


def counter(value):
    if isinstance(value, bool) or not isinstance(value, int):
        raise CanonicalError("counter must be an integer")
    if not 1 <= value <= MAX_COUNTER:
        raise CanonicalError(f"counter must be between 1 and {MAX_COUNTER}")
    return value


def classes(value):
    if isinstance(value, bool) or not isinstance(value, int):
        raise CanonicalError("classes must be an integer bit mask")
    if not 1 <= value <= 15:
        raise CanonicalError("at least one character class must be enabled (mask 1..15)")
    return value


def length(value, class_mask):
    class_mask = classes(class_mask)
    if isinstance(value, bool) or not isinstance(value, int):
        raise CanonicalError("length must be an integer")
    minimum = 6 if class_mask == CLASS_DIGITS else 8
    if not minimum <= value <= MAX_LENGTH:
        raise CanonicalError(f"length must be between {minimum} and {MAX_LENGTH} for these classes")
    return value


def classes_from_flags(lower=True, upper=True, digits=True, specials=True):
    mask = (
        (CLASS_LOWER if lower else 0) | (CLASS_UPPER if upper else 0)
        | (CLASS_DIGITS if digits else 0) | (CLASS_SPECIALS if specials else 0)
    )
    return classes(mask)
