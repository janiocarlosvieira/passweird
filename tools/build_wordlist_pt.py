#!/usr/bin/env python3
# tools/build_wordlist_pt.py
# Passweird - builds the Portuguese word list used by --gen-boost
# Licensed under the GNU General Public License v3.0
"""
Builds src/passweird/v3/data/wordlist-pt.txt: 7776 Portuguese words without
diacritics (ADR-0009 §1).

    python tools/build_wordlist_pt.py FREQUENCY_FILE DICTIONARY_FILE

Inputs (not vendored; see src/passweird/v3/data/README.md for hashes):
  FREQUENCY_FILE   pt_br_50k.txt from hermitdave/FrequencyWords (CC-BY-SA-4.0):
                   "word count" per line, most frequent first.
  DICTIONARY_FILE  the ispell.pt word list (GPL-2+), e.g. Debian's
                   /usr/share/dict/portuguese.

A word is kept when it is in the frequency list AND, spelled the same way in
lower case, in the dictionary. The frequency list supplies "words people know",
the dictionary removes names, foreign words and subtitle noise. Diacritics are
stripped afterwards and duplicates removed AFTER stripping, so 'país' and
'pais' become one entry rather than two indistinguishable ones.

The list is a UX artefact, not part of the derivation: only the canonical form
of the boost is frozen. What must never change silently is its SIZE, because
the entropy printed to the user is computed from it.
"""
import pathlib
import re
import sys
import unicodedata

SIZE = 7776
SHAPE = re.compile(r"^[a-z]{4,8}$")
OUTPUT = pathlib.Path(__file__).resolve().parent.parent / "src" / "passweird" / "v3" / "data" / "wordlist-pt.txt"

# Words nobody should be handed as part of a secret they may have to read aloud.
BLOCKED = frozenset("""
merda porra puta puto putas putos caralho foda fodase foder fodido fodida fodeu cuzao bosta
buceta boceta cacete viado viados bicha bichas vadia vadias piranha corno cornos otario otaria
idiota idiotas imbecil estupro estuprar estuprada estuprador nazista nazistas nigger preto
macaco aleijado retardado retardada mongol babaca babacas cagar cagou cagada mijo mijar
pinto pica pau rola tesao gozar gozou gozo transar transou sexo sexual penis vagina anus
cocaina heroina maconha suicidio suicida matar morte morto morta morrer assassino assassina
droga drogas vagabunda vagabundo prostituta desgraca desgracado maldito maldita demonio
diabo inferno cadaver sangue estupido estupida burro burra gordo gorda feio feia
""".split())


def strip_diacritics(word):
    return "".join(ch for ch in unicodedata.normalize("NFD", word) if not unicodedata.combining(ch))


def build(frequency_path, dictionary_path):
    dictionary = set()
    with open(dictionary_path, encoding="utf-8", errors="strict") as handle:
        for line in handle:
            word = line.strip()
            if word and word == word.lower():        # capitalised entries are proper names
                dictionary.add(word)

    chosen, seen = [], set()
    with open(frequency_path, encoding="utf-8") as handle:
        for line in handle:
            word = line.split(" ")[0].strip()
            if word not in dictionary:
                continue
            plain = strip_diacritics(word)
            if not SHAPE.match(plain) or plain in seen or plain in BLOCKED:
                continue
            seen.add(plain)
            chosen.append(plain)
            if len(chosen) == SIZE:
                break
    if len(chosen) != SIZE:
        raise SystemExit(f"only {len(chosen)} words survived the filters, {SIZE} needed")
    return sorted(chosen)


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    words = build(sys.argv[1], sys.argv[2])
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(words) + "\n", encoding="ascii")
    print(f"Wrote {OUTPUT} ({len(words)} words)")


if __name__ == "__main__":
    main()
