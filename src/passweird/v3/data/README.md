# Bundled data

## `wordlist-pt.txt`

7776 Portuguese words without diacritics, 4 to 8 letters, one per line, sorted. Used only by
`--gen-boost` to draw a boost with the operating system's CSPRNG (ADR-0009 §1). It is **not**
part of the derivation: any text is a valid boost. Its size is what the entropy shown to the
user is computed from (log2(7776) = 12.92 bits per word), so a test pins the file's SHA-256.

Built by `tools/build_wordlist_pt.py` from two sources, both unmodified:

| Source | Licence | SHA-256 of the input used |
|---|---|---|
| `content/2018/pt_br/pt_br_50k.txt`, [hermitdave/FrequencyWords](https://github.com/hermitdave/FrequencyWords) (derived from OpenSubtitles 2018) | CC-BY-SA-4.0 | `a61d6f2ede97c5daad5fb3907b72a228f0aff12668be6d24da590d20804fa611` |
| ispell.pt word list, Projecto Natura, Universidade do Minho (Debian `wportuguese` 20220219-1, `/usr/share/dict/portuguese`) | GPL-2+ / LGPL-2.1+ / MPL-1.1 | `43f44eb8ce613ae274dbb5b01d16019a2dc8488893398e547a5d45479710d6c4` |

The resulting list is distributed under the GNU GPL v3, like the rest of Passweird
(CC-BY-SA-4.0 material may be adapted under GPLv3; the dictionary is used under GPL-2+).
