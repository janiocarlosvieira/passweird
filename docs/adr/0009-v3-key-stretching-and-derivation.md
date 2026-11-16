# ADR-0009 — v3: memory-hard stretching, canonical inputs and a tiered, syncable journal

**Status:** Accepted (revision 5)
**Date:** 2026-11-16
**Supersedes (when accepted):** the "risk accepted" decision of
[ADR-0003](0003-chave-publica-publicada-como-oraculo-offline.md), the `info` layout of
[ADR-0004](0004-separacao-de-dominio-no-info-do-hkdf.md), the log format of
[ADR-0006](0006-formato-do-log-e-deteccao-por-registro.md) and the proposal in
[ADR-0007](0007-verificacao-de-senha-contra-o-log.md).

v3 is a **compatibility break**: no v2 output reproduces under v3. v2 stays in the tree as
read-only code, used only to open old files and to print old passwords during migration.

## Context

A review of v2 found the following. Items 1–4 were known; 5–9 came out of the audit that
preceded this ADR and shape the design below.

1. `--register-master` writes `modified_hash(master)` to `~/.passweird/master.hash`. That value
   **is** the HKDF PRK and the key of `hosts.enc`, the log and the keyfile wrap. Reading the
   file is equivalent to knowing the master password.
2. No slow KDF. The master goes through 2× SHA-256 with no salt; the temporal secret only
   enters the HKDF `info`. One password leaked by any site, plus its context, is an offline
   oracle at GPU SHA-256 speed. The README sentence "passwords are only testable against the
   service" is therefore wrong.
3. `-T` is both a secret and a version label.
4. `b % len(charset)` is biased.
5. **Profiles are correlated.** Length is in `info`, the character-class flags are not. The
   same HKDF bytes are mapped through different charsets, so the `-s` (no specials) password
   for a context reveals `b mod 62` for every byte of the full-charset one, cutting each of
   its characters from 77 candidates to about 4.
6. **The hash-summary line is a second `master.hash`.** `master:<80 bits of the PRK>` is
   printed to the terminal on every run and stored in the log (in clear with `--plain-log`).
   It is an unsalted 2×SHA-256 oracle for the master password; `temporal:` is the same for
   the temporal secret at 1× SHA-256, and `app:` confirms which sites are in use.
7. **One key, four jobs, no file binding.** `master_hash` is HKDF PRK, PBKDF2 password for
   `hosts.enc`, for every log record and for the keyfile wrap. Ciphertexts carry no magic,
   version or AAD, so a blob of one kind decrypts as another.
8. **The log key drifts.** With `--key-file` or `--fido2` the log is encrypted under the
   *blended* (for FIDO2: per-context) hash, so `--view-log` and the last-flags check silently
   skip those records. PBKDF2 (100k) runs once per record on every read.
9. **Nothing sets file permissions.** `~/.passweird` and everything in it is created with the
   process umask (0775/0664 on the development machine), including plaintext CSV exports.

## Decision

### 1. Inputs and canonical form

| Input | Secret | Canonical form |
|---|---|---|
| `master` | yes | NFC. No trimming, no case change. Non-empty. C0 controls and U+007F rejected |
| `boost` | yes | NFC, trimmed, runs of whitespace collapsed to one U+0020, **diacritics removed** (below), ASCII `A–Z` lowered. Non-empty |
| `user_id` | no | NFC, trimmed, ASCII `A–Z` lowered. Non-empty. An e-mail address is recommended |
| `site` | no | See below |
| `login` | no | NFC, trimmed, ASCII `A–Z` lowered. Empty means "absent" |
| `counter` | no | Integer `1 … 2³²−1`. Default 1 |
| `length` | no | `8 … 128`; `6 … 128` when only digits are enabled |
| `classes` | no | Bit mask: 1 lower, 2 upper, 4 digits, 8 specials. Non-zero |

`boost` ("reforço") is one secret shared by every site, drawn once by `--gen-boost` and
memorised. It replaces the temporal secret as a *secret*; `counter` replaces it as a *version*.
The lowering and whitespace rules exist because phone keyboards capitalise the first word and
double-space freely.

**Diacritics in the boost.** After NFC, trimming and whitespace collapsing, the boost is
decomposed (NFD), every code point in the block **U+0300–U+036F** (Combining Diacritical
Marks, listed explicitly in the code) is removed, and the result is recomposed (NFC). Only then
are ASCII letters lowered, so `ÁGUA` and `agua` are the same boost. `país`/`pais` and
`açucar`/`acucar` therefore give the same boost, which matches the bundled list: it is
deduplicated after accent stripping, so a user who types the accent out of habit, or whose
keyboard autocorrects one in, must not get different passwords. Marks outside that block and
letters with no decomposition (`ø`, `ß`) are left alone. A boost that is empty after this step
is rejected. This applies to the boost only: the master password keeps its accents.

"Trimmed" and "whitespace" mean the Unicode `White_Space` set, listed explicitly in the code
so it does not depend on the runtime. After trimming, every input rejects any remaining C0
control and U+007F.

Only ASCII letters are case-mapped anywhere. Full Unicode case mapping depends on the Unicode
version of the runtime, which is exactly the kind of divergence that surfaces as a lockout.

**`site` rule**, applied in this order, purely syntactic:

1. NFKC, trim.
2. Drop a `scheme://` prefix; drop everything from the first `/`, `?` or `#`.
3. Drop userinfo (up to and including the last `@`); drop a trailing `:port`.
4. ASCII-lower; strip trailing dots; strip every leading `www.` (repeatedly, so that the
   canonical form is a fixed point).
5. The result must match `^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`, else the input is **rejected**.

`https://WWW.GitHub.com:443/login?x=1` → `github.com`. `ufpb-sigaa` stays `ufpb-sigaa`.
Non-ASCII host names are rejected with a message asking for the `xn--` form: IDNA mapping
differs between libraries and versions, and no conversion is safer than a divergent one.

There is deliberately **no Public Suffix List**: it changes over time, and a password must not.
`accounts.google.com` and `google.com` are therefore different sites; the tool always prints the
canonical site before deriving, and the journal (§6) remembers which one was used.

**`--gen-boost [N]`**: default **5 words, minimum 4**, drawn with the OS CSPRNG from a bundled
Portuguese list **without diacritics**: exactly 7776 entries, each `[a-z]{3,9}`, deduplicated
*after* accent stripping (`país`/`pais` collapse to one entry). 12.9 bits per word: 51.7 bits
at 4, **64.6 at 5**, 77.5 at 6. The list is a UX artefact, not part of the algorithm: only the
canonical form of `boost` is frozen, and a user may supply their own. The file's SHA-256 is
pinned by a test so the entropy claim cannot drift silently.

### 2. Encoding

```
U8(n), U32(n), U64(n)   big-endian unsigned
LP(x)                   U16(len(x)) || x      x is bytes; strings are UTF-8; len ≤ 65535
ALG                     "passweird-v3/argon2id-v19-m262144-t3-p4/hkdf-sha512"   (ASCII)
```

Every variable-length field is length-prefixed, so the ambiguity class of ADR-0004 cannot
recur. `ALG` is bound into both the salt and every `info`, so changing any parameter changes
every output: parameters are frozen by the identifier.

### 3. Stretching

```
P    = LP(master) || LP(boost)
S    = SHA-256( LP(ALG) || LP("salt") || LP(user_id) )                  # 32 bytes
K0   = Argon2id(password=P, salt=S, t=3, m=262144 KiB, p=4, taglen=64,
                version=0x13, secret=∅, ad=∅)

F    = SHA-512( LP(ALG) || LP("factor") || LP(kind) || LP(factor_bytes) )
       kind ∈ {"none", "keyfile"};  factor_bytes = "" for "none"
PRK[kind] = HMAC-SHA512(key=F, message=K0)                              # HKDF-Extract
```

`master` and `boost` enter Argon2id **together**. An attacker cannot test one without the
other, and every guess of either pays the full memory-hard cost. `K0` and every `PRK` live in
memory only, in mutable buffers zeroed after use (best effort; see Consequences).

`PRK["none"]` is the *local* key (fingerprint, recovery wrap, keyfile wrap). Site outputs
derive from the `PRK` of the factor the user selected.

### 4. Expansion

HKDF-Expand (RFC 5869) with HMAC-SHA512:

```
info(purpose, site, login, counter, extra) =
    LP(ALG) || LP(purpose) || LP(site) || LP(login) || U32(counter) || LP(extra)

OKM(prk, purpose, …, n) = HKDF-Expand(prk, info(purpose, …), n)
```

| Purpose | PRK | site/login/counter | `extra` | Bytes |
|---|---|---|---|---|
| `password` | selected | yes | `U8(length) ‖ U8(classes) ‖ U8(1)` | 4096 |
| `totp` | selected | yes | – | 20 |
| `ssh-ed25519`, `ssh-checkint` | selected | yes | – | 32, 4 |
| `tls-ed25519`, `tls-serial` | selected | yes | – | 32, 19 |
| `tls-rsa-p`, `tls-rsa-q` | selected | yes | `U16(bits) ‖ U32(candidate)` | bits/16 |
| `pgp-ed25519`, `pgp-ctime` | selected | yes | – | 32, 4 |
| `fingerprint` | none | no (empty, 0) | – | 3 |
| `journal-recovery` | none | no | `journal_id` | 32 |
| `keyfile-wrap` | none | no | – | 32 |

`counter` is the only rotation mechanism: new password for a site = a higher `counter`. Length
and classes are inside `info`, which removes finding 5.

### 5. Password sampling

```
stream  = OKM(prk, "password", site, login, counter, extra, 4096)
charset = [a-z if 1] + [A-Z if 2] + [0-9 if 4] + ["!@#$%^&*()_+-=." if 8]     # this order

uniform(n):                       # n ≤ 256
    limit = 256 − (256 mod n)
    repeat: b = next byte of stream
    until b < limit
    return b mod n

repeat:
    pw = charset[uniform(len(charset))] for i in 1..length
until pw contains at least one character of every enabled class
return pw
```

If the stream is exhausted the implementation MUST fail, never fall back. The probability is
below 2⁻⁴⁰⁰ for every valid parameter set.

Rejecting the *whole* candidate and redrawing from the continuing stream yields the exact
uniform distribution over compliant passwords. The usual alternative (place one character per
class, fill, shuffle) is deterministic too but not uniform, which is why it was not chosen. At
the default (18 characters, all classes) the result carries 112.6 bits.

### 6. Local state in tiers

Three tiers, three different secrets:

| Tier | Opens with | Gives |
|---|---|---|
| Journal | **access password** | sites, logins, counters, flags, notes. No password, no key |
| Derivation | `master` + `boost` (+ keyfile) | every password and key |
| Recovery | `master` + `boost` | the journal, when the access password is lost |

Nothing on disk can derive a password. There is no verifier file and no hash summary of any
secret. Typing errors are caught by the **fingerprint**: `OKM(…"fingerprint"…, 3)` rendered as
four consonant–vowel syllables, 6 bits each (`bdfghjklmnprstvz` × `aeio`), e.g. `kode-nafi`,
shown on every derivation and stored nowhere.

**Keys.**

```
journal_id = 16 random bytes, fixed at --init
DEK        = 32 random bytes, fixed at --init

access slot  (in keys.pw3, synced):
    KEK_a = Argon2id(password=LP(access_password), salt=salt_a, m, t, p,
                     taglen=32, version=0x13, secret=∅, ad=∅)
    slot  = U32(m) || U32(t) || U32(p) || salt_a(32) || nonce(12)
            || AES-256-GCM(KEK_a, nonce, DEK, aad)            # 32 + 16 bytes
    aad   = "PW3S" || U8(1) || journal_id || "access"
            || U32(m) || U32(t) || U32(p) || salt_a

keys.pw3 = "PW3S" || U8(1) || journal_id(16) || slot           # 125 bytes in all

    offset   0   4  "PW3S"
             4   1  format version (1)
             5  16  journal_id
            21   4  m, memory in KiB     U32 big-endian
            25   4  t, passes            U32 big-endian
            29   4  p, lanes            U32 big-endian
            33  32  salt_a
            65  12  nonce
            77  48  ciphertext (32) || GCM tag (16)

    "access" in the aad is the six ASCII bytes, with no length prefix.

recovery wrap (printed once, NOT stored by default):
    KEK_r = OKM(PRK["none"], "journal-recovery", extra=journal_id, 32)
    file  = "PW3R" || U8(1) || journal_id || LP(ALG) || nonce(12) || AES-256-GCM(KEK_r, nonce, DEK, aad=preceding bytes)
```

`m`, `t` and `p` are each a 32-bit big-endian unsigned integer, both in the slot and in the
aad, in that order. A reader must refuse a slot outside `8·p ≤ m ≤ 4 GiB`, `1 ≤ t ≤ 64`,
`1 ≤ p ≤ 64` before allocating anything. The access slot's Argon2id parameters are stored in
the slot, default the same as §3. They are *not* frozen: `--change-access-password` rewrites the slot with new parameters and the same DEK.
`--init` refuses an access password equal to `master` or `boost`.

**Where the oracle is, stated plainly.** The synced journal is an offline oracle for the
*access password* only. The recovery wrap is an offline oracle for `master + boost` at full
Argon2id cost: anything that `master + boost` can open is, by construction, something a guess
of `master + boost` can be tested against. It is therefore **printed once** by `--init`, as
Base32 text and as a QR code, to be kept on paper or offline, and is **not written to disk**.
`--keep-recovery-file` is the explicit opt-in that stores it as `~/.passweird/v3/recovery.pw3`
(local, never in the synced folder); a device that has it can derive and update the journal
with `master + boost` alone. Every other device asks for the access password as well.
`--recover` accepts the Base32 text or the file.

**Records.** Plaintext is canonical JSON, padded with zero bytes to a multiple of 256:

```
{ "v": 1, "ts": <ms since epoch, UTC>, "op": "put" | "delete",
  "site": …, "login": …, "counter": …, "length": …, "classes": …,
  "parents": [[device_id_hex, seq], …],
  "notes": "<free text>", "totp": "<where the second factor lives>",
  "keys": ["<physical key registered at the site>", …], "x": { <free map> } }
```

`notes`, `totp`, `keys` and `x` are free-form, never enter any derivation, and are the place
for "TOTP is in the phone's Aegis", "YubiKey 5C blue + backup in the safe".

**Export.** Generated passwords leave the tool only as an encrypted KeePass database:
`--export-kdbx FILE` (KDBX 4, via `pykeepass`, optional extra `passweird[kdbx]`), with its own
password prompted, refusing to overwrite, mode 0600. Each entry carries title, user name,
password, URL, notes and the derivation parameters as custom fields.

The KDF of the exported file is **set explicitly** and verified after writing, never left to
the library's template: **Argon2id, 256 MiB, 3 iterations, parallelism 4**, with a fresh
random salt. If the library cannot be made to write those values, the export fails.

Intended flow: export to a new file, then in KeePassXC open the main database and use
*Database → Merge From Database…* on the export, then delete the export. Every CSV exporter
is removed; managers that cannot read KDBX are reached through KeePassXC.

### 7. Synchronisation across devices

Designed for a folder replicated by Syncthing among 3–4 machines. No server, no locking.

```
<journal dir>/                 synced
  keys.pw3                     header + access slot
  streams/<device_id>.pw3j     one append-only file per device
~/.passweird/v3/               local only, 0700 / 0600
  config                       ALG, user_id, journal dir, device_id, defaults
  seen                         highest seq seen per stream
  recovery.pw3                 only with --keep-recovery-file (§6)
```

**Every write is atomic.** `keys.pw3`, each stream and the local files are never modified in
place: the new content goes to a temporary file in the same directory, is `fsync`ed, and
replaces the old one with a rename, followed by an `fsync` of the directory. An append to a
stream is therefore a full rewrite of that (small) file. A power cut leaves either the old
file or the new one, never a partial record, which is what lets the reader treat any
malformed or truncated record as an error instead of something to tolerate.

**One writer per file.** `device_id` is 16 random bytes created by `--init` or `--join`. A
device appends only to its own stream, so the sync layer never sees two versions of one file.

```
stream header = "PW3J" || U8(1) || journal_id || device_id
record        = U32(len) || nonce(12, random) || AES-256-GCM(K_stream, nonce, plaintext, aad)
K_stream      = HKDF-Expand( HKDF-Extract(salt=journal_id, IKM=DEK),
                             LP("PW3J/stream") || device_id, 32 )
aad           = stream header || U64(seq)            seq = 0, 1, 2, … within the stream
```

The AAD binds every record to journal, device and position. Reading verifies that `seq` is
contiguous. A record that fails authentication is an **error naming stream and index**, never
something to skip.

**Clock.** `ts = max(wall clock, 1 + highest ts seen in any stream)`. Order stays "by `ts`",
but a record written after seeing another always sorts after it, whatever the wall clocks say.

**State** = union of all streams, ordered by `(ts, device_id, seq)`, folded per
`(site, login)`:

1. *Heads* are the records of an entry that no other record of that entry lists in `parents`.
   Every new record lists all heads its writer could see. One head: no concurrency. Several
   heads: the entry was edited on devices that had not yet seen each other.
2. Fields other than `counter`: the last record in order wins.
3. **`counter` = the maximum over every `put` ever written for the entry**, including records
   that precede a `delete`. It never decreases.
4. Several heads that differ in `counter`, `length` or `classes` mark the entry **in
   conflict**. Derivation still works, but prints the candidates and the devices involved until
   any device writes a record that lists all heads (`--resolve SITE`, or simply the next edit).

Why "maximum" is the right rule for `counter`:

- Records carry the absolute counter, not "+1". Two devices that both go 3 → 4 offline derive
  the **same** password, and the merge is 4 with nothing to reconcile.
- If one device went 3 → 4 → 5 and another 3 → 4, the site can only hold one of them. The
  journal cannot know which; the highest is the best guess, the conflict flag says so, and
  `-C N` derives any earlier value for the login that precedes fixing it.
- Monotonicity means a re-created entry never silently returns to a password that was
  already retired.

**Rollback and clones.** `seen` records the highest `seq` observed per stream; a stream that
comes back shorter is reported as a rollback. A device takes its next `seq` from its own
stream file. If that file holds records beyond what the device wrote (a copied or restored
install), or a `*.sync-conflict-*` copy of any stream exists, the one-writer rule was broken:
the tool refuses to write and asks for `--new-device-id`. A reinstalled device joins with a
fresh id; its old stream stays readable forever. Compaction and DEK rotation are out of scope
for v3.0.

### 8. Second factor

**Keyfile only**: 32 random bytes, stored as
`"PW3F" || U8(1) || nonce || AES-256-GCM(keyfile-wrap key)`. It can be copied to every device and to a
backup, so it does not break regeneration. `--gen-keyfile` refuses to overwrite. Arbitrary
files as keyfiles and `--recoverable` are removed: the latter was a second memorised secret,
which is now `boost`.

**FIDO2 is removed as a derivation factor.** An hmac-secret output exists inside one
authenticator and cannot be replicated to a second: losing the key loses every password,
which contradicts "regenerable from memory". `--fido2`, `--fido2-register` and the `fido2`
extra are dropped. Physical keys registered *at a site* as its second factor are recorded in
the journal's `keys` field, which is documentation, not derivation.

### 9. Argon2id parameters

`t=3, m=256 MiB, p=4, 64-byte tag`. Measured on the development machine (i7-13700, 32 GB,
argon2-cffi 25.1.0, best of 3):

| m | t | p=1 | p=4 |
|---|---|---|---|
| 64 MiB | 3 | 0.087 s | 0.039 s |
| 128 MiB | 3 | 0.185 s | 0.082 s |
| **256 MiB** | **3** | **0.386 s** | **0.166 s** |
| 512 MiB | 3 | 0.810 s | 0.314 s |
| 1 GiB | 2 | 1.206 s | 0.442 s |

Throughput with every core busy (independent `p=1` instances): 2.6 guesses/s with one process,
14.8 with 8, **17.0 with 16 and with 24**. The machine saturates on memory bandwidth, not on
cores, which is the property being bought.

Why these values:

- RFC 9106's second recommended set is `t=3, m=64 MiB, p=4`. Stretching here runs once per
  run, not once per login on a server, so 4× the memory is affordable.
- 512 MiB halves the attacker's rate again but is where Android becomes fragile (below), and
  the algorithm must be identical on every platform.
- `p=4` cuts honest latency ~2.3× on any phone or laptop without changing the attacker's
  memory × time cost.

**Android, measured on the target device.** Samsung Galaxy S23 Ultra (SM-S918B), Termux,
reference `argon2` 20190702, Argon2id `t=3, m=2^18 KiB, p=4`, 64-byte tag, five runs:

| Run | 1 | 2 | 3 | 4 | 5 | Median |
|---|---|---|---|---|---|---|
| Seconds | 0.908 | 0.975 | 0.938 | 0.928 | 0.881 | **0.928** |

No allocation failure. That is 5.6× the desktop's 0.166 s, somewhat slower than the 3–4×
assumed before the measurement, and well inside the 2 s limit.

The rest of the table below is still an **estimate**: the flagship row for native code is now
replaced by the measurement, the mid-range column and the pure-JVM row are not measured.
Assumption for those: a mid-range 4 GB phone is 8–15× slower than the desktop.

| Implementation | Flagship | Mid-range 4 GB (est.) |
|---|---|---|
| Native libargon2, 4 threads | **0.93 s (measured)** | 1.5–3 s |
| Bouncy Castle, pure JVM, 1 thread | 2.5–4.5 s (est.) | 6–12 s, likely OOM |

The pure-JVM path allocates the 256 MiB on the Java heap, at or above the default per-app
limit on many devices. The Android target therefore needs the native implementation; Bouncy
Castle is acceptable for the desktop JVM target. The app must run the stretch off the main
thread and keep `PRK` for a short, visible session instead of re-stretching per site.

**The parameters are frozen.** The gate set before freezing was a median of at most 2 s on
the target phone with no allocation failure; the measurement above meets it, so
`m=262144` stands and `ALG` is final. The parameters never change from here on; a different
set would be a new `ALG` and therefore a different set of passwords. The measurement was
taken with the reference command-line binary, not inside the app: the app's native call
should match it, and must still run off the main thread.

### 10. Cost of an attack, in GPUs

The attacker holds one site password with its `site`/`login`/`counter`/flags (or a published
public key, or `recovery.pw3` plus a stream) and knows `user_id`. Each guess of
`(master, boost)` costs one full Argon2id; nothing can be precomputed across users (salt) or
across parameter sets (`ALG`).

**What bounds a GPU.** One guess fills 256 MiB three times. Each 1 KiB block reads two blocks
and writes one, so a guess moves about 3 × 768 MiB ≈ 2.4 GB through memory, a third of it as
data-dependent random reads. The work is bandwidth, not arithmetic:

| Bound for one top GPU (RTX 5090: 32 GB, ~1.8 TB/s nominal) | guesses/s |
|---|---|
| Hard ceiling: nominal bandwidth ÷ 2.4 GB, perfect efficiency | ~700 |
| Concurrency allowed by VRAM: 32 GB ÷ 256 MiB | 125 instances |
| Published measurement, scaled: 8× RTX 5090 ≈ 490 H/s on Argon2id (Specops, 2026), i.e. ~61 per card; scaled ×¼ for 256 MiB | **~15** |
| **Planning figure used below** | **100** |

The Specops parameters were not available to us. Their own comparison (a 96-core EPYC at
730 H/s) matches this desktop's measured rate at 64 MiB, `t=3` scaled by core count and memory
channels, so 64 MiB is assumed; if they used less memory, the scaled figure drops further. The
planning figure of 100 is about 7× today's best published software and one seventh of the
physical ceiling. In the same study the rig did 221×10⁹ SHA-256/s, about 2.8×10¹⁰ per card,
which is the v2 column.

Time to exhaust the space (halve for the average):

| Guessing entropy | v2, 1 GPU (~10¹⁰/s) | v3, 1 GPU (100/s) | v3, 100 GPUs | v3, 10 000 GPUs |
|---|---|---|---|---|
| 30 bits (weak master, boost known) | instant | 124 days | 30 hours | 18 minutes |
| 40 bits | 2 minutes | 350 years | 3.5 years | 13 days |
| 51.7 bits (4-word boost alone) | 4 days | 1.2×10⁶ years | 12 000 years | 117 years |
| **64.6 bits (5-word boost alone)** | 88 years | 8.8×10⁹ years | 8.8×10⁷ years | 880 000 years |
| 77.5 bits (6-word boost alone) | – | – | – | 6.8×10⁹ years |

At roughly 5×10⁻⁷ USD per guess (card amortised over three years plus power), exhausting a
4-word boost costs on the order of 2×10⁹ USD and a 5-word boost 10¹³ USD, before any entropy
from the master password. Argon2id buys about 27 bits over v2 at the planning figure. The
rows for the boost alone are the floor: they hold even if the master password is already
known, which is why `boost` is mandatory and why 4 words is the minimum, not the default.

### 11. Migration

`--migrate-v2` asks for the v2 master (and v2 keyfile), the v3 secrets and the access
password, then:

1. Opens `hosts.enc` with the v2 code. Each line is canonicalised with the §1 rule and written
   to this device's stream as a `put` (counter 1, `x.origin = "v2"`). Lines that fail the rule
   are listed for manual correction, never guessed.
2. Reads the v2 log. Records hold only truncated hashes, so they are joined to the hosts list
   by recomputing each context's `app:` summary; a match recovers the last `len`/`feat` for
   that site. Unmatched records are counted and reported.
3. Optionally writes v2 password → v3 password per site into a `.kdbx` (two entries per site).
4. Uses a v2 keyfile (`--v2-key-file`) only to read the v2 data. It is not carried over: a v3
   keyfile is exactly 32 random bytes and every password changes anyway, so a new one is
   created with `--gen-keyfile`.
5. Lists `master.hash`, `hosts.enc`, the v2 log, `fido2.cred` and old CSV exports and, on
   confirmation, deletes them, **after** the stream is written and re-read successfully.
   `--keep-v2-files` skips the question.

v2 passwords generated with `--fido2` cannot be reproduced by the migration.

Deleting a file does not erase it from an SSD, a snapshot or a backup. Any master password
that was ever registered with `--register-master`, or whose summary line was logged in clear,
must be treated as exposed and **not reused as the v3 master**.

### 12. CLI

| v2 | v3 |
|---|---|
| `-T`, `--temporal-secret-file`, `--gen-temporal` | removed; `--gen-boost [N]` (5 default, 4 minimum), boost always prompted hidden |
| – | `--user-id`, `-u/--login`, `-C/--counter N`, `--bump` |
| – | `--init`, `--join` (new device on an existing journal), `--new-device-id` |
| `--register-master`, `--no-check` | removed; fingerprint always shown |
| `--master-pass` | removed (argv is visible to other processes); `--secrets-stdin` for automation |
| `--plain-log`, `-w`, `--no-print-hash` | `--no-journal`; no summary line exists |
| `--audit`, `--view-log`, `--view-list`, `--encrypt-list` | `--list`, `--show SITE`, `--history [SITE]`, `--edit SITE`, `--resolve SITE`, `--import-list FILE`: **access password only** |
| – | `--change-access-password`, `--recover` (open the journal with the recovery text or file), `--keep-recovery-file` |
| `-o/--output` (7 CSV formats) | `--export-kdbx FILE` |
| `--mass-rekey` | same, over the journal, output to `.kdbx`; issues a new recovery text (below) |
| `--fido2`, `--fido2-register` | removed |
| `--gen-keyfile --recoverable`, raw keyfiles | removed |
| `-V v2` | `--migrate-v2`, `--v2-show SITE` (read-only) |

**`--mass-rekey` and the recovery text.** `KEK_r` is derived from `master + boost`, so after
a rekey the recovery text issued earlier does not open with the new secrets. `--mass-rekey`
therefore prints a **new** recovery text (Base32 and QR) wrapped under the new secrets, and
warns that the previously printed one **still opens the journal with the old master and
boost**: the DEK did not change. The old printout must be destroyed. The same holds for a
`recovery.pw3` kept on disk, which is replaced.

Length and class flags are unchanged, but when the journal has an entry for the site its
values win and a differing flag is an error unless `--force`. The canonical site and the
fingerprint are printed before the password.

## Test vectors

`tests/vectors/v3/`, Python normative, same `--check` discipline as v1:

- canonicalisation (accept and **reject** cases, including non-ASCII sites) for every input;
- a few full-cost stretch cases (`K0` in hex), and many cheap cases that start from a given
  `K0`, so the Kotlin suite does not pay 256 MiB per case;
- every purpose in §4; sampling cases that hit byte rejection and class rejection;
- fingerprint; access slot and recovery wrap with fixed DEK, salts and nonces;
- journal: record decryption, and **merge scenarios** as sets of streams with the expected
  folded state (identical concurrent bump, divergent bump, delete then re-create, clock
  skew, rollback, cloned device).

v1 vectors are generated from the code they test. v3 adds independent checks for the
primitives: Argon2id cross-checked between argon2-cffi and a second implementation, HKDF-SHA512
against Wycheproof, plus a chi-square test on the sampler.

## Consequences

- New mandatory Python dependency: `argon2-cffi`; optional `pykeepass`. Kotlin gains a native
  Argon2 dependency on Android and Bouncy Castle on desktop.
- A derivation that also updates the journal runs Argon2id twice (access slot and `K0`),
  about 0.4–0.8 s on a desktop, unless the device opted into `--keep-recovery-file`.
- **Changing the access password does not revoke the old one.** The DEK is fixed, so any
  earlier copy of `keys.pw3` (Syncthing file versioning, a backup, another device that has
  not synced yet) still opens the journal with the old password, including records written
  later. Revocation needs DEK rotation, which is out of scope for v3.0. For the same reason
  a recovery text issued before `--mass-rekey` keeps working with the old secrets.
- There are now three secrets to remember. The access password is the low-value one: losing
  it is recoverable, and leaking it exposes metadata and notes, not passwords.
- The Android app in v3.0 is derivation-only. Reading a Syncthing-replicated journal on the
  phone is possible with this format but is not in scope.
- Published public keys (ADR-0003) remain offline oracles, now at Argon2id cost with the
  boost as a floor. The risk is mitigated, not removed.
- Not addressed: a compromised machine or keylogger, phishing (nothing binds the site string
  to the page being visited), a malicious device that already holds the DEK, and memory
  hygiene beyond best effort. Python cannot reliably erase an immutable `str`;
  `wipe_string_from_ram` is removed instead of repaired.

## Open questions

1. The Portuguese word list. One is built and bundled (sources and licences in
   `src/passweird/v3/data/README.md`); its content still awaits the author's review. It can
   change without touching the algorithm, as long as it keeps 7776 entries.

Resolved in revision 2: non-ASCII sites are rejected; FIDO2 is removed; the 16-bit verifier
is removed in favour of the fingerprint alone. Resolved in revision 3: the recovery wrap is
printed once and kept on disk only with an explicit flag. Resolved in revision 4: `m` is
frozen at 262144 KiB after the on-device benchmark (§9). Revision 5: diacritics are removed
from the boost; the access slot's field widths are stated; `--mass-rekey` reissues the
recovery text.
