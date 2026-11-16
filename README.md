# Passweird

Passweird is a **deterministic** password generator: instead of storing passwords in a vault, it
recomputes the same password every time it is given the same ingredients. Nothing on disk can
generate a password; if you remember your secrets you can rebuild every one of them on any
machine.

The same derivation produces **SSH** keys, **TLS** certificates (Ed25519 or RSA), **TOTP**
secrets and **OpenPGP** key pairs.

This is the **v3** engine, specified in
[ADR-0009](docs/adr/0009-v3-key-stretching-and-derivation.md). It is a compatibility break: no
v2 password reproduces under v3. See [Migrating from v2](#migrating-from-v2).

## What you remember, and what each thing opens

| Secret | Opens | If it leaks |
|---|---|---|
| **Master password** + **boost** | every password and key | everything; both are needed |
| **Access password** | the journal: your site list, counters, notes | metadata and notes, no password |

- The **boost** is one extra secret, the same for every site, drawn once by the tool and
  memorised. Master and boost go through Argon2id (256 MiB) **together**, so neither can be
  guessed without the other and every guess costs a full memory-hard computation.
- The **journal** remembers what a stateless generator cannot: which sites you use and which
  counter, length and character classes each one has. It is encrypted, never holds a password,
  and is meant to be replicated between your devices (for example with Syncthing).
- A **fingerprint** such as `kode-nafi` is shown on every run. It is how you notice a typo in
  the master password or boost. It is stored nowhere.

## Requirements

- Python 3.10+
- The `gpg` (GnuPG) binary, only for `--pgp`. On Windows install
  [Gpg4win](https://gpg4win.org/) separately.

## Installation

```bash
pipx install passweird            # recommended
# or: pip install passweird
```

Optional extras:

```bash
pipx install "passweird[kdbx]"    # --export-kdbx (KeePass database)
pipx install "passweird[qr]"      # QR code of the recovery text
pipx install "passweird[totp]"    # otpauth URI and current code for --totp
pipx install "passweird[pgp]"     # --pgp (still requires the gpg binary)
pipx install "passweird[all]"
```

For development:

```bash
git clone https://github.com/janiocarlosvieira/passweird.git
cd passweird
pip install -e ".[dev]"
pytest tests/ -q
```

## First steps

```bash
passweird --gen-boost     # draws 5 Portuguese words (64.6 bits); memorise them
passweird --init          # user id (e.g. your e-mail), master, boost, access password
```

`--init` prints the fingerprint and, **once**, a recovery text (Base32, plus a QR code with the
`qr` extra). Keep it on paper or offline: together with master + boost it reopens the journal
if you forget the access password. It is not stored on the device unless you pass
`--keep-recovery-file`.

Then:

```bash
passweird github.com -u fulano     # derive a password, and remember the site
passweird github.com -u fulano     # same password again
passweird github.com -u fulano --bump    # rotate: shows the current and the next password
passweird --list                   # needs only the access password
```

Secrets are always prompted hidden. They are never accepted as command-line arguments, never
printed back and never written to disk.

### More devices

Replicate the journal folder (`~/.passweird/v3/journal` by default, or `--journal-dir`) with a
tool such as Syncthing, then on each further device:

```bash
passweird --join --journal-dir /path/to/synced/journal
```

Each device appends only to its own file inside the folder, so the sync tool never has two
versions of one file to reconcile. If two devices rotate the same site while offline, the
higher counter wins and the entry is marked as a conflict until you run `--resolve SITE`.

## Site names

A URL is reduced to its host by a fixed, purely syntactic rule:
`https://WWW.GitHub.com:443/login` becomes `github.com`. There is no public-suffix logic, so
`accounts.google.com` and `google.com` are different sites; the canonical name is always
printed before the password. Non-ASCII host names are rejected: enter the `xn--` form.

## Flag reference

### Derivation

| Flag | Description |
|---|---|
| `SITE` | Site or context. Prompted if omitted (`-p` prompts hidden) |
| `-u, --login` | Login at the site; part of the derivation |
| `-C, --counter N` | Derive with this counter instead of the journal's |
| `--bump` | Rotate: show current and next password, record the new counter |
| `-L, --length` | Length, 8–128 (6–128 for digits only). Default 18 |
| `-U`, `-l`, `-n`, `-s` | Disable uppercase / lowercase / digits / specials |
| `--force` | Use the flags given even if the journal entry differs, and record them |
| `--no-journal` | Stateless run: reads and writes nothing (add `--user-id` if not initialised) |
| `--key-file PATH` | Keyfile as a second factor (see `--gen-keyfile`) |
| `--totp`, `--ssh`, `--ssl`, `--rsa BITS`, `--pgp` | Derive that kind of material instead of a password |

When the journal has an entry for a site, its counter, length and classes are used; flags that
differ are an error unless `--force`.

### Journal (access password only)

| Flag | Description |
|---|---|
| `--list`, `--show SITE`, `--history [SITE]` | Read the journal |
| `--edit SITE` with `--notes`, `--second-factor`, `--hw-key` | Free-form fields: notes, where the site's TOTP lives, physical keys registered there |
| `--resolve SITE`, `--delete SITE` | Clear a conflict; delete an entry (its counter is kept as a floor) |
| `--import-list FILE` | Add sites from a text file, one per line (`site [login]`) |
| `--change-access-password` | Change it. **This does not revoke the old one**: any earlier copy of `keys.pw3` still opens the journal |

### Setup, recovery, export

| Flag | Description |
|---|---|
| `--gen-boost [N]` | Draw a boost of N words (default 5, minimum 4) |
| `--init`, `--join`, `--journal-dir DIR` | First device; further devices |
| `--new-device-id` | After copying or restoring an installation |
| `--gen-keyfile PATH` | Create a keyfile (never overwrites). Copy it to every device and to a backup |
| `--recover [--recovery-file PATH]` | Lost access password: reopen the journal with the recovery text |
| `--print-recovery`, `--keep-recovery-file` | Issue the recovery text again; store it on this device |
| `--export-kdbx FILE` | Export passwords (all, or `SITE`) to a new KeePass database |
| `--mass-rekey --export-kdbx FILE` | New master/boost: old and new password of every site |
| `--secrets-stdin` | Read every prompt from standard input, for automation |

### Export to a password manager

Passwords leave Passweird only as an encrypted KeePass database (KDBX 4; Argon2id, 256 MiB,
3 iterations, parallelism 4). There is no plaintext export.

```bash
passweird --export-kdbx ~/passweird-export.kdbx
```

Then in KeePassXC open your main database, choose **Database → Merge From Database…**, select
the export, and delete it afterwards.

## Security model, in short

- **Nothing stored can generate.** No hash of the master password, no summary of any secret
  and no generated password is written anywhere. A test scans every file the tool creates.
- **A leaked site password is an offline oracle, at a price.** Someone holding one of your
  passwords, its site and your user id can test guesses of master + boost. Each guess costs one
  Argon2id over 256 MiB; a high-end GPU manages on the order of 100 per second, against about
  10¹⁰ for the v2 scheme. A 5-word boost alone puts the search out of reach
  ([ADR-0009 §10](docs/adr/0009-v3-key-stretching-and-derivation.md)).
- **Published public keys** (`--ssh`, `--ssl`, `--rsa`, `--pgp`) are the same kind of oracle.
- **The synced journal** is an oracle for the access password only. The recovery text is an
  oracle for master + boost, which is why it is kept off disk by default.
- **Not protected against:** a compromised machine or keylogger, phishing (nothing ties the
  site name to the page you are on), and a device that already holds the journal key.
- Python cannot reliably erase strings from memory; keys are zeroed on a best-effort basis.

Let the tool draw the boost. A phrase you invent is far weaker than it looks, and its strength
cannot be measured; five random words are 64.6 bits whatever the attacker knows about the method.

## Migrating from v2

```bash
passweird --init
passweird --migrate-v2                              # site list and settings
passweird --migrate-v2 --export-kdbx pairs.kdbx     # also old → new password per site
passweird --v2-show CONTEXT                         # read-only: one v2 password
```

The v2 site list (`hosts.enc`) is imported; lengths and character classes are recovered from the
v2 log where a record matches. Entries without a canonical v3 name are listed, not guessed. The
v2 files are deleted only if you confirm. v2 passwords made with `--fido2` cannot be reproduced.

If the v2 master password was ever registered with `--register-master`, or its summary line was
shown or logged, treat it as exposed and **do not reuse it** as the v3 master.

Removed in v3: `-T` and temporal-secret files (replaced by the boost and the counter),
`--register-master`, `--master-pass`/`--master-file`, the plaintext log, CSV export, FIDO2 as a
derivation factor, `--recoverable` keyfiles, change mode (`-c`) and batch mode (`-f`).

## Code layout

- `passweird/v3/` — the v3 engine: `canon` (input canonical form), `derive` (Argon2id, HKDF,
  sampling), `keys` and `journal` (key hierarchy, per-device streams, merge), `kdbx`,
  `artifacts` (SSH/TLS/OpenPGP), `migrate`, `app` (what the CLI does).
- `passweird/main.py` — argument parsing.
- `passweird/crypto.py`, `passweird/storage.py` — the v2 engine, kept to read old data and for
  the shared key-format builders.
- `kotlin/` — the Android/desktop app, **still on the v2 engine**; porting it to v3 is pending.

The command line is currently English only; the v2 translations have not been carried over yet.

## Running the tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
python tools/generate_vectors_v3.py --check
```

- `tests/test_v3_canon.py`, `test_v3_derive.py`, `test_v3_journal.py` — the v3 golden vectors in
  `tests/vectors/v3/`, plus checks that do not come from this code: Argon2id against a second
  implementation and the RFC 9106 vector, HKDF against Wycheproof, a chi-square test of the
  sampler.
- `tests/test_v3_cli.py`, `test_v3_migrate.py`, `test_v3_kdbx.py`, `test_v3_artifacts.py`,
  `test_v3_wordlist.py` — the command line end to end, migration, export, key material.
- `tests/test_crypto.py`, `test_storage.py`, `test_regressions.py`, `test_vectors.py` — the v2
  engine.

The tests never touch the real `~/.passweird`: `conftest.py` redirects the home directory to a
temporary one for every test.

## License

GNU General Public License v3.0.
