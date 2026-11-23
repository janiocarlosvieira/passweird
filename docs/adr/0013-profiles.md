# ADR-0013 — Profiles: several independent installations on one device

**Status:** Accepted
**Date:** 2026-11-23
**Builds on:** [ADR-0009](0009-v3-key-stretching-and-derivation.md) (§6 local state, §7 layout,
§12 CLI). Nothing in the derivation, the file formats or the vectors changes.
**Touches:** [ADR-0010](0010-linux-desktop-application.md) (§3 lock, §6.1 first run),
[ADR-0011](0011-android-application-for-v3.md) (§4, §6, §7) and
[ADR-0012](0012-windows-application.md) (§1, §4 local state).

## Context

A v3 installation is one directory per operating-system user. `base_dir()` in `v3/app.py`
returns `~/.passweird/v3`, with no option or environment variable to change it (ADR-0012 §4
moves it to `%LOCALAPPDATA%\Passweird\v3` on Windows, through `local_state_dir()`). The
directory holds one `config` (`user_id`, `journal_dir`, `device_id`, default length and
classes), one `seen` and, if kept, one `recovery.pw3`. `--journal-dir` chooses where the
journal lives, but only at `--init` or `--join`, and only once: a second `--init` is refused
because a configuration already exists.

KeePassXC users separate concerns by file: a work database that stays on the work machine and
never enters a synchroniser, a personal one replicated to every device. Passweird has no
equivalent, and the author needs exactly that split: a work registry kept on the work machine
only, next to a personal registry synchronised by Syncthing.

What works today, and why it is not enough:

1. **`--no-journal --user-id ID`** derives under another user id without reading or writing a
   journal. It is a second derivation context with no registry: no counters, no history, no
   notes.
2. **`HOME=… passweird`.** On Linux `base_dir()` follows `$HOME`, so this yields a second
   installation. It also redirects everything else in that process and its children that
   reads `$HOME` (Qt settings, `keepassxc-cli` for the optional merge), nothing on screen says
   which installation is in use, and it has no counterpart on Windows or Android.
3. **A second operating-system account.** Real isolation, far too heavy for daily use.

A note on the word. In v2, "context" (*contexto*) is the site or application string
(`storage.py`: "Contexto do Aplicativo"; `migrate.py` still says "v2 context"). To avoid giving
the same word a second meaning, this feature is called **profile**.

## Goals and non-goals

Goals:

- Several independent installations on one device, each with its own user id, access
  password, journal folder, device id, `seen`, recovery file and defaults, and, when the user
  wants it, its own master, boost and keyfile.
- The profile in use is always chosen explicitly and always visible.
- The installation that exists today becomes the profile `default`, with no migration.
- No change to derivation, to any file format or to the vectors.

Non-goals:

- **Isolation between profiles against the same OS user.** Every profile's files are readable
  by that user's processes, as every KeePassXC database in one home directory is. A second OS
  account remains the answer when that is the threat.
- **Sharing one journal between two profiles**, or one profile spanning two journals.
- **Moving entries between profiles.** `--list` and `--import-list` already carry site names
  across; counters and history stay where they were written.

## Decision

### 1. A profile is a local state directory, and its name is only a label

A profile is the directory that ADR-0009 §7 calls `~/.passweird/v3/`: `config`, `seen`,
`recovery.pw3` when kept, and the lock file of ADR-0010 §3 once it exists. Its journal folder
is chosen at `--init` or `--join`, as today, and recorded in its `config`.

The profile name enters **no derivation, no journal file and no record**. Two consequences,
both deliberate:

- Renaming a profile is renaming its directory. No password changes.
- What makes two profiles derive different passwords is their secrets and user id, never their
  names (§6).

### 2. Layout

```
local_state_dir()/              ~/.passweird/v3 (Linux), %LOCALAPPDATA%\Passweird\v3 (Windows)
  config  seen  recovery.pw3    profile "default": exactly today's files, unmoved
  journal/                      default journal folder of "default", as today
  profiles/                     0700 on Linux; the ACL of ADR-0012 §4 on Windows
    <name>/                     same protection
      config  seen  recovery.pw3
      journal/                  default journal folder of <name>
```

The default profile stays at the root so that every existing installation keeps working
untouched. `profiles` is not a name ADR-0009 uses, so nothing collides. The asymmetry is the
price of zero migration (Alternatives, 6).

The default journal folder of a named profile is inside its own directory, local and not
synchronised: the right default for a registry that must stay on one machine. A profile meant
to be synchronised is initialised with `--journal-dir` pointing at the folder Syncthing
replicates, exactly as today.

### 3. Names

A profile name is trimmed and ASCII-lowered, as `user_id` is (ADR-0009 §1), and must then match

```
^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$          1 to 32 characters
```

`default` is reserved for the root profile. The Windows device names `con`, `prn`, `aux`,
`nul`, `com1`–`com9` and `lpt1`–`lpt9` are refused **on every platform**, so that a name valid
on one system is valid on all of them. Anything else is rejected with the rule in the message,
never adjusted.

### 4. Selection: explicit, never remembered

```
--profile NAME          if given
PASSWEIRD_PROFILE       otherwise, if set and not empty
default                 otherwise
```

There is **no stored "current profile"**. A remembered selection is hidden state, and the cost
of the wrong profile is concrete: a password derived under the wrong secrets, or a rotation
written to the wrong registry. A shell alias (`alias pw-work='passweird --profile work'`) or a
desktop launcher (§8) gives the same convenience in the open.

A named profile that does not exist is an **error** that names it and suggests
`--init --profile NAME` or `--join --profile NAME`. Only those two commands create a profile
directory, so a typing error never yields an empty profile.

When the selected profile is not `default`:

- the first line of output is `Profile: NAME`, before the canonical site and the fingerprint;
- every prompt carries the name: `[work] Master password:`.

For `default` nothing changes, so the output of an existing installation stays as it is.

### 5. Commands

- **`--init` and `--join`** work inside the selected profile, with today's checks and messages
  plus those of §6.
- **`--list-profiles`** (new) needs no secret. For each initialised profile, `default` first, it
  prints the name, the user id, the journal folder, the first 8 hex digits of the device id,
  whether a recovery file is kept and the pinned keyfile, if any (§9). None of that is secret.
- **Every other command** (derivation, `--list`, `--show`, `--history`, `--edit`, `--resolve`,
  `--delete`, `--import-list`, `--change-access-password`, `--recover`, `--print-recovery`,
  `--export-kdbx`, `--mass-rekey`, `--new-device-id`, `--migrate-v2`, `--v2-show`) acts on the
  selected profile and on nothing else. `--no-journal` keeps its meaning: nothing is read from
  or written to a journal, and the selected profile's `config` still supplies the user id and
  defaults, as the single `config` does today.
- **The recovery text names its profile.** `print_recovery` adds a line with the profile name
  and the user id above the Base32 groups; neither is secret. With two profiles, a printed sheet
  that does not say which registry it opens is half a recovery.
- **No `--delete-profile` and no `--rename-profile`.** Deleting a profile is deleting its
  directory (and its journal folder, if no other device uses it); renaming is renaming the
  directory (§1). The documentation says both. A command would be one more destructive path to
  get wrong, for operations that need no code.

### 6. What keeps profiles independent

Checked at `--init` and `--join`, and again whenever a profile's journal is opened:

1. **One profile per journal on a device.** The `journal_id` in the clear header of `keys.pw3`
   (ADR-0009 §6, offset 5) must not be the `journal_id` of another profile on this device.
   Comparing the identifier rather than the path also catches the same journal reached through
   a symbolic link, or a second copy of it. Two profiles on one journal would be the same
   registry twice, written under two device ids from one machine: never what was meant.
2. **A journal folder never holds local state.** The journal folder of any profile must not
   be, or contain, `local_state_dir()` or any profile directory. This generalises ADR-0010
   §6.1 step 7: a synchroniser pointed at such a folder would replicate `config`, `seen` and
   any `recovery.pw3`.
3. **Same secrets, same passwords.** A profile separates *state*, not *derivation*. Two
   profiles with the same user id, master and boost derive the same password for the same
   site, login and counter. `--init` warns when the user id equals that of another profile on
   the device. The fingerprint exposes the rest: it depends on master, boost and user id, so
   two profiles that show the same four syllables share those secrets.

   For compartmentalisation (a profile whose master may be compromised without touching the
   other) the secrets must differ. A different user id alone changes every password but
   protects nothing, because the user id is not secret. The documentation says so next to
   `--init`.

### 7. Implementation in the engine

- `base_dir()` gives way to `profile_dir(name)`, built on `local_state_dir()` of ADR-0012 §1
  (until that lands, on today's `~/.passweird/v3`). `config_path()`, `recovery_path()`,
  `default_journal_dir()` and the lock path take the profile directory instead of calling a
  module-level function. `journal.Journal` already receives its local directory as an
  argument (that is where `seen` lives), so it does not change.
- The profile is resolved once, in `main.py`, and passed down: to `app.py` today, to
  `service.py` once ADR-0010 §3 lands. No other module reads `PASSWEIRD_PROFILE`.
- The lock of ADR-0010 §3 is per profile. Its purpose is one writer per stream; a stream
  belongs to one journal, and a journal to one profile. Two windows on two profiles are
  therefore allowed; two on the same profile are not.

`seen` is keyed by `journal_id` and starts over when the identifier differs (`_read_state` in
`journal.py`). That is why a profile must be a whole directory and not a section of a shared
`config`: a shared `seen` would be reset at every switch, silently turning off the rollback and
clone detection of ADR-0009 §7 and §13.7.

### 8. Front ends

**Desktop, Linux and Windows (ADR-0010, ADR-0012).**

- The header bar shows the profile name beside the state of ADR-0010 §4, and so does the window
  title.
- A profile selector sits in the header bar. Switching is a **full lock**: it leaves
  "Derivation unlocked" and "Registry open" (wiping `K0` and every `PRK`, and clearing the
  clipboard if it still holds a password the application put there), releases the old
  profile's lock and takes the new one.
- The application starts in the profile named by `--profile` or `PASSWEIRD_PROFILE`, else in
  `default`. It does not remember the last one used (§4). One menu launcher per profile
  (`passweird-gui --profile work`) is the documented way to open a profile directly, much as
  KeePassXC opens a given database.
- The first-run wizard (ADR-0010 §6.1) gains a step 0, the profile name, preset to `default`
  when no profile exists yet. Step 7 applies the checks of §6.

**Android (ADR-0011).**

- **A1, stateless.** The application remembers a short list of `(profile name, user id)` pairs
  instead of a single user id. The Derive screen shows the selected profile and lets the user
  switch, which leaves "Derivation unlocked". ADR-0011 §7 does not move: profiles, like
  secrets, are created on a desktop, and the phone only records the user id of each.
- **A2, registry.** One folder permission per profile, each pointing at that profile's
  synchronised journal folder. A profile whose journal is never synchronised has no registry
  on the phone.

### 9. A keyfile pinned to the profile

The fingerprint is computed from `PRK["none"]` (ADR-0009 §3 and §4), so it does not depend on
the keyfile. A forgotten `--key-file` therefore gives a different password while the four
syllables look right, and nothing in the journal records which factor an entry was derived
with. A profile whose sites are derived with a keyfile can pin it:

- **What is stored.** `config` gains two optional fields: `key_file`, the absolute path, and
  `key_file_sha256`, the SHA-256 of the file's bytes. The hash is not an oracle: the file holds
  a random nonce and a random factor under AES-GCM, and no guess of a secret recomputes it.
- **What it covers.** Everything the profile derives with the selected factor: passwords and
  the TOTP, SSH, TLS, RSA and OpenPGP material, `--export-kdbx` and the old side of
  `--mass-rekey`. The file is checked **before** Argon2id runs: missing, unreadable or with
  another hash, it is an error that names the path. There is no derivation without it.
- **`--key-file` on a pinned profile** is accepted only for a file with the pinned hash (a copy
  kept elsewhere, say); any other file is an error.
- **Setting the pin.** `--pin-key-file PATH` asks for master and boost and opens the keyfile
  under them, so a keyfile made for other secrets is refused by its GCM tag; then it records
  path and hash. `--init --key-file PATH` pins at creation; right after `--init`,
  `--gen-keyfile PATH` followed by `--pin-key-file PATH` does the same, since the registry is
  still empty. When the registry already has entries, pinning is refused unless `--force`,
  with a message that says why: from then on every entry derives with this keyfile, which is
  right only if they were already derived with it. Moving a registry *onto* a keyfile is
  `--mass-rekey --new-key-file`.
- **A moved file.** `--pin-key-file NEWPATH` with a file whose hash is the pinned one only
  updates the path. It needs no secret: it is the same keyfile.
- **Removing the pin.** `--unpin-key-file` is allowed at any time, with a warning: in this
  profile, a derivation without `--key-file` silently gives other passwords again.
- **`--mass-rekey` on a pinned profile** must be told what happens to the factor:
  `--new-key-file PATH` (a keyfile made for the new secrets), which becomes the new pin, or
  `--drop-key-file`, which removes it. Neither is assumed. On an unpinned profile,
  `--new-key-file` keeps today's meaning and pins nothing.
- **The pin is local**, like everything in the profile directory. On a device that joins the
  registry, `--join` asks whether its sites are derived with a keyfile; the answer is a path or
  nothing, and `--key-file PATH` on the command line answers it. At `--join` the file is only
  checked to be a keyfile (its `PW3F` header) and hashed; it is opened under master and boost
  at the first derivation, which fails clearly if it belongs to other secrets.

On the desktop, the unlock dialog of a pinned profile does not ask for a keyfile and fails
before stretching if the file is missing; the profile's settings show the path and offer pin,
move and unpin under the same rules.

## Phases

| Phase | Content | Depends on |
|---|---|---|
| P1 | Engine and CLI: `profile_dir`, selection, names, `--list-profiles`, the checks of §6, the named recovery text, the keyfile pin of §9, tests | – |
| P2 | Desktop: selector, launchers, wizard step 0 | P1, ADR-0010 |
| P3 | Android: profile list (A1), one folder per profile (A2) | P1, ADR-0011 |

Windows inherits P1 and P2 through the platform seam of ADR-0012.

## Tests

- **`default` does not move.** A test pins `~/.passweird/v3/config` (and its Windows
  counterpart) for `default`. The existing suite passes without `--profile`, and its output
  contains no `Profile:` line and no prompt prefix. One change to it is expected: a `--join`
  fed through `--secrets-stdin` answers the keyfile question of §9 with one more line, empty
  for no keyfile.
- **Profiles do not touch each other.** With two profiles side by side, every operation on one
  leaves every file of the other unchanged, compared by hash before and after.
- **Names:** a table of accepted, rejected and reserved names, Windows device names, and ASCII
  lowering.
- **Selection:** `--profile` over `PASSWEIRD_PROFILE` over `default`; an unknown name fails and
  creates nothing.
- **Independence checks:** `--init` and `--join` refused on a journal already attached to
  another profile, also through a symbolic link and through a copy; refused on a journal folder
  that is or contains local state; the warning on a repeated user id.
- **Keyfile pin:** a missing or different file stops derivation before Argon2id; `--key-file`
  with another file is refused; pinning a registry that has entries needs `--force`; a copy with
  the pinned hash moves the pin without secrets; `--mass-rekey` on a pinned profile refuses to
  run without `--new-key-file` or `--drop-key-file`; without a pin, behaviour is today's.
- **Vectors:** the derivation vectors of ADR-0009 pass unchanged under any profile.

## Alternatives rejected

1. **Overriding `$HOME`**, which works today: it redirects everything else, is invisible and
   exists on Linux only.
2. **Several journals in one `config`.** A shared `seen` is reset at every switch (§7), and one
   file holding the settings of unrelated registries couples what should be independent.
3. **The profile name inside the derivation**, as domain separation. Renaming would change
   every password, and the user id already plays that role, as a salt the user knows.
4. **A remembered current profile** (`--use NAME`): hidden state (§4).
5. **One operating-system account per profile.** Correct isolation, not a daily tool. It stays
   the recommendation when isolation from the user's own processes is the requirement.
6. **Moving `default` into `profiles/default/`.** Symmetric, but it moves files under every
   existing installation, including a journal folder that Syncthing may already replicate from
   `~/.passweird/v3/journal`. Zero migration wins.

## Consequences

- Derivation, formats and vectors are untouched, and `default` is today's installation.
- One more thing to get wrong: the profile. Explicit selection, the error on unknown names and
  the name on every prompt are the mitigation. The fingerprint catches the wrong profile's
  secrets being typed, provided the profiles' secrets differ.
- Each profile has its own recovery text and access password and, if compartmentalised, its
  own master and boost. Compartmentalising multiplies what must be remembered and kept on
  paper; that is the cost of the separation, and the reason it is optional.
- Profile names appear in shell history, in `argv` and in the environment. They are labels,
  not secrets, and should be chosen as such.
- A pinned keyfile that goes missing now stops every derivation of its profile, instead of
  silently producing other passwords. The advice of ADR-0009 §8, to copy it to every device
  and to a backup, matters more.

## Decided with the author (2026-11-23)

- **Keyfile pinned per profile:** yes (§9). It was the first open question of the proposal.
- **Status:** accepted.

## Open questions

1. **Showing profiles on the phone when only `default` exists.** Proposal: no; the selector
   appears with the second profile.
2. **Starting the desktop application in the last profile used** would be friendlier and
   contradicts §4. Proposal: no, for the reason given there.
