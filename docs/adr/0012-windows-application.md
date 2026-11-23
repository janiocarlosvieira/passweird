# ADR-0012 — The Windows application

**Status:** Proposed
**Date:** 2026-11-16
**Builds on:** [ADR-0009](0009-v3-key-stretching-and-derivation.md) (algorithm and journal),
[ADR-0010](0010-linux-desktop-application.md) (the desktop application and its interaction
model) and the decisions recorded in [ADR-0011](0011-android-application-for-v3.md) about
defaults and minimum platform versions.

## Context

ADR-0010 defines the desktop application: Python with Qt 6 (PySide6), in the same process as
the normative engine, over a service layer shared with the CLI. ADR-0011 carries the same
model to Android, where a second implementation was unavoidable.

Windows is a different case from Android. Python and Qt both run there, the CLI is already
tested on Windows in CI on every commit, and the engine already tolerates the platform
(`fileio.py` skips the directory `fsync` Windows cannot do; the wheels of `argon2-cffi` and
`cryptography` exist for it). The question is therefore not "which technology" but "what does
ADR-0010 assume about Linux that is false on Windows".

Those assumptions, found by reading ADR-0010 and the code:

1. **Installation.** `pipx` presumes a Python the user installed. Most Windows users have none.
2. **Where local state lives.** `~/.passweird` resolves inside the user profile, next to
   folders that OneDrive commonly takes over and uploads.
3. **File privacy.** Modes `0700`/`0600` mean nothing on NTFS; `chmod` silently does nothing.
4. **Atomic replacement.** Renaming over a file fails on Windows while another process holds
   it open, and a synchroniser or an antivirus scanner routinely does.
5. **Lock, suspend and session signals** come from D-Bus in ADR-0010.
6. **Clipboard.** Windows keeps a clipboard history and can sync the clipboard to the cloud
   and to other devices. The KDE hint of ADR-0010 means nothing here.
7. **Screen capture and crash dumps** have Windows-specific mechanisms, some of them better
   than what X11 offers.

## Goals and non-goals

**Goals.** The same application, the same screens, the same three tiers and the same
passwords as on Linux, installable by someone who has never heard of Python, with the
platform's own protections switched on.

**Non-goals.**

- **No third implementation.** No C#, no WinUI, no Kotlin desktop. Every password on Windows
  comes from the Python engine that the vectors define.
- **No Windows Hello unlock, no credential stored in the Credential Manager or under DPAPI.**
  Same reasoning as ADR-0011 §5: a wrapped `PRK` at rest is derivation material protected by
  the Windows sign-in instead of by the boost.
- No browser extension, no autofill, no tray icon, no background service (ADR-0010).
- No Microsoft Store package in the first version (Open questions).

## Decision

### 1. One code base, one platform seam

The application of ADR-0010 runs on Windows **unchanged above one module**. Everything that
differs between the two systems sits behind a single interface, with one implementation each:

```
passweird/gui/platform/__init__.py     picks the implementation at import
passweird/gui/platform/linux.py        D-Bus, KDE clipboard hint, RLIMIT_CORE, .desktop entry
passweird/gui/platform/windows.py      this ADR
```

The interface is small and closed: `on_lock(callback)`, `on_suspend(callback)`,
`copy_secret(text)`, `clear_secret()`, `protect_window(window)`, `harden_process()`,
`local_state_dir()`, `install_shortcut()`. No `if sys.platform` appears anywhere else in
`passweird/gui/`; a test enforces it, next to the "no cryptography in the GUI" rule.
`windows.py` uses `ctypes` against the system DLLs. It adds no dependency.

The rules of ADR-0010 §3 hold as they are, and the platform module is covered by the first
one: it contains no cryptography.

### 2. Supported systems

**Windows 11, on releases Microsoft still services**, x64. Windows 10 is out of support and is
not a target: the same principle as the Android minimum of ADR-0011, a security tool does not
run on a system that no longer receives fixes. The application checks the build at start and
refuses older ones with a sentence that says why. The minimum is raised, never lowered, as
releases leave servicing. ARM64 follows when the Qt and Argon2 wheels for it are verified in
CI; until then it is not claimed.

### 3. Installation: a signed, self-contained build

Two supported ways, the same code in both:

- **Installer (the default for people).** A frozen build that carries its own Python, Qt and
  the engine, produced in CI from a tagged commit, installed **per user** (no administrator
  rights) under `%LOCALAPPDATA%\Programs\Passweird`, with a Start-menu shortcut and a clean
  uninstaller. It contains both `passweird-gui.exe` and the console `passweird.exe`.
- **`pipx install "passweird[gui]"`**, for those who already live in Python. Identical
  behaviour; `passweird-gui --install-shortcut` creates the Start-menu entry.

Conditions on the installer:

- **The binaries and the installer are code-signed.** An unsigned build of a password tool
  trains its users to click through SmartScreen, which is the opposite of what it should
  teach. No public release happens before signing is in place.
- **The build is reproducible in substance:** pinned Python, pinned wheels with hashes, the
  build script in the repository, and the SHA-256 of every release artefact published with
  the tag.
- **The frozen build runs the vector suite before it is released**, as a built executable,
  not only as source: all of `canonical.json`, `derivation.json` and `journal.json`,
  including the three full-cost Argon2id cases. A packaging mistake that drops or replaces a
  native library must fail here.
- **The frozen build pins the Python version**, and with it the Unicode tables behind
  NFC/NFD/NFKC. ADR-0009 already confines the exposure (explicit white-space list, explicit
  removed block, ASCII-only case mapping), and the vectors catch a divergence on the code
  points they cover.
- **No self-update.** The application does not download or replace its own code. *About* shows
  the installed version and the address of the releases page; the application itself still
  makes no network connection.

The freezing tool (PyInstaller, Nuitka or Briefcase) is chosen in phase W1 by which one
passes the conditions above with the fewest antivirus false positives; the choice is recorded
in the build script.

### 4. Local state and the journal folder

- **Local state goes to `%LOCALAPPDATA%\Passweird\v3`**, never to the roaming profile and
  never under Documents or Desktop. This is `local_state_dir()` of §1, and the CLI uses the
  same function, so both front ends agree. It holds what `~/.passweird/v3` holds on Linux:
  the configuration, `seen`, the lock file, and the recovery file only if explicitly kept.
- **Privacy by ACL, not by mode.** When the directory is created, inheritance is disabled and
  the ACL is set to the current user, SYSTEM and Administrators only, and the same check runs
  at start: if another principal has access, the application says which and offers to fix it.
- **The journal folder must not be inside a cloud-synchronised location.** At `--init` and
  `--join`, and again at every start, the application resolves the folder and refuses it if
  it lies under a OneDrive root (personal or business, including Documents and Desktop when
  "known folder backup" has redirected them) or under another provider's sync root that
  Windows reports. Syncthing is the only synchroniser the design assumes. The same check
  applies to the place chosen for a KDBX export, as a warning the user can override.
- **Atomic writes with patience.** `os.replace` is atomic on NTFS, but it raises a sharing
  violation while Syncthing or a scanner holds the target. The engine's `atomic_write` gains
  a bounded retry for exactly that error on Windows (short back-off, a few seconds in total),
  after which it fails with a message that names the file. It never falls back to writing in
  place. The directory `fsync` stays skipped, as today; `seen` and `pending` (ADR-0009
  §13.7) are what make an interrupted write recoverable either way.
- **File names** in the journal are lower-case hex and survive a case-insensitive file
  system. The application refuses a journal folder on a volume that is not NTFS or ReFS.

### 5. The three tiers: same states, Windows signals

States and timeouts are those of ADR-0010 §4 as decided there: registry 15 min, derivation
2 min, clipboard 60 s. The triggers come from the session instead of D-Bus:

| Event | Source | Effect |
|---|---|---|
| Workstation locked, user switched | session-change notifications | leave "Derivation unlocked" and "Registry open" |
| Remote session connected or disconnected | the same notifications | the same |
| Sleep, hibernate | power-broadcast messages | the same |
| Idle | the application's own timers | per state |

If registering for the notifications fails, the timers still apply and *About → Security*
says the lock signal is unavailable.

### 6. Secrets on Windows

- **Clipboard.** A copied password is placed with the three clipboard formats Windows defines
  for this purpose, which exclude the content from **clipboard history**, from **cloud
  clipboard sync** to other devices, and from clipboard monitoring tools that honour them. It
  is cleared after 60 s or on lock, only if the clipboard still holds that value. If history
  or cloud sync is enabled in Windows, the first copy of a session says so once: the formats
  are a request that well-behaved components honour, not an enforcement.
- **Screen capture.** Every window is excluded from capture with the display-affinity setting
  Windows provides: screenshots, screen recording, remote-assistance tools and the system's
  own activity-snapshot features see a black rectangle. This is stronger than anything
  ADR-0010 can do under X11, and it is on by default with no setting to turn it off. The
  recovery-text window is covered like the rest; it can still be **printed**.
- **Crash handling.** At start the process disables the error-reporting dialog for itself and
  registers itself as excluded from Windows Error Reporting, so that a crash does not write a
  memory dump that may be uploaded. The exception hook prints type and location, never
  values, as in ADR-0010.
- **Memory.** `K0` and every `PRK` are wiped on leaving "Derivation unlocked", as on Linux.
  The limits are the same and are stated the same way: Python cannot erase an immutable
  `str`; the page file and the hibernation file may hold what was in memory, which is an
  argument for full-disk encryption, not something the application can fix. *About →
  Security* reports whether the system volume is encrypted and recommends it if not.
- **Entry fields** as in ADR-0010 §7. A hardware or software keylogger and a compromised
  session remain out of scope, exactly as on Linux.
- **Antivirus.** The application asks for no exclusion and documents none. If a scanner
  quarantines a release, that is a release defect to be fixed by signing and by the choice of
  freezing tool, never by telling users to add an exception.

### 7. What the other features need on Windows

- **KeePass merge (ADR-0010 §6.7).** `keepassxc-cli.exe` is looked up in KeePassXC's install
  directory as well as on `PATH`. The same conditions apply: password on standard input,
  backup copy first, result verified, manual path as the default.
- **Printing the recovery text** goes through the system print dialog with no temporary file.
  The dialog's "print to PDF" and "print to OneNote" destinations produce a file or a cloud
  note; the confirmation screen says so before the dialog opens.
- **Synchronisation panel.** Unchanged. It also reports the cloud-folder check of §4.
- **Console.** The CLI stays supported on Windows as it is today. `--mass-rekey` and
  `--migrate-v2` remain CLI-only (ADR-0010 §6.8).
- **Language and accessibility.** Portuguese and English; the Windows high-contrast themes
  and Narrator are tested once per release, since Qt's defaults do not guarantee either.

### 8. Tests

- CI already runs the Python suite on Windows; the GUI suite of ADR-0010 §10 joins it,
  headless.
- Platform-module tests on a Windows runner: the ACL after creating the state directory; the
  OneDrive-root detection against a fabricated environment; the retry of `atomic_write`
  with the target held open by another process; the clipboard formats actually present after
  `copy_secret`; the clear-only-if-unchanged rule.
- Release gate: the frozen executable passes the vector suite (§3), is signed, and its
  hashes are published.
- A manual checklist per release, short and written down: lock the workstation with
  derivation unlocked; sleep and wake; take a screenshot of the window; open clipboard
  history after a copy; install and uninstall as a standard user.

## Phases

All of them depend on ADR-0010. None is started before its G2.

| Phase | Delivers | Size | Depends on |
|---|---|:-:|---|
| **W0** | The platform seam of §1 extracted in the Linux application (pure refactor), `local_state_dir()` shared with the CLI, the "no `sys.platform` elsewhere" test | small | G2 |
| **W1** | `windows.py`: state directory and ACL, cloud-folder refusal, retrying atomic write, lock/suspend signals, clipboard formats, capture exclusion, crash-dump hardening. Runs from `pipx` on Windows | medium | W0 |
| **W2** | Frozen build in CI, the vector gate on the executable, per-user installer and uninstaller, Start-menu shortcut | medium | W1 |
| **W3** | Code signing, published hashes, release checklist, README section for Windows, high-contrast and Narrator pass | small, plus the wait for a certificate | W2 |

W1 is usable by the author through `pipx`. A public release is W3, not earlier.

## Consequences

- No new implementation to keep in agreement: Windows inherits every fix and every vector
  from the Linux application, and the cost of supporting it is one module and one build.
- The engine changes in two small, platform-guarded places (`local_state_dir`, the retry in
  `atomic_write`). Neither touches derivation; the vectors do not move.
- A code-signing certificate is a recurring cost and an identity to protect. Its private key
  must not live on a development machine; where it lives is an open question.
- The installer is tens of megabytes, because it carries Python and Qt.
- Windows gives the application two protections Linux under X11 does not (capture exclusion,
  clipboard-history exclusion) and takes away one (meaningful file modes, replaced by ACLs).
  The documentation says so instead of pretending the platforms are equal.

## Open questions

1. **Signing.** Which kind of certificate, issued to whom, and where the key is held (a
   hardware token, or a signing service in CI). This gates W3.
2. **Distribution channel.** Releases page only, or also `winget`? The Microsoft Store is a
   separate packaging format and review process; proposal: not in the first version.
3. **Freezing tool** (§3), decided by measurement in W1.
4. **ARM64**, when the wheels can be verified in CI.
5. **Portable build** (a folder that runs without installing, for a USB stick): convenient,
   but it invites running the application on machines the user does not control. Proposal: no.
