# ADR-0010 — A Linux desktop application over the v3 core

**Status:** Accepted
**Date:** 2026-11-16
**Builds on:** [ADR-0009](0009-v3-key-stretching-and-derivation.md). Nothing in ADR-0009 changes.
**Touches:** [ADR-0008](0008-kotlin-multiplatform-port.md) (the Compose desktop target, see §2).

## Context

v3 is complete as a command line: derivation, the tiered journal, synchronisation, recovery and
KDBX export. It is correct and it is tiring to use. The friction is specific:

1. **Three secrets, typed blind, in a fixed order.** A typo in the master or the boost is only
   visible as a fingerprint the user has to remember to look at.
2. **The journal is invisible.** Knowing which sites exist, which counter is current, where a
   TOTP lives or which entries are in conflict means running `--list`, `--show` and `--history`
   one at a time.
3. **Rotation is a blind jump.** `--bump` produces the new password, but the old one is needed
   on the site's "current password" field in the same minute, and nothing ties the journal
   update to the change having actually worked on the site.
4. **Onboarding is unforgiving.** `--init` prints the recovery text once, in a terminal that
   keeps scrollback, and nothing checks that the boost and the recovery text were written down.
5. **Sync trouble is silent until it blocks.** Rollback, a cloned install and
   `*.sync-conflict-*` files surface as a refusal to write, with no place to see the state of
   each device's stream.
6. **Passwords travel through the terminal.** They are printed, selected with the mouse and
   stay in scrollback and in the X11 primary selection.

The daily path remains KeePassXC (ADR-0009 §6): Passweird derives, KeePassXC fills the browser.
The desktop application is for the moments Passweird itself is needed: first setup, adding a
site, rotating a password, consulting the registry, resolving a conflict, recovering.

## Goals and non-goals

**Goals.** Make those moments short and hard to get wrong; make the journal browsable with the
access password alone; keep generated passwords out of terminals; make the state of
synchronisation visible.

**Non-goals.**

- No browser extension and no autofill. KeePassXC-Browser is audited and already in use;
  origin matching, iframes and the native-messaging channel are where such projects fail.
- No new cryptography, no new file format, no change to any vector. The application is a
  second front end to the same engine, next to the CLI.
- No Android work here. The phone stays derivation-only (ADR-0009, Consequences).
- No daemon, no network listener, no cloud. Synchronisation stays a folder that Syncthing
  replicates.
- No storage of generated passwords, of `PRK`, or of the fingerprint (§5).

## Decision

### 1. Toolkit: Python with Qt 6 (PySide6), in the same process as the core

The application is written in Python and imports `passweird.v3` directly.

| Option | Verdict |
|---|---|
| **PySide6 (Qt 6)** | **Chosen.** Installs from PyPI into the same `pipx` environment as the CLI; mature widgets for exactly this shape of application (filterable list, detail pane, wizard); LGPL, compatible with GPLv3; same toolkit as KeePassXC, so the two look alike side by side |
| GTK 4 + libadwaita (PyGObject) | Sound, and lighter. Considered and rejected by the author (2026-11-16) because PyGObject depends on system packages and typelibs, which breaks the one-command `pipx` install, and because libadwaita ignores the desktop theme under Cinnamon |
| Compose Multiplatform desktop (the existing `kotlin/composeApp`) | Rejected **for the desktop**. It would need the whole of ADR-0009 ported first (Argon2id, canonicalisation, journal, merge, recovery, KDBX) and would make the security of the desktop depend on a second implementation before delivering any usability. Python is normative; the desktop should run the normative code |
| Web UI in a local server, Tauri or Electron | Rejected. A browser engine holding the master password, a loopback port to protect, and a JavaScript supply chain, for no gain over native widgets |
| Terminal UI (Textual) | Rejected as the answer, kept as a fallback idea. It fixes browsing but not the clipboard, the QR code or the onboarding |

Only `PySide6-Essentials` is required (QtCore, QtGui, QtWidgets, QtDBus, QtSvg). It is an
optional extra, so the CLI keeps its small footprint:

```
pipx install "passweird[gui]"      # adds PySide6-Essentials, pykeepass, qrcode
passweird-gui                      # entry point: passweird.gui.main:main
```

### 2. Consequence for ADR-0008

The Kotlin port keeps its purpose, **the phone**, and its v3 scope stays what ADR-0009 fixed:
derivation only, driven by the vectors. The Compose **desktop** target is not developed further
and is dropped once this application reaches phase G2; on Linux there is one desktop
application, and it runs the normative code.

### 3. Architecture: one service layer, two front ends

`v3/app.py` today mixes three things: the operations, the prompts (`Prompter`, `getpass`) and
the printing (`say`). The application needs the first without the other two.

```
passweird/v3/canon.py derive.py keys.py journal.py kdbx.py      engine (unchanged)
passweird/v3/service.py                                         NEW: operations as plain calls
passweird/v3/app.py  + passweird/main.py                        CLI: argument parsing, prompts, text
passweird/gui/                                                  desktop: widgets, state, threads
```

`service.py` exposes the operations as functions that take values and return values or raise
typed errors: `open_journal(access_password)`, `unlock(master, boost, keyfile)`,
`preview(entry, counter)`, `record(entry, counter)`, `add_site(...)`, `edit(...)`,
`resolve(...)`, `export_kdbx(...)`, `recovery_text()`, `sync_status()`, and so on. It never
prompts and never prints. The CLI is rewritten on top of it with **no change of behaviour**:
the existing suite is the proof.

Three rules, each enforced by a test:

1. **The GUI package contains no cryptography and no canonicalisation.** A test fails if any
   module under `passweird/gui/` imports `hashlib`, `hmac`, `secrets`, `argon2`,
   `cryptography`, `unicodedata`, or anything from `passweird.v3` other than `service`.
2. **Everything the GUI shows about an input comes from the engine.** The canonical site shown
   while the user types is `service.canonical_site(text)`, not a re-implementation.
3. **One process writes.** The application takes a lock file in `~/.passweird/v3/` and refuses
   to start twice; the CLI takes the same lock for the duration of a write. A device has one
   stream and one writer (ADR-0009 §7).

Argon2id (0.2–0.4 s, twice when the journal is also opened) runs in a worker thread; the
window never freezes and shows a determinate "stretching" state.

### 4. The three tiers become three visible states

The tiers of ADR-0009 §6 map to states the window always shows, with a different colour and
label in the header bar:

| State | Entered with | What is possible | Leaves automatically |
|---|---|---|---|
| **Locked** | – | nothing; the window shows only the unlock field | – |
| **Registry open** | access password | browse, search, edit notes, see history, sync status, resolve conflicts that need no derivation | after 15 min idle; on screen lock; on suspend |
| **Derivation unlocked** | master + boost (+ keyfile) | copy or reveal passwords, rotate, add a site, export, reissue recovery | after **2 min** idle; when the window loses focus for 60 s; on screen lock; on suspend; on leaving "Registry open" |

Leaving "Derivation unlocked" wipes `K0` and every `PRK` (the `Session` buffers of
`derive.py`) and clears the clipboard if it still holds a password the application put there.
Screen lock and suspend are observed over D-Bus (`org.freedesktop.login1` `PrepareForSleep`
and the session's `Lock` signal, with the desktop's screensaver interface as a fallback);
if neither is available the idle timers still apply. Timeouts are configurable downwards
freely and upwards to a fixed ceiling (10 min for derivation).

The master and the boost are asked for **only** when an action needs them, in a single dialog
that names the action ("Unlock derivation to rotate github.com"), never at start-up.

### 5. Fingerprint: shown, taught, never stored

The fingerprint is displayed large in the unlock dialog the moment stretching finishes and
stays in the header for as long as derivation is unlocked. Copy and reveal are disabled for
the first second after it appears, so that it is seen at least once per unlock.

The application does **not** remember the fingerprint to "check it for the user". A stored
fingerprint is 24 bits of verifier for `master + boost`, which is the artefact ADR-0009
removed on purpose. The onboarding (§6.1) teaches it instead: the user types it back once.

### 6. Screens

**6.1 First run (wizard).** Create a registry, or join one already in the synced folder.

1. User id, with the warning that it is a salt and must never change.
2. Boost: "Draw 5 words" with a re-roll button and the bit count; or "I have my own". The
   words are then hidden and typed back in full. Accent, case and spacing tolerance is shown
   live through the engine's canonical form.
3. Master password, twice; refused if equal to the boost.
4. Access password, twice; refused if equal to master or boost, with the note that it must
   not be a variation of the master.
5. Fingerprint, shown, then typed back.
6. Recovery text: Base32 groups and QR code, in a window that is not part of the main one,
   with **Print…** (straight to the print dialog, no temporary file). To continue, the user
   types back three groups chosen at random. Nothing is written to disk unless the explicit
   "keep a recovery file on this machine" box is ticked, with ADR-0009's warning beside it.
7. Journal folder, with a check that it is not inside `~/.passweird` and a reminder that this
   folder, and only this one, goes into Syncthing.

"Join" is steps 7, then the access password, then a new device id. It refuses a folder with
no `keys.pw3`, and explains `--new-device-id` when a clone is detected.

**6.2 Main window.** A search field on top, a list on the left, a detail pane on the right.

- *List:* site, login, and small markers: conflict, deleted, "has notes", "second factor
  recorded", "hardware key recorded". Typing anywhere filters; `Ctrl+K` focuses the search.
- *Detail:* canonical site, login, counter, length and classes in words ("18 characters,
  no specials"), notes, where the second factor lives, hardware keys, and the history of the
  entry (which device, when, what changed). Notes, second factor and keys are editable with
  the access password alone.
- *Actions:* **Copy password** (`Enter`), **Reveal** (hold to show, monospace, with a
  per-character-class tint so `l`/`1`/`I` and `O`/`0` are distinguishable), **Rotate…**,
  **Show TOTP secret…**, **Delete…**. The first use of any of them in a session opens the
  unlock dialog.

**6.3 Add a site.** One field that accepts a pasted URL. Under it, live: the canonical site
the engine will use, and why ("`accounts.google.com` is not the same site as `google.com`").
A rejected input shows the engine's reason. Then login (optional), and the site's rules as
plain controls: length, character classes, with presets ("digits only", "no specials",
"maximum 12"). The first password is shown with the same two-step confirmation as a rotation.

**6.4 Rotate (the guided change).** This is the flow the CLI cannot give:

1. The dialog shows **current** (counter *n*) and **new** (counter *n+1*), each with its own
   copy button, and the site opened in the browser on request.
2. The new password is derived with `service.preview`, which **writes nothing**.
3. The user changes the password on the site, then presses "It worked — record it". Only then
   does the journal get its `put` with counter *n+1*.
4. "It did not work" discards the preview; "The site rejected the format" goes back to the
   rules of §6.3 and derives again at *n+1* with the new length or classes.

If the engine currently records at derivation time, the split into `preview` and `record` is
part of phase G0. The journal must never run ahead of the site.

**6.5 Conflicts.** An entry in conflict shows its candidates side by side: counter, length,
classes, device, date, and, with derivation unlocked, a copy button for each, so the user can
find out which one the site actually accepts. "This one is right" writes the resolving record.

**6.6 Synchronisation.** A panel listing each device stream: a name the user can assign to a
device id (stored in the registry's free-form `x` map, so that it syncs), number of records,
date of the last one, and whether this device has seen all of it. Rollback, clone and
`*.sync-conflict-*` files are explained in words, each with the single action that fixes it.
The application watches the journal folder and refreshes when Syncthing delivers a change.

**6.7 Export to KeePass.** Choose entries (all, changed since the last export, or a
selection), choose a new file, type its password. The KDF is the one ADR-0009 §6 fixes. The
last step offers two ways to finish, and then to delete the export:

- **Manual (default):** the instructions for KeePassXC, *Database → Merge From Database…*.
- **Merge into my KeePass database… (optional):** the application runs KeePassXC's own
  `keepassxc-cli merge` of the export into a database the user picks. It does not open or
  write the main database itself: the merge logic is KeePassXC's, not a second one written
  here. Conditions, all enforced:
  - offered only when `keepassxc-cli` is found; otherwise the button explains what is missing;
  - the main database's password is asked in its own dialog, handed to the child process on
    its standard input, never on the command line, never stored, and cleared when the process
    ends. A key file or a hardware key configured on that database is passed through with the
    corresponding `keepassxc-cli` options; if the combination is not supported, the screen
    falls back to the manual path instead of improvising;
  - a timestamped copy of the main database is made beside it before the merge and its path
    is shown; the copy is the user's to delete;
  - the result is checked by listing the "Passweird" group of the merged database and
    comparing entry titles with what was exported; a mismatch is reported, not repaired;
  - the path of the main database may be remembered in the configuration; nothing else is.

  The exact `keepassxc-cli merge` options (credentials for each side, key file, hardware key)
  are to be confirmed against the installed version in phase G4, with a test that runs a real
  merge on throwaway databases.

**6.8 Maintenance.** Change the access password (with the "this does not revoke the old one"
notice of ADR-0009), reissue the recovery text, recover with the recovery text, create a
keyfile, import a list of sites. `--mass-rekey` and `--migrate-v2` stay CLI-only at first:
they are rare, long, and better run where their full output can be read.

### 7. Handling of secrets in the application

- **Clipboard.** Copy puts the password on the clipboard only (never the X11 primary
  selection), marked with `x-kde-passwordManagerHint=secret` so that clipboard managers that
  honour it keep no history. It is cleared after **60 s**, or on lock, **only if the clipboard
  still holds that value**. A countdown is visible.
- **Entry fields.** Password echo mode, input methods and predictive text disabled, no undo
  history, contents cleared as soon as they are handed to the engine. A "show" toggle exists
  for the boost only, because five words are hard to type blind.
- **Nothing sensitive leaves the process by accident.** No logging of values; the exception
  hook prints the error type and location, never local variables; core dumps are disabled at
  start (`RLIMIT_CORE = 0`, `PR_SET_DUMPABLE = 0`); nothing is written under `/tmp`; printing
  the recovery text goes through the print dialog, not through a file.
- **What this does not solve, stated plainly.** Python cannot erase an immutable `str`, so a
  typed secret may survive in process memory until reuse (ADR-0009, Consequences). Under X11,
  any program in the session can read the clipboard, capture the screen and log keystrokes;
  the application cannot prevent that, and says so once, in *About → Security*. A compromised
  machine remains out of scope, exactly as for the CLI.

### 8. Language, look, accessibility

Portuguese (Brazil) and English from the start, through Qt's translation files; the engine's
error messages are mapped by error type, not by matching text. System theme, light and dark.
Every action reachable from the keyboard; all controls labelled for screen readers; no
information carried by colour alone (the three states of §4 also differ in icon and text).

### 9. Packaging

`pipx install "passweird[gui]"` is the supported installation. `passweird-gui
--install-desktop-entry` writes a `.desktop` file and an icon under `~/.local/share`, so the
application appears in the menu; `--remove-desktop-entry` undoes it. Flatpak or AppImage are
left for when someone other than the author needs them: the sandbox would have to reach the
journal folder and D-Bus, and that deserves its own decision.

### 10. Tests

- The service layer is tested without Qt; the CLI suite must stay green through the refactor.
- GUI tests run headless (`pytest-qt`, `QT_QPA_PLATFORM=offscreen`): state transitions and
  timeouts with a fake clock, the clipboard clear rule, the wizard's "typed back" gates, the
  rotate flow writing nothing before confirmation.
- The three architecture rules of §3 are tests.
- No new golden vectors: the application derives nothing on its own. One end-to-end test
  drives the GUI to produce the password of an existing vector, as a wiring check.

## Phases

Each phase ends in something usable; none depends on the next.

| Phase | Delivers | Size |
|---|---|---|
| **G0** | `service.py` extracted, CLI on top of it, `preview`/`record` split, shared lock file. No behaviour change | medium |
| **G1** | Read-only registry browser with the access password: list, search, detail, history, sync panel, auto-lock | medium |
| **G2** | Derivation: unlock dialog with fingerprint, copy and reveal, clipboard rules, add site, guided rotation, edit notes/second factor/keys | medium |
| **G3** | First-run wizard (create and join), recovery text with print and QR, recover, change access password | medium |
| **G4** | Conflicts view, KDBX export with the optional `keepassxc-cli` merge, list import, keyfile | medium |
| **G5** | Translations, desktop entry, accessibility pass, documentation and screenshots in the README | small |

G0 and the rule tests of §3 deserve the strongest review: after them the application is
ordinary interface work that cannot change what a password is.

## Consequences

- A new optional dependency, PySide6-Essentials (tens of megabytes), isolated in the `gui`
  extra. The CLI and the engine do not import it.
- The CLI is refactored once, onto `service.py`. That is a risk taken on purpose: two front
  ends over two copies of the logic would diverge.
- The desktop Compose target of ADR-0008 ends; the Kotlin port narrows to the phone.
- The window makes the registry easy to read, which also makes shoulder-surfing and an
  unattended unlocked screen more costly than with a terminal. The auto-lock defaults of §4
  are the answer, and they are strict by design.
- Nothing new is stored: no cache, no recent list, no window state that names a site.

## Decided with the author (2026-11-16)

- **Toolkit:** Qt 6 through PySide6 (§1).
- **Merge into the main KeePass database:** offered as an option beside the manual path,
  delegated to `keepassxc-cli` (§6.7).
- **Timeouts:** derivation 2 min, registry 15 min, clipboard **60 s** (§4, §7).
- **Tray icon:** none. A background process with a quick "copy the password of …" keeps
  derivation unlocked for longer than the task needs.

## Open questions

1. **Ceilings** for the configurable timeouts (10 min proposed for derivation; clipboard and
   registry not yet fixed).
2. **Device names** in the registry's `x` map: acceptable use of the free-form field, or a
   field of its own in a later record version?
3. **Name and icon** of the application as it appears in the menu.
