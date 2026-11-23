# ADR-0011 — The Android application for v3 (Kotlin)

**Status:** Accepted
**Date:** 2026-11-16
**Builds on:** [ADR-0009](0009-v3-key-stretching-and-derivation.md) (the algorithm and the
journal) and [ADR-0010](0010-linux-desktop-application.md) (the interaction model).
**Supersedes:** the scope of [ADR-0008](0008-kotlin-multiplatform-port.md).
Its method stays: Python is normative and the vectors are the contract.

## Context

ADR-0010 settled the desktop: one Linux application, in Python, running the normative code.
It also narrowed Kotlin to the phone. This ADR is the counterpart of ADR-0010 for that phone:
the same interaction model, carried to Android, on top of a Kotlin implementation of v3.

**Is it Android only?** The *application* is. The *core* is not quite:

| Piece | Targets | Why |
|---|---|---|
| `passweird-core` | Android **and JVM** | The JVM target is how the vector suite runs in CI and on a developer machine, without an emulator. It ships in no desktop product |
| `composeApp` | **Android only** | The `desktop` target and `desktopMain` are removed (ADR-0010 §2) |
| iOS | not planned | The core stays in `commonMain` so that it remains possible; nothing is built or tested for it |

What exists today in `kotlin/` implements **v2**: `Derivation.kt` (2× SHA-256, HKDF, biased
sampling), TOTP, Base32, a Compose screen for passwords and TOTP, and a v1 vector test. It
already has `FLAG_SECURE` and `allowBackup="false"`. None of the v2 derivation survives; the
project structure, the build and the vector harness do.

The difference from the desktop that shapes everything below: on the phone the engine is a
**second implementation**. ADR-0010 could forbid cryptography in the GUI and inherit
correctness from Python. Here correctness has to be earned again, vector by vector, and the
order of the work follows from that.

## Goals and non-goals

**Goals.** Derive any v3 password on the phone, identical to the desktop; later, consult the
registry there with the access password; keep the three-tier model and the fingerprint
discipline of ADR-0010; never hold on the phone anything that can derive.

**Non-goals.**

- **No Android Autofill service and no keyboard (IME).** Filling apps and browsers is the job
  of the KeePass client already on the phone, fed by the KDBX that the desktop exports.
- **No KDBX export, no `--mass-rekey`, no migration, no SSH/TLS/RSA/OpenPGP material** on the
  phone. Those are desktop operations. TOTP secrets are in scope (they already are in v2).
- **No biometric shortcut that stores a key.** See §5.
- **No v2 compatibility.** Nothing was ever in production.

## Decision

### 1. Two modules, one rule

```
kotlin/passweird-core   commonMain: canon, encoding, HKDF, sampling, fingerprint, TOTP,
                                    journal parsing, merge          (pure, no platform types)
                        androidMain / jvmMain: SHA-2, HMAC, AES-GCM, Argon2id, NFC/NFD
kotlin/composeApp       Android only: Compose UI, state, lifecycle, clipboard, storage access
```

The rule of ADR-0010 §3 applies with the same force: **`composeApp` contains no cryptography
and no canonicalisation.** It calls a small façade in the core (`Engine`), the Kotlin
equivalent of `service.py`, with the same operation names. A test fails the build if
`composeApp` imports `javax.crypto`, `java.security`, `java.text.Normalizer` or anything from
the core other than the façade.

### 2. Argon2id on Android

The parameters are frozen (`t=3, m=262144 KiB, p=4`, 64-byte tag) and were measured on the
target phone with the reference C code: 0.93 s (ADR-0009 §9).

- **Android:** the reference `libargon2`, compiled with the NDK and called through JNI. The
  256 MiB live in native memory, outside the Java heap.
- **JVM (tests only):** Bouncy Castle's Argon2, which is acceptable where the heap is large.
- **Excluded:** `libsodium`'s `crypto_pwhash`, which offers no parallelism parameter and
  therefore cannot compute `p=4`; and any pure-JVM Argon2 on the phone (heap limit,
  ADR-0009 §9).

A maintained wrapper around the reference code may replace the project's own JNI glue if it
exposes parallelism and raw output; that choice is made in phase A0 and recorded in the code.
Either way the three full-cost vectors of `derivation.json` must pass **on a device or
emulator**, not only on the JVM, because the JVM run exercises a different Argon2.

Stretching runs off the main thread, in a foreground-visible state with a determinate
indicator. If the allocation fails, the application says so and derives nothing: there is no
fallback to smaller parameters, which would be a different `ALG` and different passwords.

### 3. Unicode is the second place a port diverges

`canon` depends on NFC, NFD and NFKC. Python and Android carry different Unicode versions.
ADR-0009 already limits the exposure (only ASCII is case-mapped; the white-space set and the
removed block are explicit lists), but normalisation itself is delegated to the platform.

- The core uses `java.text.Normalizer` on both targets and passes every case of
  `canonical.json`, accept and reject.
- In addition, a generated test compares Python and Kotlin over every code point in the
  Latin, Greek and Cyrillic blocks and over the combining marks, for all three forms. Any
  difference found is fixed by **rejecting** the input on both sides, never by special-casing
  one of them: ADR-0009's principle that no conversion is safer than a divergent one.
- Text arriving from the keyboard is normalised by the engine, never by the UI.

### 4. The three tiers on a phone

Same states as ADR-0010 §4, with phone-sized timeouts:

| State | Entered with | Leaves automatically |
|---|---|---|
| **Locked** | – | – |
| **Registry open** (from phase A2) | access password | 5 min idle; screen off; app in background for 60 s |
| **Derivation unlocked** | master + boost | **1 min** idle; screen off; app in background for 30 s; process death |

Leaving "Derivation unlocked" zeroes `K0` and every `PRK` (held in `ByteArray`, never in
`String`) and clears the clipboard if it still holds a password the application put there.

Until phase A2 the application has no registry: it is **stateless**, as `--no-journal` is.
The user id is the only thing it remembers. Site, login, counter, length and classes are
entered each time, with the engine's canonical site shown live.

### 5. Secrets on Android

- **Nothing that can derive is stored.** No `PRK`, no `K0`, no master, no boost, and no
  fingerprint (24 bits of verifier, ADR-0010 §5). This excludes the usual "unlock with
  fingerprint" feature: a Keystore-wrapped `PRK` is derivation material at rest, protected by
  the phone's lock screen instead of by 65 bits of boost. If typing two secrets on glass
  proves unbearable in use, that is a new decision with its own ADR, not a setting.
- **Entry fields:** password input type, no suggestions, the "no personalised learning" IME
  flag, excluded from Autofill and from accessibility text where the platform allows. A "show"
  toggle for the boost only. The third-party keyboard still sees every keystroke; the
  application says so once and recommends a keyboard without network permission.
- **Screen:** `FLAG_SECURE` on every window (already present), which also blanks the recents
  thumbnail. The fingerprint is shown the moment stretching ends; copy and reveal are disabled
  for the first second.
- **Clipboard:** the clip is marked sensitive (always available at the minimum version, API 33), cleared after
  **60 s** or on lock, and only if it still holds that value. "Reveal" exists so that a password can be read
  and typed without touching the clipboard at all.
- **Process:** no logging of values; no crash reporter; `allowBackup="false"` and data
  extraction rules that exclude everything; no `INTERNET` permission in the manifest, so the
  application cannot make a network connection even by mistake.

### 6. The registry on the phone (phases A2 and A3)

ADR-0009 left this out of v3.0 and noted the format allows it. The plan:

- **A2, read-only, opt-in.** Disabled until the user enables it in the settings. The user then points the application, once, at the synced journal folder
  through the system folder picker (Storage Access Framework); the folder is replicated by a
  Syncthing client on the phone. With the access password the application reads `keys.pw3`
  and every stream, folds them with the same merge as Python (all scenarios of `journal.json`
  must pass), and shows the list, the detail, the history and the conflicts. Selecting an
  entry pre-fills derivation with its counter, length and classes. The phone **writes
  nothing**: it has no device id and no stream.
- **A3, writing, deferred.** A phone that records rotations needs its own device id, its own
  stream, atomic writes through a document provider that may not offer rename-over, and the
  rollback and clone detection of ADR-0009 §7. Until that is designed, rotation is done on a
  desktop, and the phone shows the result after the next sync.

A read-only phone has one honest limitation: a rotation done on the desktop is invisible on
the phone until Syncthing has run there. The registry screen shows the date of the newest
record it has seen.

### 7. Screens

- **Derive** (A1): site (paste a URL, canonical form shown), login, counter, length, classes
  with presets; then the unlock sheet (master, boost), the fingerprint, and **Copy** /
  **Reveal** / **TOTP secret**.
- **First run** (A1): user id, with the warning that it is a salt; then the fingerprint
  lesson: derive once, compare the four syllables with the desktop's. There is no "create"
  on the phone: secrets and the recovery text are created on a desktop (ADR-0010 §6.1).
- **Registry** (A2): search, list with the same markers as the desktop, detail, history,
  conflict candidates side by side.
- **About → Security**: what the application stores (the user id, the folder permission),
  what it cannot protect against (keyboard, a compromised phone), and the build's `ALG`.

### 8. Tests and the definition of "done"

- `passweird-core` runs **all three** v3 vector files on the JVM: `canonical.json`,
  `derivation.json`, and from A2 `journal.json` (keys, stream decryption, merge, integrity).
  The v1 vectors and the v2 code are deleted in the same change that lands v3 derivation.
- An instrumented test runs the three full-cost Argon2id cases on a device or emulator.
- `byte_rejections`, `candidate_rejections` and `stream_bytes_used` are asserted, not only
  the password (ADR-0009, vector README).
- The rule test of §1, and UI tests for the timeouts, the clipboard rule and the one-second
  fingerprint delay.
- **A release is allowed only when every vector passes on the device and a password derived
  on the phone has been compared by hand with the desktop for at least one real entry.**

## Phases

| Phase | Delivers | Size | Review |
|---|---|:-:|---|
| **A0** | v3 core in Kotlin: canon, encoding, Argon2id (JNI), extract, expand, sampling, fingerprint, TOTP; `canonical.json` and `derivation.json` green on JVM and device; v2 code and the desktop target removed | large | strongest: this is the part that decides what a password is |
| **A1** | Stateless application: derive, unlock sheet, fingerprint, copy/reveal, clipboard and lifecycle rules, first run | medium | normal |
| **A2** | Opt-in, read-only registry over the synced folder: keys, streams, merge, list, detail, conflicts; `journal.json` green | medium | strong for the core part (merge, AES-GCM framing), normal for the UI |
| **A3** | Writing from the phone: own stream, atomic writes, integrity | large | needs its own design note first |
| **A4** | Portuguese and English, accessibility pass, signed release build, README | small | normal |

A0 does not depend on ADR-0010's G0 and can run in parallel with the desktop work. A1 is
usable on its own: it is today's application, with the right algorithm.

## Consequences

- Two implementations of v3 now exist and must agree forever. The vectors are what makes
  that tolerable; any new behaviour lands in Python and in the vectors first, then in Kotlin.
- The build gains the NDK and a native library per ABI (`arm64-v8a` at least; `x86_64` for
  the emulator).
- The Compose desktop application disappears. Nothing replaces it but ADR-0010.
- The phone is the device most likely to be lost or stolen. With this design a stolen,
  unlocked phone yields the user id and, from A2, a copy of the encrypted registry: metadata
  behind the access password, and no password.
- Typing the master and a five-word boost on a phone keyboard is slow. That cost is accepted
  in exchange for §5; the accent, case and spacing tolerance of the boost exists for this.

## Decided with the author (2026-11-16)

- **The registry on the phone is off by default and opt-in (A2).** Out of the box the
  application is the stateless one of A1 and holds no list of sites. *Settings → Registry on
  this phone* turns it on, after a screen that states what changes: an encrypted copy of the
  metadata will live on the device most exposed to theft, behind the access password, and
  still nothing that derives. Turning it off again releases the folder permission and
  forgets the folder; it cannot delete the synced copy, and says so.
- **Writing from the phone (A3) stays deferred**, and if it is ever built it follows the same
  pattern: off by default, enabled explicitly. Rotation is done on a desktop. A3 is not
  started without a design note of its own, and nothing in A0-A2 may assume it will exist.
- **Minimum Android version: API 33** (Android 13). A security tool has no business running
  on a system old enough to lack the platform's own protections: API 33 is where a clip
  can be marked sensitive and where the system itself expires clipboard content. `minSdk`
  goes from 26 to 33 in both modules in phase A0. Policy from here on: the minimum is raised,
  never lowered, as versions fall out of security support; each raise is a line in the
  changelog, not a new ADR.

## Open questions

Both are settled by trying, inside the phase that needs them, and recorded in the code:

1. **Which Syncthing client** on Android, and whether its folder is reachable through the
   folder picker on the target phone. To be tried before A2 is started.
2. **JNI glue of our own, or an existing wrapper** around the reference Argon2 (§2), in A0.
