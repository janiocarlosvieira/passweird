# ADR-0007 — Password verification against the log

**Status:** Proposed
**Date:** 2026-08-03

## Context

In a stateless generator, the most frequent practical question is not "what is my password?" —
it is **"is the password I would generate right now still the one on the account?"**. It drifts
whenever any factor changes without the user noticing: a different length flag, a temporal
secret typed with a variation, a changed master password.

`--audit` (main.py:459) comes close but answers something else: it checks whether a **record
exists** for a context/temporal pair, via `storage.find_in_log`. It does not regenerate the
password, does not compare anything, and returns every occurrence without distinguishing which
is the most recent.

The log already keeps what is missing: every line carries `pwd:<summary>`, where the summary is
`crypto.summarize_password_hash` — the first 10 and last 10 hex characters of `sha256(password)`.

## Decision

A new verification (`--verify`) that:

1. asks for the context and temporal secret via `getpass` (hidden, like `--audit`'s interactive
   mode, to leave no trace in shell history);
2. scans the log **bottom-up** and stops at the first record for that context — the most recent
   documented change, chronologically;
3. regenerates the password using `len` and `feat` **read from that record itself**, not the
   command-line flags;
4. compares the summary against the record's `pwd:` field.

Point 3 is the least obvious and most important decision: regenerating with the current defaults
would make verification fail every time the user's pattern had changed since generation — which
is exactly the situation where a reliable answer matters most. Verifying means reproducing the
recorded conditions, not the current ones.

## Consequences

### What the truncated summary allows us to claim

That is 20 of the 64 hex characters of a SHA-256, i.e. **80 bits**. The chance of two distinct
passwords colliding on those 80 bits is 2⁻⁸⁰. A match is conclusive for any practical purpose.

### The three outcomes need to stay distinct

| Outcome | Meaning |
|---|---|
| No record | Never generated, **or** generated with `-w/--write` (logging off) |
| Record, matches | The current password reproduces the last documented change |
| Record, diverges | Some factor changed: master password, temporal secret, or context |

Collapsing the first case into the others would be a serious usability error: "no record found"
and "password does not match" call for opposite actions, and conflating them could make a user
change an account's password unnecessarily.

### Inherited limit

Verification only sees what was logged. Anyone who systematically uses `-w` has nothing to
verify — and that needs to be stated in the output, not inferred by the user.

### Dependency

Depends on the [ADR-0006](0006-formato-do-log-e-deteccao-por-registro.md) fix: over a
mixed-format log, the previous reader silently lost records, and a verification reading an
incomplete log would answer "no record" for passwords that do exist — exactly the outcome that
must not be confused.

## The log as an oracle

Recording `pwd:<80 bits of sha256(password)>` is what makes verification possible, and it is
also an offline verification oracle for the generated password — a single SHA-256 per attempt,
with no salt.

The risk is contained, not eliminated: the log is encrypted at rest with AES-256-GCM under a key
derived from the master password itself, so whoever does not have it cannot read the summaries.
But `--plain-log` writes everything in the clear, and then the password, master and temporal
summaries become readable to anyone with read access to the disk.

This is not introduced by this ADR — the log format is already like this. It is recorded here
because this feature is what gives the field its usefulness, and therefore what fixes the field
in the format. See [ADR-0003](0003-chave-publica-publicada-como-oraculo-offline.md) for the same
risk pattern in asymmetric material, and for why the current KDF does not sustain either one well.
