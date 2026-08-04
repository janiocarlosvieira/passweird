# ADR-0005 — Batch processing of keyring files

**Status:** Proposed
**Date:** 2026-08-03

## Context

Passweird knows how to **export** to seven keyring formats (`EXPORT_FORMATS`, storage.py:12),
but does not know how to **read** any of them. Anyone with a vault already populated with
old-pattern passwords has no migration path — they would have to reprocess entries one by one
by hand.

The concrete case that motivated this: a KeePassXC file with dozens of passwords in old
patterns, to be reprocessed into a new file under the current pattern, with the user consulted
password by password and the entry's URL used as a suggested context name.

Two constraints came along with it and shape the design:

1. **The master password and temporal secret must not go on the command line.** They land in
   shell history and are visible via `ps`. In batch mode this is worse than in single-shot use,
   because one command ends up exposing the secret that unlocks dozens of accounts.
2. **The change is confirmed individually.** Vault migration is effectively irreversible — the
   user needs to be able to skip entries and interrupt midway without losing what was already
   done.

## Decision

Add keyring reading as the inverse of the existing export operation, plus a per-entry
interactive pipeline.

- **`EXPORT_FORMATS` gains a `fields` map** linking canonical names (`name`, `url`, `username`,
  `password`) to each format's columns. A single structure describes both directions, instead of
  keeping a separate import table that could drift from the export one over time.
- **Autodetection by header.** The seven headers are textually distinct
  (`Title`/`Name`/`title`/`name`, `Username`/`User Name`/`Login`), so matching the read header
  against the known ones is unambiguous. `--vault-format` allows forcing it.
- **Secrets asked once, up front, via `getpass`.** Including the temporal secret, which in the
  single-shot flow is read with a visible `input()` — in batch mode it would stay on screen for
  much longer. If provided via `--master-pass`/`-T`, the existing warning
  (`storage.print_command_line_warning`) still fires, but execution proceeds: whoever chose to
  automate has already been warned.
- **Output file is always new.** `--vault-out` is mandatory and can never equal the input. Created
  with mode `0600`.
- **Every confirmation also logs** (`build_and_log_line`), so migrated entries become verifiable
  through the ADR-0007 feature.

## Consequences

**Positive.** A migration path now exists for anyone with an existing vault. The user keeps
per-entry control, able to skip whatever they do not want to touch. The output format can differ
from the input, so this also becomes a keyring-conversion tool.

**Cost.** Seven `fields` maps to keep in sync with `header`. Mitigated by a round-trip test per
format — writing and reading back must return the original.

**Accepted limitation: the generated file has passwords in plain text.** This is inherent to the
CSV format every one of these keyrings imports; there is no way to avoid it without breaking
interoperability. Mode `0600` and an explicit closing warning ("import it, then delete it") are
the available mitigation. This must not be treated as a detail: it is the single point of
greatest exposure in Passweird's whole flow.

**Accepted limitation: `firefox` has no title column.** The canonical name falls back to the URL,
which is faithful to the format but means a Firefox → Firefox round-trip loses the original title
if it came from another keyring.

## Rejected alternatives

- **Reading KeePassXC's `.kdbx` directly.** Would require `pykeepass` and implementing the
  vault's encryption, plus handling the user's actual file — much higher risk. The CSV export is
  the common denominator across all seven keyrings and keeps Passweird out of the original file.
- **Reusing `-f/--file`** (batch of contexts in text/CSV). It solves a different problem:
  generating passwords for a list of names. Here the input is a vault with its own structure, and
  the output is another vault. Overloading the same flag would confuse the two flows.
- **Non-interactive mode (process everything without asking).** Rejected for now: the
  URL-derived context suggestion gets it wrong in common cases (subdomains, multiple accounts on
  the same site), and a whole batch migrated under the wrong context is undetectable afterward —
  the passwords simply stop regenerating.
