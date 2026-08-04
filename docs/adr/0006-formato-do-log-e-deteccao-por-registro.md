# ADR-0006 — Log format and per-record detection

**Status:** Accepted (implemented)
**Date:** 2026-08-03

## Context

The local log (`~/.passweird/passweird.log`) is written in two formats, chosen per run:

- **encrypted** (default): AES-256-GCM blocks, each preceded by a 4-byte big-endian length
  prefix;
- **plaintext** (`--plain-log`): one line per record, always starting with a 14-digit
  `date_str`.

Since the choice is made **per run** and the file is **append-only**, a single file can hold
both formats interleaved in any order. Just using `--plain-log` once and then going back to the
default is enough — this is not an exotic case.

`storage.read_logs_from_file` (storage.py:725) picked the format by inspecting **the first 14
bytes of the file** and then treated the whole file as being of that type. The function's
docstring correctly argued why the discriminator itself is sound (a length prefix is never made
of ASCII digits) — but applied that discriminator only once.

Behavior verified on a mixed log:

| Write order | Symptom |
|---|---|
| plaintext, then encrypted | `UnicodeDecodeError` propagates to the top; the whole log becomes unreadable |
| encrypted, then plaintext | **silent loss**: two records written, one returned |

The second is the more serious one: no error at all, records just disappear. This affects
`--view-log`, `--audit` and anything else built on the log, since they all go through this
function.

## Decision

Decide the format **per record**, not per file. The read loop now looks, at every position:

- next 14 bytes are ASCII digits → plaintext record, consume up to `\n`;
- otherwise → encrypted block, consume a 4-byte prefix + payload.

The discriminator remains exactly the one already documented, and it remains correct
record-by-record: an encrypted block's length prefix starts with `\x00\x00\x00` for any
realistic payload size, and a null byte is not an ASCII digit. What changed is where it is
applied, not what it is.

Additionally, a file truncated mid-block (power loss during a write) must return every intact
record read up to that point, without raising.

## Consequences

- `--view-log`, `--audit` and the ADR-0007 verification now see the whole log regardless of
  format mixing.
- No change to the write format: existing logs remain readable, and the fix is purely on the
  read side.
- The loop got a bit longer, but the implicit file-wide decision that caused the bug is gone.

## Note on the format itself

The "append-only with two interleavable encodings and heuristic discrimination" format is
inherently fragile — it works here because the discriminator happens to be well chosen, not
because the design is robust. A versioned file header, or a per-record type byte, would be more
defensible. Not done now because it would require migrating existing logs for little gain: with
per-record detection, the case that used to break now works. Recorded here as the preferable
design if the log format is ever revisited for another reason.
