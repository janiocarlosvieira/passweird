# Golden derivation vectors

`derivation-v1.json` is the contract every Passweird implementation must satisfy — the Python one
included. See [ADR-0008](../../docs/adr/0008-kotlin-multiplatform-port.md) for why it exists.

Passweird's outputs are pure functions of the user's inputs, so a second implementation is only
useful if it reproduces the first **bit for bit, permanently**. A password that is "almost right"
is just a wrong password, discovered when someone is locked out of an account. This file turns
"we hope they agree" into "CI fails if they don't".

## Regenerating

```bash
python tools/generate_vectors.py            # rewrite the file
python tools/generate_vectors.py --check    # fail if it is stale (used in CI)
```

**Python is normative.** Every derivation change lands there first, regenerates this file, and
only then is a port expected to follow.

## Reading a failure

A failure in `tests/test_vectors.py` is never "fix the test". It means a derivation changed. The
only two valid responses:

1. **Unintentional** — revert the change. Every already-deployed password derived from the old
   behaviour would otherwise stop reproducing.
2. **Intentional** — regenerate, and treat the diff as the compatibility break it is. ADR-0004 is
   the precedent: it altered every HKDF `info` string, and that was a deliberate, documented
   decision.

Each case carries its **intermediate** values (`master_hash`, `app_hash`, `raw_hkdf_hex`,
`compliance_nonce`), so a failing port localizes to a stage instead of only learning that the
final password differs.

## Structure

| Group | What it pins |
|---|---|
| `modified_hash` | The entry point of every derivation, including UTF-8 multi-byte input |
| `blend_secondary_factor` | Keyfile / FIDO2 blending |
| `hkdf_expand` | Lengths of 1, 64, 65 and 200 bytes — the block-boundary counter loop |
| `password` | 16 cases: lengths, every character-class toggle, temporal salt, Unicode, compliance loop |
| `totp` | Base32 secrets, unpadded |
| `summaries` | Truncated log fingerprints used by `--audit` |

## What a port must get right

These are the failure modes the vectors were built to catch. They are not hypothetical — each was
measured against this implementation.

**Unsigned bytes.** Password indexing is `charset[byte % charset.length]` with bytes read as
**0..255**. On the JVM `Byte` is `-128..127` and `%` preserves the sign, so a direct translation
yields negative indices. About 54% of the bytes in these vectors exceed 127. The wrong output is
still a plausible-looking password, which is exactly what makes it dangerous — use
`b.toInt() and 0xFF`.

**Charset order.** Built by concatenation: lowercase, then uppercase, then digits, then
`!@#$%^&*()_+-=.`. Any reordering changes every password ever generated.

**The compliance loop is live.** When the generated password lacks an enabled character class, the
nonce increments and the derivation is retried. It is not a rare branch — at length 8 one of these
vectors reaches nonce 7. `compliance_nonce` records where each case settled.

**UTF-8 everywhere.** Master passwords, contexts and temporal secrets are encoded as UTF-8 before
hashing. A platform defaulting to UTF-16 or a system charset diverges only for non-ASCII users,
which is the worst possible way to find out.

**HKDF-Expand only.** RFC 5869 *without* the Extract step, HMAC-SHA512, and the PRK is the
64-character hex **string** encoded as ASCII — not the 32 raw bytes it represents.

**Base32 without padding.** TOTP secrets are RFC 4648 with `=` stripped.
