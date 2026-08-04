# ADR-0004 — Domain separation in the HKDF `info` string

**Status:** Accepted
**Date:** 2026-08-03

## Context

Every generator builds the HKDF `info` by concatenating fields separated by `:`, ending in
`temporal_salt`:

```
{app_hash}:ssl_seed:{temporal_salt}
```

Some generators need a **sub-derivation** from the same material — the certificate's serial
number, the OpenSSH container's `checkint`, the PGP key's creation timestamp. These were
obtained by appending a literal suffix to the already-built `info`:

```python
serial_seed = hkdf_expand(prk, info + b":serial", 19)
```

The problem: `temporal_salt` is **free text controlled by the user** and sits at the **end** of
`info`. Appending a suffix after it makes the encoding ambiguous — there is no way, looking at
the final string, to tell where the salt ends and the suffix begins.

Concretely, for the same master password and the same context:

| Configuration | Resulting `info` |
|---|---|
| certificate serial with salt `X` | `{ah}:ssl_seed:X:serial` |
| **private key** with salt `X:serial` | `{ah}:ssl_seed:X:serial` |

They are identical. And since HKDF-Expand produces a stream whose prefix is stable, the serial's
19 bytes are exactly the first 19 bytes of the 32-byte private seed. **152 of the 256 bits of the
Ed25519 private key become readable to anyone who has the certificate**, which publishes the
serial in plain text. 104 bits remain — not an immediate break, but a private key leak.

Also verified in `:checkint` (SSH) and `:ctime` (PGP), with the same shape and lower severity
(the checkint stays inside the private container; the ctime leaks 4 bytes).

The password and RSA paths are **not** affected: there, the last field is the counter/nonce,
made only of digits and never containing `:`. Right-to-left decomposition is unique, so no salt
can forge the final field.

## Decision

No field is ever appended after `temporal_salt`. Sub-derivations get their **own label**,
positioned before the salt:

| Before | After |
|---|---|
| `{ah}:ssl_seed:{salt}` + `":serial"` | `{ah}:ssl_serial:{salt}` |
| `{ah}:ssh_seed:{salt}` + `":checkint"` | `{ah}:ssh_checkint:{salt}` |
| `{ah}:pgp_seed:{salt}` + `":ctime"` | `{ah}:pgp_ctime:{salt}` |

General rule for new code: **the salt is always the last field of `info`**. Any derivation
variant becomes a distinct label, never a suffix.

Rejected the alternative of hashing the salt with `sha256()` before inserting it (which would
also make it fixed-length and unambiguous): it would solve the problem, but would change the
derivation of **every** password ever generated with a temporal secret, including empty ones.

## Consequences

Choosing dedicated labels preserves the `*_seed` values, so **key material does not change**:

- **SSH** — public and private keys are identical; only the OpenSSH container bytes change.
  Already-deployed `authorized_keys` entries remain valid. Covered by a test.
- **SSL** — key identical; only the certificate's serial number changes.
- **PGP** — the Ed25519 key is the same, but `ctime` feeds into the fingerprint computation, so
  the **Key ID changes**. Already-distributed PGP keys need to be redistributed.
- **Password, RSA, TOTP** — nothing changes.

## Latent bug discovered along the way

Relabeling `ctime` moved the derived value to a different point in the range and made the `gpg`
import test fail. The change was not the cause: the computation was
`derived % 2_000_000_000`, whose ceiling is 2033-05-18. Future-dated timestamps make `gpg`
refuse the import (`failed to re-lookup public key`), and this affected roughly **1 in 9**
password/context/salt combinations — it just hadn't shown up because the previously derived
value happened to land in the past.

Fixed by mapping into a fixed, permanently past window (2000-01-01 plus up to 20 years). The
window **cannot** track the wall clock: the timestamp feeds into the fingerprint, so a moving
bound would silently change the key's identity over time.
