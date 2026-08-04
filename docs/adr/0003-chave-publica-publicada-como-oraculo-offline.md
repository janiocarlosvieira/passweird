# ADR-0003 — Published public key as an offline oracle

**Status:** Accepted — risk accepted, not mitigated
**Date:** 2026-08-03

## Context

Deterministic asymmetric material has a property a regular password does not: **the public half
gets published**. A TLS certificate served by a host, an SSH key in `authorized_keys`, a PGP key
on a keyserver — all of them become accessible to anyone.

That turns the public key into an **offline verification oracle**. Against the deterministic RSA
from [ADR-0001](0001-geracao-rsa-deterministica.md), the attack is direct:

1. Guess a candidate master password.
2. Derive `modified_hash` and from it only the **first** prime p (half the work).
3. Test `n mod p == 0`, with `n` read from the public certificate.

A hit confirms the master password — and with it, every other password derived from it. No rate
limiting is possible: the attacker has `n` and works offline.

The current KDF does not sustain this exposure. `modified_hash()` (`crypto.py`) is literally:

```python
first_hash = hashlib.sha256(value.encode()).hexdigest()
derived = hashlib.sha256(first_hash[:-1].encode()).hexdigest()
```

Two rounds of SHA-256, no salt, no work factor. It gets worse: `storage.save_master_hash()`
writes this value in plain text to `~/.passweird/master.hash`, which gives a second offline
oracle to anyone with read access to the disk, costing 2 SHA-256 per attempt.

## Decision

**Accept the risk now** and ship deterministic RSA without touching the KDF.

Rationale: swapping `modified_hash` for Argon2id is a change that invalidates **every** password
Passweird has ever generated, and requires versioning and a migration path. Bundling that with
the RSA feature would couple two changes of very different risk — one additive and testable in
isolation, the other breaking every existing user.

## Partial (accidental) mitigation — and why it is smaller than it looks

It is tempting to assume the cost of generating the key (~230ms at 2048 bits) acts as
proof-of-work and raises the attacker's cost per attempt in the same proportion. **It does not.**
The attacker has a shortcut: they do not need to discover *which* candidate in the sequence is
prime. They just walk the candidates and test `n mod candidate == 0` on each one. If the
candidate is our p, it divides n; if it is composite, it does not. This skips the small-prime
sieve and every round of Miller-Rabin — exactly what dominates the honest cost.

Measured on this codebase (pure CPython, one core, K=400 candidates per attempt):

| Oracle | Cost per guess | Guesses/s/core |
|---|---|---|
| `~/.passweird/master.hash` (2× SHA-256) | 0.76µs | ~1,324,000 |
| Published RSA public key | 2.36ms | ~424 |
| *(honest generation, for comparison)* | 229ms | — |

In other words: the attacker pays about **1% of the honest generation cost**, and the effective
brake is ~3,000× over a regular password guess — not the ~300,000× the generation-time
difference would suggest. On a 100-core rig that is ~42k guesses/s; reimplemented in C or on a
GPU, much more. A ~40-bit-entropy password is reachable; a 6+ word diceware passphrase is not.

The conclusion is that this is **not a designed defense** and should not be counted as one.

## Precomputation: what is and is not a "rainbow table"

Worth distinguishing, because the two oracles have different attack shapes:

- **`master.hash` is the classic case.** `modified_hash` has no salt and is identical for every
  Passweird user, so a single precomputed table inverts anyone's file. It is exactly the scenario
  rainbow tables were invented for.
- **The public key is not**, in the classic sense: the target `n` is unique per
  (master password, context), and no table covers that without also enumerating contexts.

But there are two real precomputation gaps even so:

1. The pipeline is `password → modified_hash → HKDF(context) → p,q → n`, and the **first stage
   does not depend on the context**. A `master_hash` table for a large dictionary is built once
   and reused against every Passweird target that exists.
2. Contexts have low entropy and are guessable (`gmail.com`, `github.com`). For a popular
   context, one can precompute `password → n` and match it against any user of that service.

Both die with a per-user salt in the KDF — which is precisely what migrating to Argon2id should
bring.

## The context is not secret on the SSL path

An aggravating factor specific to `--ssl`/`--rsa`: the certificate **prints the derivation
context in the CN**, in plain text. Choosing an unpredictable context name — a strategy that
works for `--ssh`, whose public key does not carry the context — is worthless here, because
whoever downloads the certificate reads the context along with it.

This is why `temporal_salt` was wired into the SSL/RSA path (it used to be computed in
`main.py` and discarded). It is **the only unpredictable input that is not published with the
artifact**, and should be treated as a second password, not a version label: `2026/01` adds no
meaningful entropy; a 6+ word random passphrase does.

Documentation consequence: the README explicitly instructs on this, and the CLI emits a warning
when a certificate is generated without a temporal secret.

## How much entropy is needed

The attack costs ~2.4ms/guess/core in this Python implementation. Assuming an attacker who
reimplements it in C, gains 100× and has 10⁴ cores, that reaches the order of 10⁹ guesses/s; a
state-level adversary with 100× more resources would reach 10¹¹.

| Combined entropy (master password + temporal secret) | at 10⁹ guesses/s | at 10¹¹ guesses/s |
|---|---|---|
| 40 bits | 18 minutes | seconds |
| 50 bits | 13 days | 3 hours |
| 60 bits | 37 years | 133 days |
| 70 bits | 3.7×10⁴ years | 374 years |
| 80 bits | 3.8×10⁷ years | 3.8×10⁵ years |
| 100 bits | infeasible | infeasible |

Two 6-word diceware passphrases add up to ~155 bits and sit comfortably out of reach. A "strong"
master password in the common sense (12 mixed characters, ~60–70 bits) resists an opportunistic
attacker, but not comfortably against a dedicated adversary — and does not resist at all if the
real entropy is lower than the naive count suggests, which is the typical case for
human-chosen passwords. That is why the README recommends a strong temporal secret, a keyfile,
or FIDO2 whenever asymmetric material is published.

**Note:** an earlier version of this ADR gave "~weeks" for 60 bits and "~10⁴ years" for 80 bits.
Both were wrong due to an arithmetic error — they understated resistance by roughly three and
four orders of magnitude, respectively. The numbers above have been recalculated.

## Consequences

- Anyone using `--rsa`, `--ssl`, `--ssh` or `--pgp` with a weak master password is materially
  less protected than someone who only generates passwords, because the oracle gets published.
  This must be stated in the documentation in plain language, not hidden.
- Recorded as a separate roadmap item: replace `modified_hash` with Argon2id, with a salt and
  algorithm versioning, and stop writing the master hash in plain text. A future ADR supersedes
  this one when that happens.
