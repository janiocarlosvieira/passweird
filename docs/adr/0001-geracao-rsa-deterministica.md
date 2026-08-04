# ADR-0001 — Deterministic RSA key generation

**Status:** Accepted
**Date:** 2026-08-03

## Context

Passweird's premise is to be *stateless*: nothing is kept in a vault, everything is recomputed
from the master password plus a context. Every output honored this — passwords, Ed25519 SSH
keys, TOTP, PGP — except one. The `--rsa BITS` flag called `rsa.generate_private_key()` with no
seed at all, producing fresh material on every run. The CLI printed a WARNING admitting the
problem, and the README documented the limitation as if it were unavoidable: *"the library
offers no seeded RSA generation"*.

The limitation was in the API, not in the mathematics. RSA key generation has exactly **one**
source of randomness: the choice of p and q. Everything else — `n = p·q`, `d = e⁻¹ mod λ(n)`,
the CRT parameters — is already a deterministic function of those two primes.

## Decision

Derive p and q from the same HKDF-SHA512 stream the rest of the project already uses
(`hkdf_expand`), and assemble the key via `rsa.RSAPrivateNumbers(...).private_key()` instead of
`rsa.generate_private_key()`.

Details that are part of the decision:

- **Distinct HKDF labels** for the two primes (`{app_hash}:rsa_seed:{temporal_salt}:p` and
  `:q`), following the pattern already established by `:ssh_seed:`, `:ssl_seed` and `:serial`.
  Rejected the alternative of deriving the second prime by transforming the user's input (e.g.
  reversing the keywords): that is an ad-hoc transform of low diversity, offering no principled
  argument for independence between p and q.
- **The SSL path was brought in line with the other generators** in the same change-set: it now
  derives from `app_hash` (no longer the raw `app`) and accepts `temporal_salt`, which used to be
  computed in `main.py` and silently discarded. `domain_context` is left only as the
  certificate's CN. This invalidates any previously issued Ed25519 SSL key — accepted, because
  none had been issued. See ADR-0003 for why the salt matters so much here.
- **No modular reduction into a range.** The candidate is built by forcing the top two bits to 1
  (guarantees `p·q` reaches the requested bit length) and bit 0 to 1 (odd). A `mod` over a span
  that is not a power of two would bias the low end of that span.
- **Mandatory constraints** applied during rejection: `gcd(e, p−1) = gcd(e, q−1) = 1` (otherwise
  `d` does not exist) and `|p − q| > 2^(bits/2 − 100)` (FIPS 186-5; without it, Fermat's method
  trivially factors the modulus).
- `RSAPrivateNumbers` validates the CRT parameters on construction, which doubles as a free
  self-check.

## Consequences

**Positive.** `--rsa` now honors the project's premise. The WARNING is gone from the CLI. The
whole certificate becomes reproducible (see the note on validity below).

**Cost.** The project now carries its own primality arithmetic (small-prime sieve +
Miller-Rabin), with the risk that homegrown cryptographic code always carries — mitigated by
tests that cross-check our primality testing against `sympy`'s independent implementation, and
by a sign/verify test proving OpenSSL accepts the assembled key.

**Measured performance** (pure CPython, no `gmpy2`, ordinary CPU): ~0.2–1s at 2048 bits and
~1–4s at 4096 bits. The spread is intrinsic — it depends on how many candidates are needed
before landing on a prime — not on the hardware. It is the same order of magnitude as
`openssl genrsa`, so it is not a new cost to the user.

**Necessary side effect.** Certificate validity used to come from `datetime.now()`, which has
one-second granularity: two certificates generated more than a second apart already diverged.
This went unnoticed because Ed25519 generates in microseconds; with RSA taking seconds,
announcing reproducibility would have been a half-truth. The anchor is now the current day's
UTC midnight, which makes the certificate byte-identical within the same UTC day. This changes
the bytes of previously issued Ed25519 certificates — the Ed25519 keys stay identical, only the
validity window changes.

## Rejected alternatives

- **pycryptodome with `randfunc=`.** Works and is clean, but adds a whole separate cryptography
  dependency for something `cryptography` already lets us assemble via `RSAPrivateNumbers`.
  Keeping a single cryptography library is worth more.
- **Mandatory `gmpy2`.** Would speed up generation by roughly an order of magnitude, but requires
  a compilation toolchain and turns a plain `pip install` into a friction point. Left as a
  possible future optional acceleration (use it if available, fall back to pure CPython if not).
- **Fixed-epoch validity anchor** (e.g. 2020-01-01 plus a derived offset). Would give perfect,
  permanent reproducibility, but would generate already-expired certificates.
