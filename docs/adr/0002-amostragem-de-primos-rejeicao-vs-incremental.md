# ADR-0002 — Prime sampling: rejection, not incremental search

**Status:** Accepted
**Date:** 2026-08-03

## Context

With [ADR-0001](0001-geracao-rsa-deterministica.md) settling that p and q would be derived from
the HKDF stream, what remains is choosing **how** to turn an arbitrary candidate into a prime.
There are two families:

1. **Incremental search (*next-prime*).** Generate one candidate and walk upward (`p += 2`),
   running primality tests until the first prime above it is found.
2. **Rejection.** Every rejected candidate is discarded entirely and a fresh, independent
   candidate is derived by incrementing a counter that feeds into the HKDF `info`.

Incremental search is the first natural idea, and it is intuitively cheaper: only one candidate
needs to be derived from the KDF.

## Decision

Use **rejection**.

## Rationale

Incremental search picks each prime with probability **proportional to the gap preceding it**.
Primes that immediately follow a large gap are over-sampled; twin primes are under-sampled. Near
2^1024 the average gap is ~710, but gaps of order `(ln x)²` occur, producing non-uniformity of
up to ~3 orders of magnitude. FIPS 186-5 §B.3.3 forbids incremental search for exactly this
reason and requires a fresh candidate on every rejection.

In practice this bias is not an RSA break, and in a deterministic scheme it matters even less:
the key's real entropy comes from the master password, not from the draw of p. The deciding
argument was different — **both were measured, and the cost is equivalent**:

| | 1024-bit prime | 2048-bit prime |
|---|---|---|
| rejection | ~0.07s | ~1.5s |
| incremental search | ~0.11s | ~0.5s |

The variance between seeds dominates the difference between the two methods. Since there is no
performance trade-off to pay, the method chosen is the one that is standard-compliant and
simpler to justify.

## Consequences

- `_derive_prime` carries a counter that feeds into the HKDF `info`; that is what produces
  independent candidates. The counter is **not** exposed: the function is a pure function of
  (prk, label, bits).
- The Miller-Rabin bases are derived from `SHA-512(n)`, never from `secrets`/`random` — using a
  random source here would silently destroy reproducibility. Deriving them from the candidate
  itself (rather than fixing them publicly) also prevents anyone from grinding contexts until
  they hit a strong pseudoprime that passes a base set known in advance.
- There are 24 rounds (12 fixed + 12 derived bases), putting the false-positive probability
  around 2⁻⁴⁸. That is more than FIPS requires; the extra cost only falls on the two confirmed
  primes, since almost every composite candidate dies at base 2.
- A sieve of Eratosthenes up to 65536, computed once at import, eliminates ~84% of odd candidates
  by trial division before any modular exponentiation. That is what keeps generation in the
  sub-second range.
