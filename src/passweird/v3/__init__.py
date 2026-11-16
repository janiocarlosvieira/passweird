# Passweird v3 - derivation, key hierarchy and journal (ADR-0009)
# Licensed under the GNU General Public License v3.0
"""
Implementation of docs/adr/0009. Section numbers in comments refer to that ADR.

The v2 modules (passweird.crypto, passweird.storage) remain to read old files
during migration. v3 uses them in exactly two places: artifacts.py reuses the
SSH/TLS/OpenPGP format builders, and migrate.py reads v2 data. No v2
derivation feeds any v3 output.
"""
