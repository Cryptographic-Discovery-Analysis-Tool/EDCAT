"""The secret-leak guard, in one place (CLAUDE.md hard rule).

    "No private key / secret bytes in DB, logs, CLI output, CBOM, test
     snapshots. Store location + fingerprint only."

Every path that emits text a human or another system will read runs this: the
CycloneDX export, and the certificate adapter, which is the one adapter that
routinely holds private key material in memory (a PKCS#12 file contains one)
and must never let a byte of it out.

Deliberately blunt. A false positive costs one investigation; a false negative
ships a key. When in doubt the check fails closed -- `scan_for_secrets` raises
rather than returning a flag a caller can forget to read.
"""
from __future__ import annotations

import re


class SecretLeakError(ValueError):
    """Output contains something that looks like key material.

    A hard failure, never a warning: an export that leaks a key is worse than
    no export, and a finding that leaks one is worse than no finding.
    """


#: PEM armour for anything private, plus the obvious credential spellings and
#: the base64 prefix a DER-encoded PKCS#8 private key starts with.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PEM private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("PEM encrypted block", re.compile(r"-----BEGIN ENCRYPTED [A-Z ]*-----")),
    ("OpenSSH private key", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----")),
    ("PGP private key", re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----")),
    (
        "credential assignment",
        re.compile(r"(?i)\b(password|passphrase|secret_key|api[_-]?key)\s*[=:]\s*\S"),
    ),
    ("PKCS#8 marker", re.compile(r"\bMIIE[A-Za-z0-9+/]{40,}")),
)


def find_secrets(text: str) -> tuple[str, ...]:
    """Names of every pattern that matched. Empty when the text is clean."""
    return tuple(name for name, pattern in _SECRET_PATTERNS if pattern.search(text))


def scan_for_secrets(text: str, *, context: str = "output") -> None:
    """Raise SecretLeakError if `text` looks like it carries key material.

    Run on SERIALISED text, not on an object tree: the point is to check what
    actually leaves the process, including anything a nested structure
    stringified on the way out.
    """
    hits = find_secrets(text)
    if hits:
        raise SecretLeakError(
            f"refusing to emit {context}: matched " + ", ".join(hits) + ". "
            "Only locations and fingerprints may leave this process (CLAUDE.md)."
        )
