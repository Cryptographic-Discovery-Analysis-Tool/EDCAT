"""Parsers for the two TLS probes (P4; spec §3 row "TLS", §7.1 P4).

P4 requires "negotiated suite and group recorded -- the ledger's input". It
takes TWO probes to satisfy that, and the reason is measured, not stylistic:

* **sslyze 6.2.0** enumerates what an endpoint *accepts* -- certificate chain,
  cipher suites per protocol version, elliptic curves. It is the right tool
  for breadth.
* **sslyze cannot see a hybrid post-quantum group at all.** Its TLS stack is
  nassl 5.4.0, whose key-type vocabulary is exactly
  `DH, EC, X25519, X448, RSA, DSA, RSA_PSS` -- there is no ML-KEM member, so
  there is nothing for it to report even when the handshake uses one. Measured
  against the Tier A endpoint on 2026-09-19: OpenSSL 3.5.8 negotiated
  `X25519MLKEM768` with that endpoint, and sslyze scanning the same endpoint
  minutes later reported only classical curves. See OI-017.
* So the **negotiated group** -- the single input that can stop an exposure
  clock under §5.7 -- comes from an `openssl s_client` probe on OpenSSL 3.5+.

Getting this wrong fails in the quiet direction: with sslyze alone, no
endpoint would ever be observed refusing classical, no clock would ever stop,
and every surface would sit at BLEEDING forever. Safe, but useless -- the tool
could never recognise a migration that actually happened.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


class TlsProbeParseError(ValueError):
    """Probe output we cannot read. Carries no captured bytes."""


# --- openssl s_client -brief -------------------------------------------------

_PROTOCOL = re.compile(r"^Protocol version:\s*(?P<v>\S+)", re.MULTILINE)
_SUITE = re.compile(r"^Ciphersuite:\s*(?P<v>\S+)", re.MULTILINE)
_GROUP = re.compile(r"^Negotiated TLS1\.3 group:\s*(?P<v>\S+)", re.MULTILINE)
_TEMP_KEY = re.compile(r"^Peer Temp Key:\s*(?P<v>[^,\n]+)", re.MULTILINE)
_PEER_CERT = re.compile(r"^Peer certificate:\s*(?P<v>.+)$", re.MULTILINE)
_SIG_TYPE = re.compile(r"^Signature type:\s*(?P<v>\S+)", re.MULTILINE)
_ESTABLISHED = re.compile(r"^CONNECTION ESTABLISHED", re.MULTILINE)


@dataclass(frozen=True)
class NegotiatedHandshake:
    """What one handshake actually agreed on, from one vantage.

    `group` is the TLS 1.3 named group. When the server and client settle on a
    classical curve, OpenSSL reports it as `Peer Temp Key` rather than
    `Negotiated TLS1.3 group`; both are read, and `group_source` records which
    line it came from so a reader can tell a hybrid negotiation from a
    classical one without re-parsing.
    """

    established: bool
    protocol: str | None
    cipher_suite: str | None
    group: str | None
    group_source: str | None
    peer_certificate_subject: str | None
    signature_type: str | None

    @property
    def is_hybrid_group(self) -> bool:
        """True only for a group this parser can positively identify as
        hybrid. Unknown spellings are False and are resolved against
        data/crypto_families.yaml by the caller, never guessed here."""
        return bool(self.group) and "MLKEM" in self.group.upper()


def parse_negotiated(text: str) -> NegotiatedHandshake:
    """Parse `openssl s_client ... -brief` output."""
    if not text.strip():
        raise TlsProbeParseError("empty s_client output")

    group = None
    group_source = None
    if (match := _GROUP.search(text)) is not None:
        group, group_source = match.group("v"), "Negotiated TLS1.3 group"
    elif (match := _TEMP_KEY.search(text)) is not None:
        group, group_source = match.group("v").strip(), "Peer Temp Key"

    def first(pattern):
        found = pattern.search(text)
        return found.group("v").strip() if found else None

    return NegotiatedHandshake(
        established=bool(_ESTABLISHED.search(text)),
        protocol=first(_PROTOCOL),
        cipher_suite=first(_SUITE),
        group=group,
        group_source=group_source,
        peer_certificate_subject=first(_PEER_CERT),
        signature_type=first(_SIG_TYPE),
    )


# --- sslyze --json_out -------------------------------------------------------


@dataclass(frozen=True)
class SslyzeObservation:
    """What sslyze reported about one endpoint."""

    sslyze_version: str
    scan_status: str
    hostname: str | None
    port: int | None
    accepted_cipher_suites: dict[str, tuple[str, ...]] = field(default_factory=dict)
    supported_curves: tuple[str, ...] = ()
    rejected_curves: tuple[str, ...] = ()
    leaf_subject: str | None = None
    leaf_fingerprint_sha256: str | None = None
    chain_subjects: tuple[str, ...] = ()
    scan_commands_attempted: tuple[str, ...] = ()

    @property
    def completed(self) -> bool:
        return self.scan_status.upper() == "COMPLETED"


def _first_result(scan_result: dict[str, Any], command: str) -> dict[str, Any] | None:
    entry = scan_result.get(command)
    if not isinstance(entry, dict):
        return None
    result = entry.get("result")
    return result if isinstance(result, dict) else None


def parse_sslyze(document: dict[str, Any]) -> SslyzeObservation:
    """Parse one sslyze `--json_out` document (first server result)."""
    results = document.get("server_scan_results")
    if not isinstance(results, list) or not results:
        raise TlsProbeParseError("sslyze document contains no server_scan_results")
    server = results[0]

    location = server.get("server_location") or {}
    scan_result = server.get("scan_result") or {}

    suites: dict[str, tuple[str, ...]] = {}
    for command in (
        "ssl_2_0_cipher_suites",
        "ssl_3_0_cipher_suites",
        "tls_1_0_cipher_suites",
        "tls_1_1_cipher_suites",
        "tls_1_2_cipher_suites",
        "tls_1_3_cipher_suites",
    ):
        result = _first_result(scan_result, command)
        if result is None:
            continue
        accepted = result.get("accepted_cipher_suites") or []
        suites[command] = tuple(
            entry["cipher_suite"]["name"]
            for entry in accepted
            if isinstance(entry, dict) and entry.get("cipher_suite")
        )

    curves = _first_result(scan_result, "elliptic_curves") or {}
    supported = tuple(c["name"] for c in (curves.get("supported_curves") or []))
    rejected = tuple(c["name"] for c in (curves.get("rejected_curves") or []))

    leaf_subject = None
    leaf_fingerprint = None
    chain_subjects: tuple[str, ...] = ()
    certificate_info = _first_result(scan_result, "certificate_info") or {}
    for deployment in certificate_info.get("certificate_deployments") or []:
        chain = deployment.get("received_certificate_chain") or []
        if not chain:
            continue
        leaf = chain[0]
        leaf_subject = (leaf.get("subject") or {}).get("rfc4514_string")
        leaf_fingerprint = leaf.get("fingerprint_sha256")
        chain_subjects = tuple(
            (c.get("subject") or {}).get("rfc4514_string", "") for c in chain
        )
        break

    return SslyzeObservation(
        sslyze_version=str(document.get("sslyze_version", "")),
        scan_status=str(server.get("scan_status", "")),
        hostname=location.get("hostname") or location.get("ip_address"),
        port=location.get("port"),
        accepted_cipher_suites=suites,
        supported_curves=supported,
        rejected_curves=rejected,
        leaf_subject=leaf_subject,
        leaf_fingerprint_sha256=leaf_fingerprint,
        chain_subjects=chain_subjects,
        scan_commands_attempted=tuple(sorted(scan_result.keys())),
    )


#: nassl 5.4.0's complete key-type vocabulary, read off the library on
#: 2026-09-19 (fixture: tests/fixtures/recorded/openssl/3.5.8/
#: nassl_key_type_ceiling.txt). Recorded so the ceiling is a checked fact
#: rather than a claim in a comment.
NASSL_KEY_TYPES: frozenset[str] = frozenset(
    {"DH", "EC", "X25519", "X448", "RSA", "DSA", "RSA_PSS"}
)


def sslyze_can_see_group(group: str) -> bool:
    """Whether sslyze could report this group at all.

    Used to write an honest visibility entry: when the answer is False, a
    curve list from sslyze is evidence about the curves it knows, and says
    nothing whatever about the ones it does not.
    """
    return group.upper().replace("-", "_") in {k.upper() for k in NASSL_KEY_TYPES}
