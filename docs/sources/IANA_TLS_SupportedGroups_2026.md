# IANA — TLS Supported Groups registry (relevant rows)

- **Publisher:** IANA (Internet Assigned Numbers Authority), under the "Transport
  Layer Security (TLS) Parameters" registry group, per RFC 8446 §4.2.7 / RFC 7919.
- **Registry:** TLS Supported Groups
- **URL:** https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
  (anchor: "tls-parameters-8" -- Supported Groups)
- **Retrieved:** 2026-09-26

This file exists to give `data/crypto_families.yaml`'s `hybrid_groups` rows a
citable in-repo source for the wire codepoint each group name maps to, and
for the deprecated status of the pre-standardisation draft group -- neither
was previously cited anywhere in this repo (only the group *names* were, from
`IETF_RFC_10024_2026.md`). Codepoints are not used by the openssl/sslyze
probes themselves (both tools take the group's string name, not its
codepoint, as an argument), but the numeric identity is the actual IANA
registration and is what makes "these three names are THE standardised
hybrid groups, this fourth name is not" a checkable fact instead of an
assumption.

## Rows (verbatim table cells, retrieved 2026-09-26)

| Value | Description | DTLS-OK | Recommended | Reference |
|---|---|---|---|---|
| 4587 (`0x11EB`) | SecP256r1MLKEM768 | Y | N | [RFC 10024] -- "Combining secp256r1 ECDH with ML-KEM-768" |
| 4588 (`0x11EC`) | X25519MLKEM768 | Y | Y | [RFC 10024] -- "Combining X25519 ECDH with ML-KEM-768" |
| 4589 (`0x11ED`) | SecP384r1MLKEM1024 | Y | N | [RFC 10024] -- "Combining secp384r1 ECDH with ML-KEM-1024" |
| 25497 (`0x6399`) | X25519Kyber768Draft00 (OBSOLETE) | Y | D | [draft-tls-westerbaan-xyber768d00-02][RFC 10024] -- "Pre-standards version of Kyber768. Obsoleted by [RFC 10024]." |

`Recommended: D` is the registry's own "Discouraged" marker -- distinct from
`Y`/`N`, and the only row of the four carrying it. `X25519MLKEM768` is the
only row carrying `Recommended: Y`, consistent with `crypto_families.yaml`'s
existing citation of it (`Pramana_Ledger_Spec.md §5.1`) as the group actually
observed on the wire against Tier A.

## Why this doesn't need re-deriving from RFC 10024 itself

`IETF_RFC_10024_2026.md` already cites the RFC's Abstract for the three
group *names*. The RFC assigns their IANA codepoints in its IANA
Considerations section, but this repo has not vendored that section's text,
so the codepoint and "Recommended" column values are cited to the registry
page directly rather than inferred from the RFC citation already on file --
citing the primary registry is strictly stronger than re-deriving a
codepoint from a document that does not, in this repo, carry that section.
