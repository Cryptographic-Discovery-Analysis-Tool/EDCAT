# NIST IR 8547 ipd — Transition to Post-Quantum Cryptography Standards

- **Publisher:** NIST, Computer Security Division (Moody, Perlner, Regenscheid, Robinson, Cooper)
- **Date / status:** November 2024, **Initial Public Draft** (still a draft as of 2026-09-23)
- **URL:** https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf (DOI 10.6028/NIST.IR.8547.ipd)
- **Retrieved:** 2026-09-23, 29 pages, SHA-256 `6b551b4ff9858a19c1ab48d7deef2ee52d615066b7d187aaf992cb50c5ca0ed6`
- **Licence:** US Government work (public domain)

Vendored as excerpts, not the full PDF: the rows in `data/` cite this file, and
every quote below was extracted from the retrieved PDF text (pypdf), not recalled.

## Table 2 — Quantum-vulnerable digital signature algorithms (p. 13, PDF p. 20)

| Family | Parameters | Transition |
|---|---|---|
| ECDSA [FIPS186] | 112 bits of security strength | Deprecated after 2030; Disallowed after 2035 |
| ECDSA [FIPS186] | ≥ 128 bits of security strength | Disallowed after 2035 |
| EdDSA [FIPS186] | ≥ 128 bits of security strength | Disallowed after 2035 |
| RSA [FIPS186] | 112 bits of security strength | Deprecated after 2030; Disallowed after 2035 |
| RSA [FIPS186] | ≥ 128 bits of security strength | Disallowed after 2035 |

Surrounding text (p. 13): "NIST intends to instead deprecate classical digital
signatures at the 112-bit security level."

## Table 4 — Quantum-vulnerable key-establishment schemes (p. 14, PDF p. 21)

| Scheme | Parameters | Transition |
|---|---|---|
| Finite Field DH and MQV [SP80056A] | 112 bits of security strength | Deprecated after 2030; Disallowed after 2035 |
| Finite Field DH and MQV [SP80056A] | ≥ 128 bits of security strength | Disallowed after 2035 |
| Elliptic Curve DH and MQC [SP80056A] | 112 bits of security strength | Deprecated after 2030; Disallowed after 2035 |
| Elliptic Curve DH and MQC [SP80056A] | ≥ 128 bits of security strength | Disallowed after 2035 |
| RSA [SP80056B] | 112 bits of security strength | Deprecated after 2030; Disallowed after 2035 |
| RSA [SP80056B] | ≥ 128 bits of security strength | Disallowed after 2035 |

"MQC" is the PDF's own spelling in this row (Table 4), reproduced as extracted.
