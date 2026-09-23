# NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management: Part 1 – General

- **Publisher:** NIST
- **URL:** https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
- **Retrieved:** 2026-09-23, 171 pages, SHA-256 `cc32391022c1382ac7c91490f6bcc8838e0f889925270da23ef4e800e2ecb7ad`
- **Licence:** US Government work (public domain)
- **Why vendored:** NIST IR 8547 ipd states its 2030 deprecation "at the 112-bit
  security level" and points to this document for what a security level means.

## Table 2 — Comparable security strengths (printed pp. 54–55, PDF pp. 66–67)

Extracted with pypdf; columns: Security Strength | FFC (DSA, DH, MQV) | IFC (RSA) | ECC (ECDSA, EdDSA, DH, MQV)

| Security strength | FFC | IFC (RSA) | ECC |
|---|---|---|---|
| ≤ 80 | L = 1024, N = 160 | k = 1024 | f = 160-223 |
| 112 | L = 2048, N = 224 | k = 2048 | f = 224-255 |
| 128 | L = 3072, N = 256 | k = 3072 | f = 256-383 |
| 192 | L = 7680, N = 384 | k = 7680 | f = 384-511 |
| 256 | L = 15360, N = 512 | k = 15360 | f = 512+ |

Footnote to the table: "The security-strength estimates will be significantly
affected when quantum computing becomes a practical consideration."
