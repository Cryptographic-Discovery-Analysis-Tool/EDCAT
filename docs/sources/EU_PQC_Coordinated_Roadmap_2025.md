# A Coordinated Implementation Roadmap for the Transition to Post-Quantum Cryptography — Part 1

- **Publisher:** EU PQC Workstream (NIS Cooperation Group), published by the European Commission
- **Version / date:** Version 1.1, 11.06.2025
- **URL:** https://ec.europa.eu/newsroom/dae/redirection/document/117507
  (linked from https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-roadmap-transition-post-quantum-cryptography)
- **Retrieved:** 2026-09-23, 17 pages, SHA-256 `e76b0ea3abe5606e71d49c154a2fe1422413b5c31d0cc8dbf87a74263ead00ea`

Quotes extracted with pypdf.

## The per-use-case rule (PDF p. 6)

"For high-risk use cases, quantum-vulnerable public-key mechanisms shall not be
used stand-alone after the end of 2030, analogously after the end of 2035 for
medium-risk use cases."

"Stand-alone" matters: a standardised hybrid combination that includes PQC
satisfies it (the same page recommends "replacing it by a standardized hybrid
combination which includes PQC").

## Milestones (PDF p. 7)

- "By 31.12.2030: ... The PQC transition for high-risk use cases has been completed."
- "By 31.12.2035: • The PQC transition for medium-risk use cases has been completed."

## Who decides a use case's risk level (PDF p. 10)

"...distinguishes between the three basic quantum risk levels “high”, “medium”
and “low”. These risk levels are defined based on the quantum risk score..."
— computed by the organisation from the weakness of the cryptography, the impact
of it being broken, and the migration effort. This tool computes no score
(§5.12), so the risk level is the operator's to state: high-risk and
medium-risk are carried as two separate policies, exactly like India's CII /
Enterprise split, and the operator applies the one that fits.
