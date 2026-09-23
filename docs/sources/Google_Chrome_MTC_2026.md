# Cultivating a robust and efficient quantum-safe HTTPS — Google Security Blog

- **Publisher:** Google (Chrome), security.googleblog.com
- **Date:** February 2026
- **URL:** https://security.googleblog.com/2026/02/cultivating-robust-and-efficient.html
- **Retrieved:** 2026-09-23, HTML SHA-256 `bac1ad657384e8889fe0cb02bea89f321dcb9b432504b048496e8cbb64d24cb5`

Exact sentences, extracted from the retrieved HTML:

- "To ensure the scalability and efficiency of the ecosystem, Chrome has no
  immediate plan to add traditional X.509 certificates containing post-quantum
  cryptography to the Chrome Root Store."
- "Instead, Chrome, in collaboration with other partners, is developing an
  evolution of HTTPS certificates based on Merkle Tree Certificates (MTCs)"
- "Phase 1 (UNDERWAY): In collaboration with Cloudflare, we are conducting a
  feasibility study to evaluate the performance and security of TLS connections
  relying on MTCs."
- "Phase 2 (Q1 2027): ... invite CT Log operators ... to participate in the
  initial bootstrapping of public MTCs."
- "Phase 3 (Q3 2027): ... finalize the requirements for onboarding additional CAs
  into the new Chrome Quantum-resistant Root Store (CQRS) and corresponding Root
  Program that only supports MTCs."

Scope: publicly trusted WebPKI (the Chrome Root Store). Private PKI is not
addressed by this statement.
