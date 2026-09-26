# SEBI CSCRF — Cybersecurity and Cyber Resilience Framework for SEBI Regulated Entities

- **Publisher:** Securities and Exchange Board of India (SEBI), IT Department (ITD-1)
- **Circular No.:** SEBI/HO/ITD-1/ITD_CSC_EXT/P/CIR/2024/113
- **Date:** August 20, 2024
- **Circular index page:**
  https://www.sebi.gov.in/legal/circulars/aug-2024/cybersecurity-and-cyber-resilience-framework-cscrf-for-sebi-regulated-entities-res-_85964.html
  (this page is a JS-rendered shell; the actual circular PDF is loaded by it from the
  URL below, found via the page's own network request to its embedded PDF viewer)
- **Primary PDF fetched:**
  https://www.sebi.gov.in/sebi_data/attachdocs/aug-2024/1724326790365.pdf
- **Retrieved:** 2026-09-26, PDF SHA-256
  `bd9ddb68bb49b9a92771ff01ed3138e01f0962b383e9ff643008b729290fc85d` (205 pages, "Version
  1.0" per running footer)

## What the circular actually says about PQC (Box Item 7, p.59-60)

Under "2.2. ID.RA: Risk Assessment" ("ID.RA.S2" standard), the circular contains a
non-numbered "Box Item 7: Cybersecurity and Quantum Computing" with six "indicative
measures":

> "Quantum Computers can efficiently break the asymmetric cryptographic systems which
> may jeopardize the security of transactions and expose sensitive data. Further, the
> symmetric cryptography may also require larger key sizes to remain secure. In view of
> the above, this may potentially be a major cybersecurity risk in the coming decade for
> the financial sector and for the REs.
>
> To mitigate these risks, REs shall focus on the following indicative measures:
>   1. REs shall maintain an inventory of cryptographic assets, prioritizing critical
>      assets for Post Quantum Cryptography (PQC) migration, and assess their IT
>      infrastructure capabilities.
>   2. REs shall develop strategies for the protection of assets which can and cannot be
>      migrated to PQC.
>   3. REs shall upgrade employees' skills, periodically revise policies and conduct
>      proof-of-concept trials in order to prepare themselves for cybersecurity
>      challenges arising from quantum computing.
>   4. REs shall explore the feasibility to adopt PQC and technologies like Quantum Key
>      Distribution (QKD).
>   5. REs shall monitor ongoing quantum computing developments for cybersecurity
>      threats, and ensure that senior management and relevant third-party service
>      providers are aware of the possible risks associated with this technology.
>   6. REs shall enhance their crypto-agility to ensure a seamless transition to
>      quantum-resistant solutions without disrupting their current IT systems."

The wider risk-assessment clause that Box Item 7 sits under (Section 2.2.ii.2) reads:

> "Risk assessment (including post-quantum risks) of REs' IT environment shall be done
> on a periodic basis."

## Why no dated PQC milestone was added to data/policy_deadlines.yaml

The circular's own compliance/timeline machinery (Section 4, "CSCRF Compliance, Audit
Report Submission, and Timelines", Table 15) sets *periodicities* (e.g. RE risk
assessment under ID.RA.S2 is half-yearly for MIIs, annual for Qualified/Mid-size REs)
for the general risk-assessment standard that post-quantum risk assessment is folded
into -- it does not set a calendar deadline (e.g. "by 31 December 20XX") for PQC
migration, cryptographic-asset inventory, or crypto-agility specifically. Box Item 7's
six measures are stated as "indicative measures", not dated requirements.

A full-text search of the 205-page PDF (`pdftotext -layout`) for
"quantum"/"crypto-agil"/"PQC" combined with "effective from"/"w.e.f."/"deadline"/
"shall be applicable from" found no PQC-specific date. Per the task's own instruction
("if it only says something general ... with a compliance date, model it faithfully;
do not invent a PQC deadline"), and because ecdat's `Milestone` schema
(`src/ecdat/risk/policy.py`) requires every milestone to carry a `date`, this circular is
recorded in `data/policy_deadlines.yaml` as `usable: false` with `why_not_usable`
pointing here, rather than inventing a milestone date the source does not state.

## Later clarification circulars checked (no PQC content in either)

- SEBI/HO/ITD-1/ITD_CSC_EXT/P/CIR/2024/184, "Clarifications to CSCRF for SEBI REs",
  December 31, 2024.
  https://www.sebi.gov.in/legal/circulars/dec-2024/clarifications-to-cybersecurity-and-cyber-resilience-framework-cscrf-for-sebi-regulated-entities-res-_90401.html
  -- PDF fetched from
  https://www.sebi.gov.in/sebi_data/attachdocs/dec-2024/1735646756843.pdf (3 pages).
  `pdftotext` search for "quantum"/"crypto-agil"/"PQC": no matches.
- SEBI/HO/ITD-1/ITD_CSC_EXT/P/CIR/2025/119, "Technical Clarifications to CSCRF for SEBI
  REs", August 28, 2025.
  https://www.sebi.gov.in/legal/circulars/aug-2025/technical-clarifications-to-cybersecurity-and-cyber-resilience-framework-cscrf-for-sebi-regulated-entities-res-_96329.html
  -- PDF fetched from
  https://www.sebi.gov.in/sebi_data/attachdocs/aug-2025/1756380695925.pdf (11 pages).
  `pdftotext` search for "quantum"/"crypto-agil"/"PQC": no matches.

Neither clarification circular changes or adds a PQC-specific date.
