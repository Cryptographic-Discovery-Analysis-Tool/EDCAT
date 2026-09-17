# Experiments

Evidence-gate results: exact commands, tool/library versions, and raw output for anything the
code or CI relies on. No claim here may be typed from memory (see CLAUDE.md anti-hallucination
rules) — every row must be reproducible from the command given.

## EXP-001 — CycloneDX 1.6 JSON schema acquisition (2026-09-17)

**Purpose:** obtain the canonical CycloneDX 1.6 schema so enum/field verification (Lock §7,
"CycloneDX 1.6 enum verification against the canonical schema") never relies on memory.

- **URL:** https://cyclonedx.org/schema/bom-1.6.schema.json
- **Date fetched:** 2026-09-17
- **Command:**
  ```bash
  curl -s -o schemas/cyclonedx-1.6.schema.json https://cyclonedx.org/schema/bom-1.6.schema.json
  ```
- **File size:** 190,498 bytes
- **SHA-256:** `1ebcb88a2c845ecb6ff7bee7aeabdff9422cb0347f3d6875b241bd444b7e098`
- **Verification:** `$id` field inside the downloaded file reads
  `http://cyclonedx.org/schema/bom-1.6.schema.json`, `$schema` is JSON Schema draft-07 — confirms
  this is the CycloneDX 1.6 BOM schema, not a redirect or error page.
- **Outstanding:** enum verification itself (Lock §7 open question) is not yet done — this entry
  only covers acquiring the schema file.
