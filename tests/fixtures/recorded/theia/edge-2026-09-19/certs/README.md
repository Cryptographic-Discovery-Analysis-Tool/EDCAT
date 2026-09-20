# Real extracted certificate — `isrg-root-x2.pem` (recorded 2026-09-20)

**Provenance:** extracted live from the real Tier A `edge-lb` image
(`ecdat-harness-tier-a-edge-lb:latest`, the same image the theia CBOM in the
parent directory was recorded against) at the exact filesystem path
cbomkit-theia's own CBOM reports as this certificate's `location`:
`/etc/ssl/certs/ca-certificates.crt` (Alpine's CA bundle; `/etc/ssl/cert.pem`
is a symlink to it).

**Exact command:**
```
docker run --rm --entrypoint cat ecdat-harness-tier-a-edge-lb:latest \
  /etc/ssl/certs/ca-certificates.crt
```
The full bundle this command returns holds **121 certificates** (measured,
not assumed). This file is one of them — the "ISRG Root X2" entry, isolated
with `cryptography.x509.load_pem_x509_certificates` and re-serialised —
kept small and committable rather than checking in the full 121-certificate
bundle for one test case.

**Measured values** (via `ecdat.adapters.certs.parser.load_pem_or_der`, the
same canonicalisation `certs-x509` and `tls-endpoint` both use):
- `der_sha256`: `69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470`
- `spki_sha256`: `762195c225586ee6c0237456e2107dc54f1efc21f61a792ebd515913cce68332`
- subject / issuer: `CN=ISRG Root X2,O=Internet Security Research Group,C=US`

**Why this fixture exists — the format mismatch it caught.** cbomkit-theia's
own CBOM (`../edge-lb.sample.json`) reports this same certificate's
`subjectName` as the bare string `"ISRG Root X2"` — measured directly
against the real tool output, **not** the full
`"CN=ISRG Root X2,O=Internet Security Research Group,C=US"`
`python-cryptography`'s `rfc4514_string()` produces. `certmatch.py`'s
matching logic (Common Name only, not the full DN) exists specifically
because of this measured discrepancy — matching on the full subject string
would have matched nothing, ever, for any certificate on this surface.
