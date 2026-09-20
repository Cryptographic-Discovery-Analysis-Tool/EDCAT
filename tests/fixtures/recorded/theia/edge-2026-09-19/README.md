# cbomkit-theia (image `ghcr.io/ibm/cbomkit-theia:latest`, tag `edge`) — recorded 2026-09-19/20

**Exact image:** `ghcr.io/ibm/cbomkit-theia:latest`, digest
`sha256:e156d5eedfec9105f28482117e4c3b52d5ee8ebe6fe79c507c784aa731b0ac7e`, pulled 2026-09-19.
The tool reports its own version as the literal string `"edge"` inside the CBOM it writes (see
`metadata.tools.services[0].version` below) — there is no separate numbered release to pin against,
so the image digest above is the actual pin.

**Exact command (real Tier A target, real docker daemon, no image built for this purpose):**
```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/ibm/cbomkit-theia:latest image ecdat-harness-tier-a-edge-lb:latest
```
Default plugins (`certificates`, `secrets` — `javasecurity` auto-disabled: "no BOM provided").
Ran against the **already-running, already-built** Tier A `edge-lb` container image (HAProxy
3.0.27, Alpine 3.24.2) — not a purpose-built target.

**Result:** succeeded, `exit=0`. Produced a valid CycloneDX 1.6 document with **5082 components**
and **847 `dependencies` entries**, overwhelmingly parsed out of Alpine's single CA bundle file,
`/etc/ssl/cert.pem` (which is why every `evidence.occurrences[].location` below reads the same
path — it is one file containing ~150 concatenated root certificates, and the tool emits several
components — the algorithm, the hash, the signature, the public key, the certificate itself — per
certificate found inside it).

**`edge-lb.sample.json` in this directory is a trimmed six-component slice of the real output**,
not the full 3.8 MB / 126k-line file, kept small enough to commit and read. It is a syntactically
valid, self-contained CycloneDX 1.6 document on its own (its `dependencies` array is filtered to
reference only the six components kept), covering one full certificate's worth of records: the
signature algorithm, its hash, the combined signature-with-hash, the public-key algorithm, the
public key itself (as `related-crypto-material`), and the certificate record that ties them
together via `signatureAlgorithmRef`/`subjectPublicKeyRef`. The full untrimmed capture is not
committed; the counts above (5082 / 847) are the measured, real totals from the actual run,
recorded here rather than only in a file nobody will check in.

**The `payment-gateway` (JVM/Spring Boot) image FAILED, and the failure itself is a real, recorded
finding, not worked around:**
```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/ibm/cbomkit-theia:latest image ecdat-harness-tier-a-payment-gateway:latest
```
```
level=error msg="could not scan image: plugin (Certificate File Plugin) failed to updated
components of bom; max allowable directory traversal depth reached (maybe a link cycle?)"
```
Re-run with only the `secrets` plugin (`-p secrets`) to isolate whether `certificates` alone was
the problem: same failure, same error, empty output. The bundled JRE under
`/usr/lib/jvm/default-jvm/jre/...` produces a long chain of nested `jre/jre/jre/...` symlinks in
the image layer, which cbomkit-theia's directory walker refuses to follow past its own depth
limit — a real property of this specific base image + this specific tool version, not something
adapter code can parse around. Filed here rather than silently reporting "found nothing" for that
image, which would have looked identical to a genuinely clean scan.

## What this proves, adapter-design-relevant

The CBOM **importer** side of this (`src/ecdat/export/cyclonedx.py::import_cbom`, built in ledger
phase 6) already accepts exactly this shape of document as third-party evidence — this capture is
real proof that a real run of the tool this project names as its P4b sensor produces output that
importer can actually ingest, not just documentation of the format. The **wrapper adapter** that
would invoke the tool itself (shell out, capture, feed through the importer, handle the
directory-traversal failure mode as a `FAILED` outcome with a real `failure_reason` rather than
crashing or silently emitting nothing) is not written yet — see `docs/build-plan.md`'s P4b row.
