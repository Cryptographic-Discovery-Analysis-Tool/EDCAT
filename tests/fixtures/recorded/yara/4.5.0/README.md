# yara 4.5.0 — recorded fixtures (2026-09-20)

**Rule file under test:** `rules/yara/crypto-constants.yar` (Pramana's own; see that file's
header for what it matches and why).

**Exact version:** `yara --version` → `4.5.0` (provisioned by `tools/provision/build-box.sh`,
already pinned per `docs/build-box.md`).

**Target:** two files copied out of the *already-running* Tier A `edge-lb` container
(`ecdat-harness-tier-a-edge-lb-1`, HAProxy 3.0.27, Alpine 3.24.2) with `docker cp`, so this is
real Tier A material, not synthesised:

- `/usr/local/sbin/haproxy` — the load balancer's own binary. SHA-256:
  `917c71ce7d51c6810f8f54c4e801e389713f79a52f4751353e4aa4a86a93496c`
- `/usr/lib/libcrypto.so.3` — OpenSSL 3.5.8's crypto-primitives library (haproxy links this
  dynamically; it does not embed AES/SHA tables itself). SHA-256:
  `b737ff6c1e585ba6be514d17c84e2d8347921558c13db2fdb5513578797d8413`

Binaries themselves are **not** committed to this repository (they are large, and are
redistributions of Alpine/OpenSSL packages, not project material) — only the recorded command
output below, which is what a parser is written against.

## Command and exact output

```
$ yara -w rules/yara/crypto-constants.yar haproxy
(no output -- no match, exit code 1)
```
See `haproxy.no-match.txt`.

```
$ yara -w rules/yara/crypto-constants.yar libcrypto.so.3
Pramana_AES_Rijndael_Sbox libcrypto.so.3
```
See `libcrypto.match.txt` for the bare match line, and `libcrypto.match.verbose.txt` for the
`-s` (print matched strings + offsets) form: four occurrences of the AES S-box at 0x320800,
0x320900, 0x320a00, 0x320b00 (adjacent 256-byte tables — OpenSSL keeps more than one copy of the
forward table for different code paths). `Pramana_SHA256_InitialHash` did **not** match either
file in this run — recorded as a negative result, not silently omitted; OpenSSL 3.5.8's SHA-256
implementation on this build evidently does not store `H0` as one contiguous 16-byte run the rule
looks for (it may use a different constant layout, e.g. per-word or via a code-generated table) —
filed as a known limitation of this specific rule, not evidence SHA-256 is absent.

## What this run demonstrates (adapter-design-relevant)

**A binary's own YARA silence does not mean the family is absent** — the exact "package presence
vs usage" style trap this project cares about, one level down: `haproxy` itself never matches,
because AES is not compiled into it; it is present only via `readelf`'s `NEEDED libssl.so.3` /
`NEEDED libcrypto.so.3` dynamic-dependency entries (see `tests/fixtures/recorded/readelf/`).
Family evidence from a YARA match on the executable itself and family evidence from a dynamic
dependency are two different observation strengths and must be recorded as such, not merged.

**RSA/ECDSA have no fixed constant table** to match this way (no S-box, no fixed IV) — this run
does not attempt them, and an adapter built from this fixture must report that as an explicit
capability gap, not silently return zero RSA findings as if that meant "no RSA".

## Files

- `haproxy.no-match.txt`
- `libcrypto.match.txt`
- `libcrypto.match.verbose.txt`
