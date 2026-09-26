# Hybrid-group individual probe recordings (OI-016/OI-017, DEV-013)

Recorded 2026-09-26 against two throwaway local `openssl s_server` instances,
not the live Tier A endpoint. Purpose: give `adapters/tls/parser.py` and
`adapters/tls/adapter.py`'s per-group probe path something real to parse for
*acceptance* of an individually-offered group, as opposed to DEV-004's
existing full-offer / classical-only pair (`tests/fixtures/recorded/openssl/
3.5.8/tier_a_edge_lb.*`), which only ever reports the single group the
endpoint *prefers* when everything is offered at once.

## Versions

```
$ openssl version
OpenSSL 3.5.4 30 Sep 2025 (Library: OpenSSL 3.5.4 30 Sep 2025)
```

Both the server and every probe below used this same binary
(`/mingw64/bin/openssl` in Git Bash on the recording machine) -- server and
client are the same process image, so there is no cross-version ambiguity in
what a given recording proves. See `openssl_version.txt` in this directory
for the raw `openssl version` capture used for the parser's version-string
test fixture.

## Throwaway certificate

```
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout key.pem -out cert.pem -days 2 -nodes \
  -subj "/CN=ecdat-fixture-gen.test"
```

Self-signed, 2-day validity, generated solely for this recording session and
never committed (only the probe *text output* is a fixture; CLAUDE.md: no
private key bytes in test snapshots -- `key.pem`/`cert.pem` were discarded
after recording and are not part of this fixture set).

## Servers

Two `s_server` instances, differing only in `-groups`:

```
# (a) hybrid-enabled -- accepts three PQ hybrid groups plus classical X25519
openssl s_server -accept 14443 -cert cert.pem -key key.pem \
  -groups X25519MLKEM768:X25519:SecP256r1MLKEM768:SecP384r1MLKEM1024 -www

# (b) classical-only -- accepts no hybrid group at all
openssl s_server -accept 14444 -cert cert.pem -key key.pem \
  -groups X25519:secp256r1 -www
```

`hybrid_server/` holds recordings against (a); `classical_server/` holds
recordings against (b).

## Probes

Each `probe_<GROUP>.txt` is one individual-group probe -- the client offers
**only** that one named group, which is what proves *acceptance* rather than
mere *preference*:

```
openssl s_client -connect 127.0.0.1:<port> -groups <GROUP> -brief < /dev/null
```

`probe_full_offer.txt` in each directory is a control recording with no
`-groups` restriction at all (client offers OpenSSL's full default list),
recorded to confirm which group each server *prefers* when everything is on
the table -- this is the same probe shape DEV-004 already runs live, kept
here only so the "prefers vs accepts" distinction in the adapter/parser tests
has both cases side by side from the identical server instances.

| Recording | Server | Group offered | Result |
|---|---|---|---|
| `hybrid_server/probe_X25519MLKEM768.txt` | (a) hybrid | X25519MLKEM768 | accepted (hybrid) |
| `hybrid_server/probe_SecP256r1MLKEM768.txt` | (a) hybrid | SecP256r1MLKEM768 | accepted (hybrid) |
| `hybrid_server/probe_SecP384r1MLKEM1024.txt` | (a) hybrid | SecP384r1MLKEM1024 | accepted (hybrid) |
| `hybrid_server/probe_X25519.txt` | (a) hybrid | X25519 | accepted (classical) |
| `hybrid_server/probe_secp256r1.txt` | (a) hybrid | secp256r1 | **refused** -- (a) was not configured with this group; `SSL alert number 40` (handshake failure) |
| `hybrid_server/probe_full_offer.txt` | (a) hybrid | (default set) | negotiates X25519MLKEM768 -- server's preferred group |
| `classical_server/probe_X25519MLKEM768.txt` | (b) classical | X25519MLKEM768 | **refused** -- handshake failure |
| `classical_server/probe_SecP256r1MLKEM768.txt` | (b) classical | SecP256r1MLKEM768 | **refused** -- handshake failure |
| `classical_server/probe_SecP384r1MLKEM1024.txt` | (b) classical | SecP384r1MLKEM1024 | **refused** -- handshake failure |
| `classical_server/probe_X25519.txt` | (b) classical | X25519 | accepted (classical) |
| `classical_server/probe_secp256r1.txt` | (b) classical | secp256r1 | accepted (classical) -- reported as `Peer Temp Key: ECDH, prime256v1, 256 bits`, a THIRD line shape distinct from the `X25519, 253 bits` shape the existing DEV-004 fixtures cover (see DEV-013) |
| `classical_server/probe_full_offer.txt` | (b) classical | (default set) | negotiates X25519 -- no hybrid group available at all |

## What this does and does not prove

Each "accepted" result means: a handshake offering *only* that single named
group completed. It does not mean the group is preferred, and it says
nothing about any group not individually probed. `probe_full_offer.txt`
covers the complementary "preferred when everything is offered" question,
exactly as DEV-004's existing pair does against the live Tier A endpoint --
kept apart from `probe_<GROUP>.txt` on purpose, so the adapter can report
"accepted" and "preferred" as two different fields with two different
evidence refs, never conflating one for the other.

Deliberately not recorded here: the deprecated draft group
`X25519Kyber768Draft00`. OpenSSL 3.5.4 never shipped it as a named group
(`Call to SSL_CONF_cmd(-groups, X25519Kyber768Draft00) failed` -- it was a
pre-standardisation BoringSSL/Cloudflare experiment, never an upstream
OpenSSL group name), so there is no live tool on this machine that can
produce a recording of it being negotiated. The adapter's deprecated-flag
test therefore uses a hand-authored `Negotiated TLS1.3 group:` line (same
line shape this directory's real recordings establish, only the group name
substituted) rather than a recorded fixture -- documented at the test site,
not presented as a live capture.
