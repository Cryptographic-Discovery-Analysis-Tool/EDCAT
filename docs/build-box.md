# The Linux build box

Provisioned 2026-09-19. Satisfies the prerequisite in
`docs/architecture/Pramana_Ledger_Spec.md` §7:

> a Linux build box with Docker, Go, Maven, haproxy, SoftHSM2 (FACT:
> OI-007/008/009 — Semgrep does not install on Windows; images and the Go
> binary cannot be built here).

## What it is

WSL2 Ubuntu on the development machine — not a separate host. That is enough
for everything §7 needs: a real Linux kernel, a working Docker daemon, and the
scanners at their pinned versions. It is **not** the delivery target; the
delivery target is air-gapped and this box has egress by design, because it
has to pull images and packages.

| | |
|---|---|
| Distro | Ubuntu 24.04.4 LTS |
| Kernel | 6.18.33.1-microsoft-standard-WSL2 |
| Provision script | `tools/provision/build-box.sh` (idempotent) |

## Provisioning

```bash
wsl -d Ubuntu -u root -- bash -c "tr -d '\r' < /mnt/c/<path>/tools/provision/build-box.sh > /tmp/build-box.sh && bash /tmp/build-box.sh"
```

Re-runnable. It installs; it does not remove or reconfigure anything it did
not install, and it starts dockerd without changing the machine's boot
behaviour.

## What is on it

| Tool | Installed | Pinned to | Status |
|---|---|---|---|
| Docker | 29.1.3 | — | running |
| Docker Compose | 2.40.3 | — | |
| Go | 1.22.2 | — | for the E1 stripped binary |
| Maven | 3.8.7 | — | host builds only; the image uses its own |
| Java (host) | OpenJDK 21.0.12 | — | the image uses Corretto 25 |
| haproxy (host) | 2.8.16 | — | the Tier A LB runs in a container |
| SoftHSM2 | 2.6.1 | — | P11 (HSM half) |
| YARA | 4.5.0 | — | P12 |
| AWS CLI | 1.46.1 | — | P11 (KMS half); `pip install awscli` into a dedicated venv |
| LocalStack | 3.0.2 (image tag `:3.0`) | — | P11 (KMS half) fixture recording only — not a real AWS account; see DEV-011. `latest` tag refuses to start without a paid auth token, recorded as a fact, not assumed |
| **semgrep** | **1.99.0** | 1.99.0 | **MATCH** |
| **sslyze** | **6.2.0** | 6.2.0 | **MATCH** |
| **trivy** | **0.74.0** | 0.74.0 | **MATCH** |
| openssl (host) | 3.0.13 | 3.5.4 | **MISMATCH** — see OI-014 |

All three scanners with recorded fixtures match their pin, so their parsers
run against the version they were validated on. The host OpenSSL does not —
that is OI-014, and it matters less than it looks, because the interesting
TLS work happens inside containers that carry OpenSSL 3.5.8.

`semgrep` and `sslyze` live in `/opt/pramana-tools` (a venv) and are
symlinked into `/usr/local/bin`. They are kept out of the system Python
because Ubuntu 24.04 marks it externally managed (PEP 668).

## Running the Tier A reference enterprise

```bash
cd ecdat-harness/harness/compose
docker compose up -d
```

Two services: `payment-gateway` (a Spring Boot **batch** app — it starts,
prints its config-chain result, and exits 0; it is not a server) and
`edge-lb` (HAProxy, terminates TLS).

The network is `internal: true` per harness H6 ("no egress"), so **the
endpoint is not reachable from the host**. That is correct, not a bug: probe
it from a container on the same network, which is also the only honest
`probe_vantage` to record.

```bash
NET=ecdat-harness-tier-a_payments-internal
IP=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$v.IPAddress}}{{end}}' ecdat-harness-tier-a-edge-lb-1)
docker run --rm --network "$NET" alpine/openssl s_client -connect "$IP:8443" -brief </dev/null
```

### WSL lifecycle gotcha

Start the stack and reach it in **one** `wsl` invocation. When the last
process in a WSL session exits, the distro can terminate and take dockerd —
and therefore the containers — with it. A stack started in one call and
probed in the next can be found cleanly exited (code 0) in between, which
looks like a crash and is not one.

## First live measurement (2026-09-19)

The first real handshake this project has ever taken, from a container on the
internal network:

```
Protocol version:          TLSv1.3
Ciphersuite:               TLS_AES_256_GCM_SHA384
Negotiated TLS1.3 group:   X25519MLKEM768
Peer certificate:          O=Harness Payments, CN=pay-edge
Signature type:            ecdsa_secp256r1_sha256
```

Reproduced 3/3. Two follow-up probes complete the picture:

| Probe | Result |
|---|---|
| Client offers everything | negotiates **X25519MLKEM768** (hybrid) |
| Client offers **only X25519** | handshake still completes — **classical is still accepted** |
| Client forces TLS 1.2 | `ECDHE-ECDSA-AES128-GCM-SHA256`, matching `haproxy.cfg` |

This is the entire thesis, measured, on the first endpoint we ever probed:

- `haproxy.cfg` names only classical TLS 1.2 ciphers. Read as configuration,
  this surface is classical — **INFERRED**.
- The wire negotiates a hybrid post-quantum group — **OBSERVED**, and the
  configuration never said so. The `ciphers` directive governs TLS ≤1.2 only;
  TLS 1.3 group selection fell through to the container's OpenSSL 3.5.8
  defaults.
- **But classical is still accepted.** Under §5.7 that is
  `classical_still_accepted = true`, so the exposure clock **does not stop**.
  The row earns the **PARTIAL** qualifier and stays BLEEDING.

A tool that read the config would have said "classical". A tool that took one
handshake and stopped would have said "already migrated". Both would be
wrong, and the second more dangerously than the first.
