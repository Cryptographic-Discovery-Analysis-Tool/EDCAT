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

---

## Evidence gate: PRV-T1 / PRV-T2 / PRV-T3 (2026-09-17)

Runs Lock §6's PRV-T1/T2/T3 experiments and harness §16.3's freeze-gate tests 1–3, using the
revised test list from harness §16.1. **Classification: PRELIMINARY, not gate results** — see
[OI-002](open-issues.md#oi-002--no-harness-pinned-jdkbcnodeopenssl-build-exists-yet-2026-09-17):
the harness has not chosen a pinned JDK/Node/OpenSSL build yet (no payment-gateway image exists),
so these ran against whatever this machine had installed. Re-run against the harness's pinned
build once it exists, per Lock §6.1's own rule for what counts as a gate result.

Standalone code lives under `experiments/` (not `src/`, not domain code — see CLAUDE.md's `src/`
prohibition for this task).

### EXP-002 — PRV-T1: SunJCE vs Bouncy Castle OAEP, same transformation string (2026-09-17)

**Pinned versions used (this machine, not a harness pin — see OI-002):**
- JDK: `openjdk version "25.0.3" 2026-04-21 LTS`, `OpenJDK Runtime Environment Corretto-25.0.3.9.1 (build 25.0.3+9-LTS)`, `OpenJDK 64-Bit Server VM Corretto-25.0.3.9.1 (build 25.0.3+9-LTS, mixed mode, sharing)`
- Bouncy Castle: `bcprov-jdk18on-1.86` (latest release per Maven Central `maven-metadata.xml` at fetch time; `lastUpdated=20260911045244`), downloaded from `https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.86/bcprov-jdk18on-1.86.jar`, SHA-256 `2af190b300cbb0b35e248ccf5f4a06b6072030aeb3da7a98ec73abe5b4cb371f`, 7,224,011 bytes

**Code:** `experiments/PRV-T1-oaep-provider/OaepProviderTest.java`

**Commands:**
```bash
javac -cp "lib/bcprov-jdk18on-1.86.jar" OaepProviderTest.java
java -cp ".;lib/bcprov-jdk18on-1.86.jar" OaepProviderTest
```

**Raw output:**
```
java.version=25.0.3
java.vendor=Amazon.com Inc.
java.vm.name=OpenJDK 64-Bit Server VM
BC provider registered: 1.86
RSA keypair generated: 2048 bits (explicit, not under test here)
SunJCE cipher provider (encrypt): SunJCE
SunJCE encrypt: digestAlgorithm=SHA-256 mgfAlgorithm=MGF1 mgf1Digest=SHA-1
BC cipher provider (encrypt): BC
BC encrypt: digestAlgorithm=SHA-256 mgfAlgorithm=MGF1 mgf1Digest=SHA-256
SunJCE-encrypt -> SunJCE-decrypt: PRV-T1 test plaintext
BC-encrypt -> BC-decrypt: PRV-T1 test plaintext
--- cross-provider decryption ---
SunJCE-encrypt -> BC-decrypt: FAILED: org.bouncycastle.jcajce.provider.util.BadBlockException: unable to decrypt block
BC-encrypt -> SunJCE-decrypt: FAILED: javax.crypto.BadPaddingException: Padding error in decryption
--- explicit MGF1 param decrypt of SunJCE ciphertext ---
MGF1-SHA-1 (SunJCE): SUCCESS: PRV-T1 test plaintext
MGF1-SHA-256 (SunJCE): FAILED: javax.crypto.BadPaddingException: Padding error in decryption
```

**Supports or contradicts the Lock:** SUPPORTS. Lock §6.1 P-3 claims SunJCE's default MGF1 for
`RSA/ECB/OAEPWithSHA-256AndMGF1Padding` is SHA-1, and that explicit MGF1-SHA-1 decrypts while
explicit MGF1-SHA-256 fails — the raw output reproduces exactly that. Harness §16.1's "VERIFIED"
claim ("SunJCE uses SHA-1 for MGF1 ... Bouncy Castle ... use SHA-256") is also reproduced directly:
SunJCE's own `Cipher.getParameters()` reports `mgf1Digest=SHA-1`, BC's reports `mgf1Digest=SHA-256`,
for the identical transformation string, and cross-provider decryption fails in both directions.
This closes the "Bouncy Castle half still required" gap Lock §6.1 P-3 flagged.

### EXP-003 — PRV-T2: unsized AES/RSA/EC keygen defaults (2026-09-17)

**Pinned versions used (this machine, not a harness pin — see OI-002):** same JDK as EXP-002
(`openjdk 25.0.3`, Corretto-25.0.3.9.1).

**Code:** `experiments/PRV-T2-keygen-defaults/KeygenDefaults.java`

**Commands:**
```bash
javac KeygenDefaults.java
java KeygenDefaults
```

**Raw output:**
```
java.version=25.0.3
java.vendor=Amazon.com Inc.
java.vm.name=OpenJDK 64-Bit Server VM
AES unsized: keyLengthBits=256 provider=SunJCE
RSA unsized: modulusBits=3072 provider=SunRsaSign
EC unsized: fieldSizeBits=384 curveOrderBits=384 provider=SunEC
```

**Supports or contradicts the Lock:** SUPPORTS. Matches Lock §6.1 P-1/P-2 exactly (AES 256, RSA
3072, EC 384), now reproduced on JDK 25 in addition to the JDK 21 builds P-1/P-2 used, and with
the provider name recorded per the gate's explicit requirement ("Gate recording must include the
provider name returned by `getProvider()`"). Harness §16.2's "JDK version is tier-relevant
evidence" claim (default key sizes rose from JDK 19 on) is consistent with this: an unsized
`KeyGenerator("AES")` on this later JDK line is AES-256, not the Grover-tier AES-128 case Lock
§16.2 warns about for earlier lines — this experiment did not test an earlier JDK line to
directly observe that contrast (harness §16.3 lists that as an "optional contrast fixture", not
required).

### EXP-004 — PRV-T3: Node bundled OpenSSL vs system `openssl_conf` provider activation (2026-09-17)

**Pinned versions used (this machine, not a harness pin — see OI-002):**
- Node: `v24.14.1`, `process.versions.openssl=3.5.5`, `process.config.variables.node_shared_openssl=false` (statically bundled OpenSSL, not the system OpenSSL)
- System OpenSSL CLI (sanity/control only, not what Node uses): `OpenSSL 3.5.4 30 Sep 2025 (Library: OpenSSL 3.5.4 30 Sep 2025)`, mingw64 build shipped with Git for Windows

**Fixtures:**
- `experiments/PRV-T3-node-openssl/broken_openssl_conf.cnf` — `openssl_conf` app-name section
  (`[openssl_init]`) activates a provider whose `module` path does not exist; `nodejs_conf`
  app-name section (`[nodejs_init]`) activates a normal working `default` provider.
- `experiments/PRV-T3-node-openssl/good_openssl_conf.cnf` — control fixture where both sections
  are valid, to isolate any failure to "the broken section was read", not to
  "`--openssl-shared-config` itself is broken on this build".

**Commands and raw output:**

1. Sanity check that the broken config is genuinely broken when its `openssl_conf` app-name
   section is actually loaded (using the system OpenSSL CLI's `req`, which forces config load;
   plain `openssl version` / `openssl list -providers` did **not** force a load on this build and
   is not usable as a sanity check here):
   ```
   $ OPENSSL_CONF="C:\...\broken_openssl_conf.cnf" openssl req -new -x509 -newkey rsa:2048 -nodes -keyout /tmp/k2.pem -out /tmp/c2.pem -subj "/CN=test"
   Error allocating keygen context
   C8380000:error:0308010C:digital envelope routines:inner_evp_generic_fetch:unsupported:../openssl-3.5.4/crypto/evp/evp_fetch.c:375:Global default library context, Algorithm (rsaEncryption : 107), Properties (<null>)
   exit=1
   ```

2. Default Node (no `--openssl-shared-config`) with `OPENSSL_CONF` pointed at the same broken file:
   ```
   $ OPENSSL_CONF="C:\...\broken_openssl_conf.cnf" node -e "const crypto=require('crypto'); const {publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048}); console.log('RSA keygen OK, DER length='+publicKey.export({type:'spki',format:'der'}).length);"
   RSA keygen OK, DER length=294
   exit=0
   ```

3. `node --openssl-shared-config` with the same broken file and same script:
   ```
   $ OPENSSL_CONF="C:\...\broken_openssl_conf.cnf" node --openssl-shared-config -e "<same script>"
     #  C:\Program Files\Git\bin\..\usr\bin\bash.exe[6100]: std::shared_ptr<InitializationResultImpl> __cdecl node::InitializeOncePerProcessInternal(...) at src\node.cc:1221
     #  Assertion failed: ncrypto::CSPRNG(nullptr, 0)
   ----- Native stack trace -----
    1: 00007FF69FF6BADA EVP_MD_meth_get_input_blocksize+196378
    2: 00007FF69FFC5E06 node::InitializeOncePerProcess+2790
    3: 00007FF69FFC6EEC node::Start+156
    4: 00007FF6A0FE50C2 AES_cbc_encrypt+2546
    5: 00007FF6A1E58FF4 v8::base::UnsignedDivisionByConstant<unsigned __int64>+2833348
    6: 00007FFAC423CCB7 BaseThreadInitThunk+23
    7: 00007FFAC59AAD6C RtlUserThreadStart+44
   exit=134
   ```

4. Control: `node --openssl-shared-config` with the *valid* control fixture (`good_openssl_conf.cnf`),
   to confirm the flag itself doesn't crash on this build when the config it switches to is sound:
   ```
   $ OPENSSL_CONF="C:\...\good_openssl_conf.cnf" node --openssl-shared-config -e "<same script>"
   RSA keygen OK, DER length=294
   exit=0
   ```

**Supports or contradicts the Lock:** SUPPORTS. Harness §16.1 "VERIFIED: Node.js (>= 18.5) reads
the `nodejs_conf` section, not `openssl_conf`, unless `--openssl-shared-config`" is reproduced
directly: with the broken file, default Node succeeds (ignored `[openssl_init]`, used the valid
`[nodejs_init]`), while `--openssl-shared-config` fails hard (read `[openssl_init]`, which is
broken) — and command 4 rules out the alternative explanation that `--openssl-shared-config`
itself is what crashed. Note the *manner* of failure is stronger than the CI-check-shaped
"decrypt fails" signal used elsewhere: it is a hard process-initialization abort
(`ncrypto::CSPRNG` assertion), not a caught exception — recorded as-is, not softened.

---

## Evidence gate: E1–E4 / TOPO-X1–X3 (2026-09-17)

Runs the tools this task specified (pinned semgrep, sslyze-as-library, trivy, openssl) against
**Tier A targets** (harness §3/§13: `payment-gateway` + `edge-lb` + internal PKI + one negative
control; confirmed by grep — `PAY-001..008` and `INF-001`/`INF-017` all carry `tier: A`, and
`settlement-batch` — the harness's only *planted-weak-crypto* target — does **not** appear in any
Tier-A-tagged ground-truth asset, so it is out of scope for this run).

**Read first — reconciling the task's tool list against Lock §6's own E1–E4/TOPO-X1–X3
definitions**, because they don't fully overlap:

| ID | Lock §6 literal text | Executable against Tier A with the requested tools? |
|---|---|---|
| E1 | Trivy on a **stripped Go binary** | **No.** No Go toolchain on this machine, and the harness's only Go target (`targets/research/datalake-sync`) is Research domain, not Tier A. See [OI-008](open-issues.md#oi-008). Ran trivy against Tier A's actual artifacts instead, filed as supplemental, not E1. |
| E2 | YARA hits | **Not attempted.** YARA is not in this task's tool list (semgrep, sslyze, trivy, openssl). Not run, not faked. |
| E3 | sslyze **hybrid-group** reporting | **No.** Hybrid PQ key-exchange groups are only planted on `targets/infrastructure/pqc-edge`, which is Tier B, not Tier A. Tier A's edge-lb (`haproxy.cfg`) offers only classical `ECDHE-ECDSA-AES128-GCM-SHA256`/`ECDHE-RSA-AES256-GCM-SHA384`. See [OI-008](open-issues.md#oi-008). |
| E4 | OpenSSL seclevel on **weak certificates** | **Partially.** Tier A's PKI (harness §6) is deliberately strong (RSA-4096 root, ECDSA P-384/P-256) — there is no weak cert in Tier A to test seclevel *rejecting*. Ran seclevel mechanics against Tier A's real (strong) certs instead; see below and [OI-008](open-issues.md#oi-008). |
| TOPO-X1 | sslyze **SNI recording** | **Yes.** Tier A's edge-lb is exactly the SNI-relevant HAProxy TLS terminator. Executed below. |
| TOPO-X2 | BuildKit attestation retrieval by image store | **No.** No Docker on this machine (already tracked as [OI-007](open-issues.md#oi-007)). Not attempted. |
| TOPO-X3 | DER hash equality across PEM, DER, PKCS12 | **Yes.** Tier A's own PKI artifacts (`pay-edge` PEM cert, `gateway-p12` PKCS12 keystore) are exactly this material. Executed below. |

Nothing below is typed from memory: every value is read from a raw command-output file under
`tests/fixtures/recorded/<tool>/<version>/`, per CLAUDE.md's anti-hallucination rule.

### TOPO-X1 — sslyze SNI recording against Tier A's edge-lb (2026-09-17)

**Tool:** sslyze 6.2.0 (Python library API, not CLI, per this task's "sslyze (library)"
instruction). **Target substitution recorded:** the harness has no `haproxy` binary on this
machine ([OI-007](open-issues.md#oi-007)), so `openssl s_server` served the *exact* file HAProxy's
own config loads (`targets/payments/edge-lb/certs/pay-edge.pem`, produced by
`generate-pki.sh`) on `localhost:8443`.

**Code:** `tests/fixtures/recorded/sslyze/6.2.0/topo_x1_sni_probe.py`

**Command:** `python topo_x1_sni_probe.py > topo_x1_sni_probe.raw.json`

**Raw output:** `tests/fixtures/recorded/sslyze/6.2.0/topo_x1_sni_probe.raw.json`

**Finding:** sslyze 6.x sends the SNI value from `ServerNetworkLocation.hostname` — there is no
separate "SNI override" field in the connectivity result at this API surface; whatever hostname
you construct the `ServerNetworkLocation` with **is** the SNI value sent on the wire (confirmed
because the connection succeeded and the returned certificate's `subjectAltName` (`DNS:pay-edge`)
matches the hostname we set, i.e. sslyze connected using that exact SNI and the server picked the
matching cert). The scan result's `certificate_deployments_found[].leaf_san_dns` records the SAN
sslyze actually received back — that, cross-referenced with the `hostname` we supplied, is how
"which SNI got recorded against which observed cert" must be reconstructed by an ECDAT adapter:
sslyze does not hand back a labelled "SNI I sent" field distinct from the request object itself.
**Adapter-design implication:** the ECDAT sslyze adapter must persist the *request* hostname
alongside the *scan result* itself (they're two different objects in the library's API), not
assume the result payload alone carries the SNI used — this matters for TOPO-001/T7's identity
model (`{requested host, port, SNI sent, probe_vantage}` is what ECDAT asked for; it is not
reconstructable from the sslyze result object in isolation).

### TOPO-X3 — DER hash equality across PEM, DER, PKCS12 (2026-09-17)

**Tool:** openssl 3.5.4 (already present).

**Target:** Tier A's own PKI: `pay-edge` cert (PEM, and re-encoded DER) and the `gateway-p12`
keystore leaf cert (PKCS12, extracted back to PEM and DER).

**Commands and raw output:** `tests/fixtures/recorded/openssl/3.5.4/topo_x3_der_hash_equality/results.txt`

**Finding:** SHA-256 over canonical DER is identical across all three encodings — but only once
each form is actually run through `openssl x509 -outform DER` first. The raw PEM text that
`openssl pkcs12 -clcerts` emits directly (with `Bag Attributes` / `subject=` / `issuer=` comment
lines ahead of the PEM block) does **not** hash equal to the same certificate's canonical PEM —
confirming Lock §15.2 T6's "canonicalised first" qualifier is load-bearing, not decorative: a
naive whole-file hash of "the PEM I got out of the PKCS12 tool" is not a valid `same-object` check.

### E4 (partial) — OpenSSL seclevel against Tier A's real certs (2026-09-17)

**Tool:** openssl 3.5.4.

**Target:** Tier A PKI (`root-ca` RSA-4096, `int-ca-ecc` ECDSA P-384, `pay-edge` ECDSA P-256) via
the same `openssl s_server` substitute described under TOPO-X1.

**Commands and raw output:** `tests/fixtures/recorded/openssl/3.5.4/e4_seclevel_tier_a_certs/results.txt`

**Finding:** `openssl verify` accepts the full chain at default seclevel. Forcing
`@SECLEVEL=4` (192-bit minimum) into the client cipher string makes the connection fail
**before any network I/O** (`no ciphers available for max supported SSL/TLS version`) against
`pay-edge`'s P-256 ciphersuite — seclevel enforcement happens at local cipher-list construction,
not as a handshake-time rejection of the peer's cert. **This does not satisfy E4 as literally
written** (no weak cert exists in Tier A to test seclevel *rejecting* it) — see the gap table
above and [OI-008](open-issues.md#oi-008).

### E1 (supplemental, not the canonical experiment) — Trivy against Tier A artifacts (2026-09-17)

**Tool:** trivy 0.74.0 (downloaded pinned, see `tests/fixtures/recorded/trivy/0.74.0/README.md`
for the exact install command and SHA-256).

**Target:** `payment-gateway`'s built Spring Boot fat jar, and `no-crypto-service` (TRAP-07).

**Commands and raw output:** see `tests/fixtures/recorded/trivy/0.74.0/README.md` for the full
command sequence (four attempts, including one that failed and one mode switch).

**Findings:**
1. `trivy fs` against the payment-gateway directory (with its `pom.xml`) fails with a live
   `429 Too Many Requests` from Maven Central — `trivy fs`'s Maven support resolves the effective
   dependency tree over the network, which would fail identically inside the harness's declared
   no-egress internal network (H6). **Adapter-design implication:** a trivy-based pom.xml adapter
   cannot assume it can resolve Maven dependencies live from inside a deployment matching the
   harness's own network model.
2. `trivy fs` cannot see inside a standalone `.jar` file at all (0 language-specific files),
   whether pointed at the jar or its containing directory; `trivy rootfs` can (detects it as
   `Type: jar`, enumerates all 22 embedded dependency jars via `--list-all-pkgs`), including
   `org.bouncycastle:bcprov-jdk18on 1.86` bundled inside the fat jar. **This is real
   PRV-001-relevant evidence**: a provider library (Bouncy Castle) is present in the deployed
   artifact even though the payment-gateway's own `pom.xml`/source in this repo shows no direct
   BC usage — per Lock §4 "package presence = capability, never usage," this must be recorded as
   BC's *presence*, with `purpose: UNKNOWN` until a call site is found, not treated as "BC is
   used here." `fs` vs `rootfs` mode choice is therefore a real adapter-design decision, not
   interchangeable.
3. `trivy fs` against `no-crypto-service` finds nothing — correctly, since TRAP-07's
   `requirements.txt` is a comment-only stub with zero dependencies (verified directly).

**This is explicitly NOT Lock §6's E1** (Trivy on a stripped Go binary) — see the gap table above
and [OI-008](open-issues.md#oi-008) for why Tier A has no qualifying target for the real E1.

### semgrep (supplemental — not in Lock §6's E1–E4 table at all) — Tier A run (2026-09-17)

**Tool:** semgrep 1.99.0 (pinned; native-Windows install fails, see
`tests/fixtures/recorded/semgrep/1.99.0/README.md` — run inside WSL Ubuntu instead).

**Target:** `payment-gateway/src` (incl. TRAP-01) and `no-crypto-service` (TRAP-07).

**Command:** `semgrep --config=auto --json --output <file> <target>`

**Raw output:** `tests/fixtures/recorded/semgrep/1.99.0/e1_supplemental_*.raw.json`

**Findings:**
- Against `payment-gateway/src`: exactly one finding,
  `java.lang.security.audit.crypto.use-of-md5.use-of-md5` at
  `LegacyCardHash.java:21` — this is TRAP-01's planted dead-code MD5 call.
  TRAP-01's expected behaviour is "finding allowed (the call site itself is
  real)" plus "reachable: UNKNOWN or false" plus "must NOT appear in the risk
  queue as 'in use.'" **semgrep only produces the first part** — it has no
  reachability analysis and reports the call site with no indication it's
  dead code. Confirms harness OQ-5's own framing ("no reachability analysis
  ... `reachable` = UNKNOWN") is a real gap semgrep does not close by itself;
  an ECDAT adapter must apply the path-based/rule-based unreachability
  inference on top of semgrep's raw finding, not read reachability off
  semgrep's output.
- Against `no-crypto-service`: 0 findings out of 290 rules run on 3 files —
  consistent with TRAP-07's "zero crypto assets" expectation.

**Note — this is not part of Lock §6's evidence gate at all** (semgrep does
not appear in the E1–E4/TOPO-X1–X3 table; the table's only source-level tool
mentioned anywhere is trivy/sslyze/openssl/YARA). It was run because this
task's instructions named it explicitly. Recorded as supplemental
adapter-design evidence, not as satisfying any lettered/numbered gate item.
