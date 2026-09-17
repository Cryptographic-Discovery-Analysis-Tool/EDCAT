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
