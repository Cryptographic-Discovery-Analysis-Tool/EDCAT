# Evidence-gate experiments

Standalone, disposable experiments for Lock §6 / harness §16.3's evidence gate. Not domain
code — nothing here is imported by `src/ecdat`. Results are recorded in
[docs/experiments.md](../docs/experiments.md); see also
[docs/open-issues.md#oi-002](../docs/open-issues.md) for why these currently count as
preliminary observations, not gate results.

- `PRV-T1-oaep-provider/` — SunJCE vs Bouncy Castle OAEP MGF1 digest and cross-decryption.
  `javac -cp lib/bcprov-jdk18on-1.86.jar OaepProviderTest.java && java -cp ".;lib/bcprov-jdk18on-1.86.jar" OaepProviderTest`
- `PRV-T2-keygen-defaults/` — unsized `KeyGenerator`/`KeyPairGenerator` defaults.
  `javac KeygenDefaults.java && java KeygenDefaults`
- `PRV-T3-node-openssl/` — Node bundled OpenSSL vs system `openssl_conf` provider activation.
  See docs/experiments.md EXP-004 for the exact commands (env var + flag combinations).
