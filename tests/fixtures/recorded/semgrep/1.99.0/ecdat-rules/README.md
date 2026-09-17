# semgrep 1.99.0 with ECDAT's own rules — recorded fixtures (2026-09-17)

These are runs of **`rules/semgrep/crypto-inventory-java.yaml`** (ECDAT's own
inventory rules), not of the Semgrep Registry. The registry run recorded in the
parent directory is kept for contrast: with `--config=auto` the same Tier A Java
tree yielded **one** finding (a weak-hash warning); with these rules it yields
**five**, including the three legitimate call sites registry rules ignore.

**Why our own rules exist:** registry rules flag *insecure* crypto. ECDAT needs
an *inventory* of all crypto, secure included. Owning the rules also means ECDAT
ships no registry rule content, so the Semgrep Rules License v1.0 (13 Dec 2024)
does not reach it, and the same file runs on Opengrep.

**Tool version:** `semgrep --version` → `1.99.0`, run inside WSL Ubuntu (semgrep
does not install on native Windows Python — see the parent README).

**Date run:** 2026-09-17

**Exact commands** (cwd = the `ecdat` repository root, so `check_id` comes out
repo-relative as `rules.semgrep.<rule-id>` rather than carrying an absolute
machine path — the adapter matches on that stable id):

```bash
semgrep --config rules/semgrep/crypto-inventory-java.yaml \
  --json --metrics=off --disable-version-check \
  --output <out>/tier-a-java.raw.json <harness>/targets/payments/payment-gateway/src

semgrep --config rules/semgrep/crypto-inventory-java.yaml \
  --json --metrics=off --disable-version-check \
  --output <out>/no-crypto-control.raw.json <harness>/targets/controls/no-crypto-service

semgrep --config rules/semgrep/crypto-inventory-java.yaml \
  --json --metrics=off --disable-version-check \
  --output <out>/argument-forms.raw.json rules/semgrep/testdata/java
```

`--metrics=off` is the one deliberate difference from the parent directory's
registry run: these rules are local, so nothing needs to be reported to
semgrep.dev, and the run is fully offline and reproducible.

## `tier-a-java.raw.json` — the payments application's Java source

`paths.scanned` = 6 files, `results` = 5, `errors` = 0.

| Rule | File | Line | Capture |
|---|---|---|---|
| `crypto-call-nonliteral-algorithm` | `KeyWrapService.java` | 25 | `$ARG = props.getTransformation()` |
| `crypto-call-literal-algorithm` | `WebhookSigner.java` | 17 | `$ALGO = HmacSHA256` |
| `crypto-call-literal-algorithm` | `TokenVault.java` | 22 | `$ALGO = AES/GCM/NoPadding` |
| `crypto-call-literal-algorithm` | `LegacyCardHash.java` | 21 | `$ALGO = MD5` |
| `crypto-config-property-binding-declaration` | `CryptoProperties.java` | 12 | `$PREFIX = "pay.keywrap"` |

The first row is the load-bearing one: the config-driven call site is classified
as **non-literal**, so the algorithm is not observable in source and must not be
reported as observed. That is the distinction the whole source surface rests on.

Note `$ALGO` comes back **without** surrounding quotes (the quotes are in the
rule pattern, not the metavariable) while `$PREFIX` comes back **with** them
(its pattern has no quotes). The adapter must not assume one convention.

## `no-crypto-control.raw.json` — the zero-crypto negative control

`results` = 0 **and `paths.scanned` = 0**. Both numbers matter: these are Java
rules and the control is a Python service, so Semgrep looked at nothing. Zero
findings here means *did not look*, not *clean*. An adapter that reports this as
"scanned, no crypto found" fails harness §7.3 TRAP-07 ("silence != scanned").
The honest report is that this language is not covered by this ruleset.

## `argument-forms.raw.json` — rule-behaviour corpus

Run against `rules/semgrep/testdata/java/ArgumentForms.java`, which exists to
exercise argument forms no single real project contains. `results` = 7 over 1
file. What it pins down:

- **the partition holds** — all five algorithm-service call sites are classified
  by exactly one of the two algorithm rules; none is dropped;
- **a constant-propagated literal does not vanish** (line 22): Semgrep resolves
  `static final String ALG` and reports the value, while `extra.lines` still
  shows `Cipher.getInstance(ALG)`. Statically determined, but not written at the
  call site — the adapter can tell the difference by checking whether the
  captured value appears in the matched line, and must do that check
  transiently, never persisting the line;
- **a concatenation stays non-literal** (line 27, `$ARG = "AES/"+mode`);
- **a protocol is not an algorithm** (line 42): `SSLContext.getInstance("TLSv1.3")`
  matches `crypto-call-literal-protocol`, so it can never populate an algorithm
  field;
- **an explicit provider is additive, not a second call site** (line 47): two
  results at the same line/column, one for the algorithm and one for the
  provider. The adapter correlates them by `(path, line, column)` and must not
  emit two findings.

A note on `$CLASS`: its `abstract_content` comes back repeated
(`"Cipher Cipher Cipher"`). Do not use it for service identity — the rule id
already encodes the service kind, which is why the rules are split that way.
