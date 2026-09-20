# AWS KMS via LocalStack 3.0.2 — recorded fixtures (2026-09-20)

**This is LocalStack, not a real AWS account.** No real AWS credentials or
account were used or are available in this environment (checked: no
`~/.aws/`, no `AWS_*` environment variables, no `aws` CLI, on either the
Windows host or the Linux build box — see `docs/deviations.md` DEV-011 for
the full record of that check and why LocalStack was used instead).
LocalStack is a real, running implementation of the AWS API surface — every
byte below is a real HTTP response from a real running service, hit with
the real `aws` CLI, not hand-written — but it is not a genuine cloud
account, and every place this fact matters (in code, in docs, in the CLI's
own help text) says so explicitly. `adapters/kms/adapter.py`'s live path
talks to the *real* `aws kms` API surface unchanged — pointed at LocalStack
here only via `--endpoint-url`, which a real AWS account never needs.

**Exact setup:**
```
docker run -d --name localstack-kms -p 4566:4566 -e SERVICES=kms \
  -e ACTIVATE_PRO=0 localstack/localstack:3.0
```
(The `latest` tag, tried first, refused to start at all without a paid
LocalStack auth token — `License activation failed`, exit code 55. `:3.0` is
the last tag confirmed to run KMS under the free/community license with no
token, recorded here as a fact about the image, not a guess.)

**Exact AWS CLI version:** `aws-cli/1.46.1 Python/3.12.3 Linux/... botocore/1.43.62`
(installed via `pip install awscli` into a dedicated venv — see
`docs/build-box.md` for the provisioning entry).

**Exact commands** (`AWS_ACCESS_KEY_ID=test AWS_ACCESS_KEY_ID=test` and
`AWS_DEFAULT_REGION=us-east-1` — LocalStack does not validate these, any
non-empty values satisfy the CLI's own precondition that credentials be
present; this is specific to a local emulator and is never how a real
account is authenticated):
```
aws --endpoint-url=http://localhost:4566 kms create-key \
  --description "..." --key-usage ENCRYPT_DECRYPT --key-spec SYMMETRIC_DEFAULT
aws --endpoint-url=http://localhost:4566 kms create-key \
  --description "..." --key-usage SIGN_VERIFY --key-spec ECC_NIST_P256
aws --endpoint-url=http://localhost:4566 kms create-key \
  --description "..." --key-usage SIGN_VERIFY --key-spec RSA_2048
aws --endpoint-url=http://localhost:4566 kms describe-key --key-id <id>
aws --endpoint-url=http://localhost:4566 kms get-public-key --key-id <id>
aws --endpoint-url=http://localhost:4566 kms list-keys
aws --endpoint-url=http://localhost:4566 kms list-aliases
aws --endpoint-url=http://localhost:4566 kms describe-key --key-id 00000000-0000-0000-0000-000000000000
```

**Files:**
- `describe-key-symmetric.json`, `describe-key-ecc.json`, `describe-key-rsa.json`
  — real `describe-key` output for one key of each shape this surface cares
  about: a symmetric encrypt/decrypt key (no public key exists to export),
  and two asymmetric signing keys (ECC and RSA).
- `get-public-key-ecc.json` — the real, actual DER-encoded SubjectPublicKeyInfo
  for the ECC key, base64-encoded exactly as AWS's own API returns it. **This
  is the one field genuinely comparable to `certs-x509`'s `spki_sha256`** --
  AWS's own docs describe `GetPublicKey`'s `PublicKey` field as "DER-encoded
  X.509 public key, also known as SubjectPublicKeyInfo (SPKI)", the exact
  same encoding `certs/parser.py` hashes -- so `adapters/kms/parser.py`
  base64-decodes it and SHA-256-hashes the raw bytes directly, no
  re-derivation needed (unlike `images/certmatch.py`, which had to
  independently re-parse a whole certificate because cbomkit-theia gives no
  bytes at all).
- `list-keys.json`, `list-aliases.json` — account-level enumeration; a real
  operator run starts here, then calls `describe-key` per key found.
- `describe-key-not-found.stderr.txt` — the real error AWS's own API (and
  LocalStack's faithful reproduction of it) returns for an unknown key ID:
  `NotFoundException`. The adapter's live path must turn this into a
  per-target skip, not a crash -- a key that existed when `list-keys` ran
  and is gone by the time `describe-key` runs (deleted between calls) is a
  real, not hypothetical, race in a live account.

## What this proves, adapter-design-relevant

**No key material appears anywhere in any file here**, by construction of
the API itself, not by anything this project had to enforce: KMS never
exposes a private key over its API for a `CUSTOMER`-managed key (that is
the entire point of a managed key service), and a symmetric key has no
public half to export at all. This is the one surface in the whole project
where CLAUDE.md's "no private key / secret bytes" rule is enforced by AWS's
own API contract before this codebase ever gets a byte -- see
`adapters/kms/adapter.py`'s own module docstring for the corresponding,
much harder guarantee `hsm-pkcs11` has to make about a token that *can*
technically be asked to export a key (and refuses).
