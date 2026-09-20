# pkcs11-tool (OpenSC 0.25.0~rc1) against SoftHSM2 2.6.1 — recorded fixtures (2026-09-20)

**Exact versions:** `pkcs11-tool` from Ubuntu package `opensc-pkcs11 0.25.0~rc1-1ubuntu0.2`
(`dpkg -l | grep opensc`); `softhsm2-util --version` → `2.6.1` (already pinned per
`docs/build-box.md`, provisioned for phase P11).

**Setup (real, not simulated):** a fresh, user-scoped SoftHSM2 token was initialised — no root
required, `SOFTHSM2_CONF` pointed at a token directory under the build user's home directory
(`softhsm2-util --init-token --free --label pramana-fixture-token --pin 1234 --so-pin 5678`) —
then two real key pairs were generated **inside the token** via `pkcs11-tool --keypairgen`: one
RSA-2048 (`label=pramana-rsa-sign, id=01`) and one EC P-256 (`label=pramana-ec-p256, id=02`).

**No private key bytes exist outside the token at any point.** Every object listing below shows
`Access: sensitive, always sensitive, never extractable, local` on both private key objects —
that is PKCS#11's own attribute set confirming the key never left the module in plaintext; this
adapter (P11) reads exactly this metadata and nothing else, matching CLAUDE.md's hard rule ("no
private key / secret bytes ... store location + fingerprint only") and the plan's "no key
material ever" line for this surface.

**Exact commands:**
```
pkcs11-tool --module $MOD --login --pin 1234 --keypairgen --key-type rsa:2048 \
  --label pramana-rsa-sign --id 01
pkcs11-tool --module $MOD --login --pin 1234 --keypairgen --key-type EC:prime256v1 \
  --label pramana-ec-p256 --id 02
pkcs11-tool --module $MOD --list-slots
pkcs11-tool --module $MOD --list-objects                       # unauthenticated: public objects only
pkcs11-tool --module $MOD --login --pin 1234 --list-objects    # authenticated: private + public
pkcs11-tool --module $MOD --list-mechanisms
```
(`$MOD` = `/usr/lib/softhsm/libsofthsm2.so`, the SoftHSM2 PKCS#11 module.)

**Files:**
- `keygen-rsa.log`, `keygen-ec.log` — key generation output (object attributes right after creation)
- `list-slots.txt` — slot/token info: label, manufacturer, serial number, PIN state
- `list-objects-public.txt` — objects visible **without** authenticating: public keys only, no
  usage/access detail on the private halves
- `list-objects-authenticated.txt` — objects visible **after** login: adds the private key
  objects, each showing `never extractable`
- `list-mechanisms.txt` — every algorithm/mechanism this token instance supports (a real,
  measured capability list, not a static claim about what SoftHSM2 supports in general — a real
  card/HSM may support a different subset)

**What this proves, adapter-design-relevant:** the unauthenticated listing (`list-objects-public.txt`)
is the honest ceiling for a scan that never has the PIN — it sees the EC/RSA public keys, their
labels, IDs and sizes, but nothing about the private counterpart's existence or attributes. An
adapter that only has read access to a slot without a PIN must report exactly that reduced
visibility, not silently degrade to reporting nothing, and must not claim `never extractable`
about a private key it was never shown.
