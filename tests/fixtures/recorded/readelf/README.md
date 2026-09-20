# readelf (binutils, WSL Ubuntu default) — recorded fixtures (2026-09-20)

Same two real Tier A binaries as `tests/fixtures/recorded/yara/4.5.0/README.md` — read that file
first for provenance (source container, SHA-256 hashes). `readelf` here supplies the two things
YARA cannot: (a) the ELF header (confirms architecture/type honestly, rather than assuming), and
(b) the dynamic-dependency table, which is how a binary can carry a crypto family via linkage
without embedding any matchable constant itself (see the YARA README's "package presence vs
usage, one level down" note — haproxy is the concrete case).

**Exact commands:**
```
readelf -h haproxy | grep -E "Class|Machine|Type"
readelf -d haproxy | grep -i NEEDED
readelf -h libcrypto.so.3 | grep -E "Class|Machine|Type"
readelf -d libcrypto.so.3 | grep -i SONAME
strings libcrypto.so.3 | grep -iE "^OpenSSL [0-9]" | sort -u
```

**Files:**
- `tier_a_edge_lb.haproxy.header.txt`
- `tier_a_edge_lb.haproxy.dynamic-deps.txt`
- `tier_a_edge_lb.libcrypto.header.txt`
- `tier_a_edge_lb.libcrypto.soname.txt`
- `tier_a_edge_lb.libcrypto.version-string.txt`

**What this proves, adapter-design-relevant:** `libcrypto.so.3`'s SONAME (the name other binaries
reference at link time) round-trips exactly to one of `haproxy`'s five `NEEDED` entries — that
byte-for-byte string match is the only honest way this adapter may claim "haproxy uses OpenSSL's
crypto library", and even that is a *link-time capability* claim, not a *usage* claim, per the
same "package presence != usage" rule the P5 packages adapter enforces. The embedded
`OpenSSL 3.5.8` version banner (a plain ASCII string OpenSSL compiles into itself) is the only
reliable way to get a version number out of a stripped-of-symbols shared object; readelf's own
header carries no version field for this.
