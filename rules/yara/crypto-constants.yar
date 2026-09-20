/*
  Pramana's own YARA rules for compiled-binary crypto inventory (P12; stack
  decision "Binaries | YARA constants + readelf/strings; family only").

  These match PUBLISHED, PUBLIC-DOMAIN algorithm constants from their own
  government/IETF standards documents -- the same technique used by
  findcrypt/CAPA/Detect-It-Easy-style signature databases. A match says only
  "this family's reference tables are present in this binary" (RES-003/004,
  CUS-004, PAY-009/010 in scope). It is never a purpose, usage, or security
  verdict, and it is never RSA/ECDSA detection -- those have no fixed
  constant table to match (recorded as an explicit limitation, not silently
  skipped: see the "not detectable by constants" note in
  docs/PRAMANA_FINAL_2_Implementation_Plan_and_Rating.md §3 "Binaries" row).

  Recorded against real Tier A material 2026-09-20: matches libcrypto.so.3
  (OpenSSL 3.5.8) inside the tier-a-edge-lb container four times (both AES
  encrypt/decrypt table copies at adjacent offsets); does NOT match the
  haproxy binary itself, which only dynamically links libssl.so.3/
  libcrypto.so.3 rather than embedding the tables -- see
  tests/fixtures/recorded/yara/4.5.0/README.md for the full recorded run.
*/

rule Pramana_AES_Rijndael_Sbox
{
    meta:
        family = "AES"
        basis = "FIPS-197 Appendix A forward S-box, first 64 of 256 bytes"
    strings:
        $sbox_fwd = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
                      ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
                      b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
                      04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75 }
    condition:
        $sbox_fwd
}

rule Pramana_SHA256_InitialHash
{
    meta:
        family = "SHA-256"
        basis = "FIPS-180-4 5.3.3 initial hash value H(0), first four 32-bit words; both byte orders matched since object code may store the constant either way"
    strings:
        $h0_be = { 6a 09 e6 67 bb 67 ae 85 3c 6e f3 72 a5 4f f5 3a }
        $h0_le = { 67 e6 09 6a 85 ae 67 bb 72 f3 6e 3c 3a f5 4f a5 }
    condition:
        any of them
}
