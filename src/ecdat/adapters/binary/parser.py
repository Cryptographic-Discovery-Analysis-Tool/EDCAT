"""Parsers for the binary adapter's two probes (P12; stack decision
"Binaries | YARA constants + readelf/strings; family only").

Two independent, tolerant-of-nothing-found parsers:

* `parse_yara` reads `yara -s -w <rules> <target>` text output into
  (rule, family, offsets) matches. Zero matches is a normal, expected
  outcome -- the real recorded run against `haproxy` (which only
  dynamically links its crypto) produced none; see
  tests/fixtures/recorded/yara/4.5.0/README.md. This is parsed as an
  empty tuple, never an error.
* `parse_readelf_header` and `parse_readelf_dynamic` read the two `readelf`
  probes: the ELF header (class/type/machine) and the dynamic section's
  `NEEDED`/`SONAME` entries. `tests/fixtures/recorded/readelf/README.md`
  is the one that matters here: `libcrypto.so.3`'s own SONAME round-trips
  exactly to one of `haproxy`'s five NEEDED entries, which is the only
  honest way this adapter's caller (adapter.py) may say "haproxy links
  OpenSSL's crypto library" -- a link-time capability claim, not a usage
  claim, and a structurally weaker one than an embedded-constant match.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

#: rule_name -> family, read directly off rules/yara/crypto-constants.yar's
#: own `meta.family` lines (not invented here -- the rule file is the
#: citation). yara's plain-text CLI output does not carry rule meta unless
#: `-m` is passed, and this adapter's live argv does not pass it (see
#: adapter.py's `build_yara_argv`), so the rule-name -> family mapping is
#: carried in this module instead of parsed out of the tool's own output.
RULE_FAMILY: dict[str, str] = {
    "Pramana_AES_Rijndael_Sbox": "AES",
    "Pramana_SHA256_InitialHash": "SHA-256",
}

# A rule-match header line, e.g. "Pramana_AES_Rijndael_Sbox libcrypto.so.3".
# Anchored so that surrounding commentary in a recorded fixture (a shell
# prompt, an "exit=$?" echo, a parenthetical note -- see the real
# haproxy.no-match.txt fixture) cannot be mistaken for a match: none of
# those lines start with a bare identifier followed by whitespace and more
# text, and the caller additionally requires the identifier to be a known
# rule name before treating it as a header.
_HEADER_RE = re.compile(r"^(?P<rule>[A-Za-z_][A-Za-z0-9_]*)\s+(?P<target>\S.*)$")

# One `-s` verbose match line, e.g.
# "0x320800:$sbox_fwd: 63 7C 77 7B F2 6B 6F C5 ..."
_OFFSET_RE = re.compile(r"^0x(?P<offset>[0-9A-Fa-f]+):\$(?P<string_id>\S+):\s*[0-9A-Fa-f ]+$")


class BinaryProbeParseError(ValueError):
    """Probe output we cannot read. Carries no captured bytes."""


@dataclass(frozen=True)
class YaraMatch:
    """One rule's match against one binary.

    `offsets` are the `0x...`-formatted byte offsets from the `-s` verbose
    form, de-duplicated and in first-seen order; empty when the invocation
    did not use `-s` (the bare match line carries no offsets at all) or
    when the fixture simply has none to give.
    """

    rule_name: str
    family: str
    offsets: tuple[str, ...]


def parse_yara(text: str) -> tuple[YaraMatch, ...]:
    """Parse `yara -s -w <rules> <target>` output.

    Tolerant of zero matches -- empty input, or input containing no
    recognised rule-name header, both yield `()`. This is not an error
    case: it is exactly what the real recorded `haproxy` run produced
    (see module docstring), and treating "found nothing" as a parse
    failure would turn Pramana's single most important negative result
    into a crash instead of data.
    """
    rule_names: list[str] = []
    offsets_by_index: list[list[str]] = []
    current_index: int | None = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue

        offset_match = _OFFSET_RE.match(line)
        if offset_match and current_index is not None:
            offsets_by_index[current_index].append(f"0x{offset_match.group('offset')}")
            continue

        header_match = _HEADER_RE.match(line)
        if header_match and header_match.group("rule") in RULE_FAMILY:
            rule_names.append(header_match.group("rule"))
            offsets_by_index.append([])
            current_index = len(rule_names) - 1
            continue

        # Anything else (a shell prompt, an "(exit code 1 ...)" annotation,
        # an offset line with no header above it) is ignored rather than
        # raising -- real captured tool output carries exactly this kind of
        # surrounding text and a parser that refused it would be unusable
        # against the one fixture that proves the negative case works.

    return tuple(
        YaraMatch(
            rule_name=rule_name,
            family=RULE_FAMILY[rule_name],
            offsets=tuple(dict.fromkeys(offsets)),
        )
        for rule_name, offsets in zip(rule_names, offsets_by_index)
    )


# --- readelf ------------------------------------------------------------

_HEADER_FIELD_RE = re.compile(r"^\s*(?P<key>Class|Type|Machine):\s*(?P<value>.+)$")

# A dynamic-section entry line, shared shape for NEEDED and SONAME:
# " 0x0000000000000001 (NEEDED)             Shared library: [libssl.so.3]"
# " 0x000000000000000e (SONAME)             Library soname: [libcrypto.so.3]"
_DYNAMIC_ENTRY_RE = re.compile(
    r"^\s*0x[0-9A-Fa-f]+\s*\((?P<tag>[A-Za-z0-9_]+)\)\s*.*\[(?P<name>[^\]]+)\]\s*$"
)


@dataclass(frozen=True)
class ElfHeader:
    """`readelf -h`'s Class/Type/Machine, read as-is. `None` for a field
    this specific output did not carry (never guessed)."""

    elf_class: str | None
    elf_type: str | None
    machine: str | None


def parse_readelf_header(text: str) -> ElfHeader:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        match = _HEADER_FIELD_RE.match(line)
        if match:
            fields[match.group("key")] = match.group("value").strip()
    return ElfHeader(
        elf_class=fields.get("Class"),
        elf_type=fields.get("Type"),
        machine=fields.get("Machine"),
    )


@dataclass(frozen=True)
class DynamicEntries:
    """`readelf -d`'s NEEDED entries (this binary's own dynamic
    dependencies) and SONAME (this binary's own name as a shared object,
    when it has one). Tolerant of zero NEEDED entries -- a statically
    linked binary is a legitimate, if rare, observation, not a parse
    failure."""

    needed: tuple[str, ...]
    soname: str | None


def parse_readelf_dynamic(text: str) -> DynamicEntries:
    needed: list[str] = []
    soname: str | None = None
    for line in text.splitlines():
        match = _DYNAMIC_ENTRY_RE.match(line)
        if not match:
            continue
        tag = match.group("tag").upper()
        name = match.group("name")
        if tag == "NEEDED":
            needed.append(name)
        elif tag == "SONAME":
            soname = name
    return DynamicEntries(needed=tuple(dict.fromkeys(needed)), soname=soname)
