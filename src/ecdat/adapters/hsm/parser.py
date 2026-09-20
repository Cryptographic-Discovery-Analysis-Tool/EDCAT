"""Parser for `pkcs11-tool`'s plain-text output (P11 -- HSM/PKCS#11 metadata half;
spec §3 row "HSM/KMS").

`pkcs11-tool` has no JSON mode -- the recorded fixtures under
tests/fixtures/recorded/pkcs11-tool/ are its real, only available output
format, and this parser is written only against them (CLAUDE.md
anti-hallucination rule).

Three listings, three shapes:

* `--list-slots`  -- one block per slot, `key : value` lines, used only to
  identify the token (label, manufacturer, model, serial number) so a Finding
  can name where it came from.
* `--list-objects` [--login] -- one block per PKCS#11 object, headed by
  `Public Key Object; <family> ...` or `Private Key Object; <family>`,
  followed by indented attribute lines.
* `--list-mechanisms` -- one line per supported mechanism, `NAME, attr, ...`.

**The one fact this module exists to get right:** a private key object's
`Access:` line either does or does not contain the literal words
`never extractable`. That presence/absence is read here and nowhere else is
key material read, inferred, or represented -- there is no field on
`ParsedPkcs11Object` that could hold key bytes, only the token's own
attribute assertions about the object.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


class Pkcs11ParseError(ValueError):
    """`pkcs11-tool` output we cannot read. Carries no captured bytes."""


# --- --list-slots -------------------------------------------------------------

_SLOT_HEADER = re.compile(r"^Slot\s+(?P<num>\d+)\s*\((?P<hex>0x[0-9a-fA-F]+)\)\s*:")
_KV_LINE = re.compile(r"^(?P<key>[A-Za-z][\w /]*?)\s*:\s*(?P<value>.*)$")


@dataclass(frozen=True)
class ParsedSlot:
    """One slot block from `--list-slots`. Identity only -- no attempt is
    made here to enumerate that slot's objects; `parse_objects` does that
    separately, from a different invocation's output."""

    slot_num: str
    slot_hex: str
    token_label: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    serial_number: str | None = None
    login_required: bool | None = None
    raw_flags: tuple[str, ...] = ()

    @property
    def has_token(self) -> bool:
        """A slot with no `token label` line is uninitialised (e.g. an empty
        slot) or reports only `token state: uninitialized` -- either way
        there is no token identity to attach a Finding's surface to."""
        return self.token_label is not None


def parse_slots(text: str) -> tuple[ParsedSlot, ...]:
    """Every slot block in a `--list-slots` listing, in order."""
    if not text.strip():
        raise Pkcs11ParseError("empty --list-slots output")

    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in text.splitlines():
        if _SLOT_HEADER.match(line):
            if current is not None:
                blocks.append(current)
            current = [line]
        elif current is not None:
            current.append(line)
    if current is not None:
        blocks.append(current)

    if not blocks:
        raise Pkcs11ParseError("no 'Slot N (...)' block found in --list-slots output")

    slots: list[ParsedSlot] = []
    for block in blocks:
        header = _SLOT_HEADER.match(block[0])
        assert header is not None  # guaranteed by how `blocks` was built
        fields: dict[str, str] = {}
        for line in block[1:]:
            match = _KV_LINE.match(line.strip())
            if match:
                fields[match.group("key").strip().lower()] = match.group("value").strip()

        flags_text = fields.get("token flags")
        raw_flags = (
            tuple(part.strip() for part in flags_text.split(",")) if flags_text else ()
        )
        slots.append(
            ParsedSlot(
                slot_num=header.group("num"),
                slot_hex=header.group("hex"),
                token_label=fields.get("token label"),
                manufacturer=fields.get("token manufacturer"),
                model=fields.get("token model"),
                serial_number=fields.get("serial num"),
                login_required=("login required" in raw_flags) if raw_flags else None,
                raw_flags=raw_flags,
            )
        )
    return tuple(slots)


def primary_slot(slots: tuple[ParsedSlot, ...]) -> ParsedSlot | None:
    """The first slot that actually carries a token. `--list-slots` also
    reports empty slots (e.g. an uninitialised second slot); those have no
    identity to report and are never a scan target."""
    for slot in slots:
        if slot.has_token:
            return slot
    return None


# --- --list-objects -------------------------------------------------------------

_OBJECT_HEADER = re.compile(
    r"^(?P<kind>Public Key Object|Private Key Object);\s*"
    r"(?P<family>RSA|EC)"
    r"(?:\s+EC_POINT)?"
    r"(?:\s+(?P<bits>\d+)\s+bits)?\s*$"
)
_EC_PARAMS = re.compile(r"EC_PARAMS:\s*\S+\s*\(OID\s+(?P<oid>[\d.]+)\)")
_USING_SLOT = re.compile(r"^Using slot\b")

#: The one boolean-ish fact this whole adapter exists to surface: PKCS#11's
#: own confirmation that a private key never left the token in plaintext.
_NEVER_EXTRACTABLE = "never extractable"


@dataclass(frozen=True)
class ParsedPkcs11Object:
    """One object block from `--list-objects`.

    No field here can hold key material. `key_size_bits` and `curve_oid` are
    populated only for Public Key Object blocks (the only ones that print
    them); `never_extractable` is populated only for Private Key Object
    blocks (the only ones whose `Access:` line ever states it). A field left
    at its default was never printed for that block -- it is not asked for
    and not guessed.
    """

    object_kind: str  # "Public Key Object" | "Private Key Object"
    algorithm_family: str  # "RSA" | "EC"
    label: str | None = None
    key_id: str | None = None
    usage: tuple[str, ...] = ()
    access: tuple[str, ...] = ()
    key_size_bits: int | None = None
    curve_oid: str | None = None
    never_extractable: bool | None = None

    @property
    def is_private(self) -> bool:
        return self.object_kind == "Private Key Object"


def parse_objects(text: str) -> tuple[ParsedPkcs11Object, ...]:
    """Every object block in a `--list-objects` listing, in order.

    Returns an empty tuple for a listing that genuinely has no objects (a
    freshly-initialised token with nothing generated yet); that is a real,
    distinct outcome from a listing this parser cannot read at all, which
    raises `Pkcs11ParseError` instead.
    """
    if not text.strip():
        raise Pkcs11ParseError("empty --list-objects output")

    lines = [line for line in text.splitlines() if not _USING_SLOT.match(line)]

    blocks: list[list[str]] = []
    current: list[str] | None = None
    for line in lines:
        if _OBJECT_HEADER.match(line.strip()):
            if current is not None:
                blocks.append(current)
            current = [line]
        elif current is not None:
            current.append(line)
    if current is not None:
        blocks.append(current)

    objects: list[ParsedPkcs11Object] = []
    for block in blocks:
        header = _OBJECT_HEADER.match(block[0].strip())
        assert header is not None  # guaranteed by how `blocks` was built
        kind = header.group("kind")
        family = header.group("family")
        bits = int(header.group("bits")) if header.group("bits") else None

        label: str | None = None
        key_id: str | None = None
        usage: tuple[str, ...] = ()
        access: tuple[str, ...] = ()
        curve_oid: str | None = None

        for line in block[1:]:
            stripped = line.strip()
            if (match := re.match(r"^label:\s*(?P<v>.*)$", stripped)):
                label = match.group("v").strip()
            elif (match := re.match(r"^ID:\s*(?P<v>.*)$", stripped)):
                key_id = match.group("v").strip()
            elif (match := re.match(r"^Usage:\s*(?P<v>.*)$", stripped)):
                usage = tuple(part.strip() for part in match.group("v").split(","))
            elif (match := re.match(r"^Access:\s*(?P<v>.*)$", stripped)):
                access = tuple(part.strip() for part in match.group("v").split(","))
            elif (match := _EC_PARAMS.search(stripped)):
                curve_oid = match.group("oid")
            # Any other line (e.g. `EC_POINT:` raw hex) carries only the
            # PUBLIC point and is not part of what this adapter models;
            # ignored deliberately, not because it was not seen.

        never_extractable = (_NEVER_EXTRACTABLE in access) if kind == "Private Key Object" else None

        objects.append(
            ParsedPkcs11Object(
                object_kind=kind,
                algorithm_family=family,
                label=label,
                key_id=key_id,
                usage=usage,
                access=access,
                key_size_bits=bits if kind == "Public Key Object" and family == "RSA" else None,
                curve_oid=curve_oid if kind == "Public Key Object" and family == "EC" else None,
                never_extractable=never_extractable,
            )
        )
    return tuple(objects)


# --- --list-mechanisms ----------------------------------------------------------

_SUPPORTED_MECHANISMS_HEADER = re.compile(r"^Supported mechanisms:\s*$")


def parse_mechanisms(text: str) -> tuple[str, ...]:
    """The raw mechanism-name token of every line in a `--list-mechanisms`
    listing, in the order the token reported them.

    This is a capability list -- what the token *supports* -- and callers
    must not present it as what is *in use*; that labelling is the caller's
    responsibility (the fixture README calls this out explicitly), not
    something this parser can enforce.
    """
    if not text.strip():
        raise Pkcs11ParseError("empty --list-mechanisms output")

    names: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or _USING_SLOT.match(stripped) or _SUPPORTED_MECHANISMS_HEADER.match(stripped):
            continue
        name = stripped.split(",", 1)[0].strip()
        if name:
            names.append(name)

    if not names:
        raise Pkcs11ParseError("no mechanism lines found in --list-mechanisms output")
    return tuple(names)
