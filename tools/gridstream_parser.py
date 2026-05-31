#!/usr/bin/env python3
"""GridStream packet parser — authoritative reference decoder.

Canonical, dependency-free decoder for Landis+Gyr GridStream sub-GHz RF frames
as deployed by Puget Sound Energy (PSE). It turns a captured frame (hex) into a
structured, fully-labelled decode: header, addresses, CI class, the COSEM-style
application layer (class_id, L+G calling convention, OBIS-like prefix, per-packet
seq/nonce, DIF/VIF), and CRC verification.

This module is the executable companion to ``docs/gridstream-protocol.md``: the
field offsets and on-the-wire constants encoded here are exactly those documented
there. Where the spec gives precise per-family offsets, the parser uses them; for
a COSEM-bearing frame outside the documented catalog it falls back to locating
the L+G ``09`` octet-string calling-convention marker.

Use as a library::

    from gridstream_parser import parse_frame
    f = parse_frame("80FF2AD5001D29...ED89")
    print(f.type_name, f.family, f.crc.ok)
    print(f.to_dict())

Or as a CLI::

    python gridstream_parser.py 80FF2AD5001D29...ED89      # decode one frame
    python gridstream_parser.py --json 80FF2A...           # JSON output
    python gridstream_parser.py --file ../capture/corpus.log  # decode a frame file
    cat ../capture/corpus.log | python gridstream_parser.py   # decode from stdin

CRC: CRC-16/CCITT, poly 0x1021, PSE init 0x142A, covering the CI byte through the
second-to-last byte (0x55/0xA5/0xD5 only). 0xD2 frames are not covered by this
CRC (CI=0x52 ends in an auth tag; the plaintext 0xD2 variants use a framing the
standard CRC does not check) and are reported with ``crc.covered = False``.
"""
from __future__ import annotations

import datetime
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Optional

SYNC = bytes([0x80, 0xFF, 0x2A])
OBIS_PREFIX = bytes.fromhex("20302D8480")  # L+G OBIS-like logical-name prefix

# CLI input tolerance: strip terminal colour codes and pull the hex out of a
# raw capture line ("[CRC: OK] <hex> Baudrate: ...") so the parser ingests SDR
# logs directly, not just bare-hex files.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_CRC_LINE = re.compile(r"\[CRC:\s?(?:OK|BAD)\]\s+([0-9A-Fa-f]+)")
_SYNC_HEX = re.compile(r"80FF2A[0-9A-Fa-f]+", re.I)


def _extract_hex(raw: str) -> Optional[str]:
    """Pull one frame's hex out of an input token or capture-log line.

    Tolerates ANSI colour codes, a leading ``[CRC: OK|BAD]`` tag, a trailing
    ``Baudrate:``/``SNR:``/``Pwr:`` metadata tail, spaced hex (``80 FF 2A ...``),
    and ``#`` comment / blank lines. Returns None when the line carries no frame.
    """
    s = _ANSI.sub("", raw).strip()
    if not s or s.startswith("#"):
        return None
    m = _CRC_LINE.search(s)
    if m:                                   # raw capture line: "[CRC: OK] <hex> Baudrate: ..."
        return m.group(1)
    compact = "".join(s.split())            # rejoin spaced hex ("80 FF 2A" -> "80FF2A")
    if re.fullmatch(r"[0-9A-Fa-f]+", compact):
        return compact                      # bare hex, contiguous or spaced
    m = _SYNC_HEX.search(compact)           # sync-prefixed run embedded in other text
    return m.group(0) if m else None

TYPE_NAMES = {
    0x55: "Broadcast",
    0xA5: "Scheduled beacon",
    0xD5: "Directed mesh",
    0xD2: "Directed mesh (5-byte header)",
}

# Specific CI meanings (doc: Frame Header → CI byte table). Prefer these over the
# high-nibble class when the exact value is known.
CI_NAMES = {
    0x21: "Directed data",
    0x22: "Directed data",
    0x29: "Directed data",
    0x30: "Broadcast",
    0x3C: "Scheduled beacon",
    0x51: "Status push (routine)",
    0x52: "Encrypted directed",
    0x53: "Directed (short)",
    0x55: "Status push (event-driven)",
    0x81: "Bulk transfer",
}
# High-nibble frame class (doc: CI byte, high nibble = frame class, ✓).
CI_CLASS = {0x2: "directed data", 0x3: "broadcast", 0x5: "status push", 0x8: "bulk transfer"}

# COSEM interface classes (doc: Application Layer → COSEM class IDs).
COSEM_CLASSES = {
    8: "Clock",
    9: "Script_table",
    10: "Schedule",
    11: "Special_days_table",
    12: "Association_SN",
    13: "L+G vendor extension",
    14: "L+G vendor extension",
    15: "Association_LN",
    16: "L+G vendor extension",
    17: "SAP_assignment",
    18: "Image_transfer",
    19: "IEC_local_port_setup",
    20: "L+G vendor extension",
}

DIF_DATA_LENGTH = {
    0x0: "no data", 0x1: "8-bit int", 0x2: "16-bit int", 0x3: "24-bit int",
    0x4: "32-bit int", 0x5: "32-bit real", 0x6: "48-bit int", 0x7: "64-bit int",
    0x8: "selection for readout", 0x9: "2-digit BCD", 0xA: "4-digit BCD",
    0xB: "6-digit BCD", 0xC: "8-digit BCD", 0xD: "variable length",
    0xE: "12-digit BCD", 0xF: "special functions",
}
DIF_FUNCTION = {0b00: "instantaneous", 0b01: "maximum", 0b10: "minimum", 0b11: "error"}


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------
def crc16_gridstream(data: bytes, init: int = 0x142A) -> int:
    """CRC-16/CCITT, poly 0x1021, byte-MSB-first, PSE init 0x142A.

    ``data`` is the CRC body only — the caller pre-strips the header and the
    2-byte CRC tail. Matches gr-smart_meters GridStream_impl::crc16.
    """
    crc = init
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def header_len_for(type_byte: int) -> int:
    """5-byte header for 0xA5/0xD2 (1-byte length); 6-byte for 0x55/0xD5."""
    return 5 if type_byte in (0xA5, 0xD2) else 6


def looks_like_lan_id(b4: bytes) -> bool:
    """Heuristic: does a 4-byte value carry a common meter network prefix?

    Meter LAN IDs in this deployment overwhelmingly start with 0x80/0x90/0x50.
    This is a quick display/triage check, NOT the structural definition of an
    address: the data collector/gateway uses a 0x40 prefix, and addresses are
    properly identified by *position* (see ``lan_ids``). Used only for
    human-facing field labels and best-effort graph extraction — never to decide
    what to anonymize.
    """
    return len(b4) == 4 and b4[0] in (0x80, 0x90, 0x50)


# Broadcast destination: 0x55 announcements address the whole network with this
# 7-byte all-ones-but-last address. It is not a node and is never a meter ID.
BCAST_DST = bytes([0xFF] * 6 + [0xFE])


def lan_addrs(p: bytes) -> dict:
    """The source/destination LAN IDs a frame carries, by *role*, located by
    *position*. Returns ``{"src": b4, "dst": b4}`` with only the roles a frame
    actually has (a beacon has no ``dst``; a broadcast's destination is the
    not-a-node broadcast address and is omitted).

    An address is identified by where it sits in the frame — its structural
    slot — not by guessing whether its bytes "look like" an ID. This is the
    canonical, heuristic-free way to extract addresses (the anonymizer and the
    mesh-topology graph both build on it); it returns the raw 4-byte slices with
    no prefix filter, so a collector/gateway with an unusual prefix (0x40) is
    returned like any meter.

    Geometry is keyed on frame *length*, not the type byte. The type byte
    (offset 3) lies outside CRC coverage, so a single bit-flip turns 0xD5 into
    0x55 (or back) on a frame that still passes CRC; reading by length-determined
    geometry recovers such a frame's real src/dst anyway and never mistakes
    payload bytes for an address. The 6-byte-header families (0x55/0xD5) carry
    either a broadcast destination + source (the len-41 announcement, whose
    broadcast destination is omitted here) or a dst+src pair (every directed
    frame); 0xA5 beacons carry only a source; 0xD2 carries no LAN IDs.
    """
    t = p[3]
    out = {}
    if t in (0x55, 0xD5):                              # 6-byte header
        if len(p) == 41 and p[7:14] == BCAST_DST:      # broadcast: source @14
            if len(p) >= 18:
                out["src"] = p[14:18]
        else:                                          # directed: dst @7, src @11
            if len(p) >= 11:
                out["dst"] = p[7:11]
            if len(p) >= 15:
                out["src"] = p[11:15]
    elif t == 0xA5 and len(p) >= 10:                   # beacon: source @6, no dst
        out["src"] = p[6:10]
    return out


def lan_ids(p: bytes) -> list:
    """Every LAN ID a frame carries (dst before src), located structurally.

    A thin wrapper over :func:`lan_addrs` that drops the role labels — the
    anonymizer mines the *set* of real IDs and does not care which is which.
    """
    a = lan_addrs(p)
    return [v for v in (a.get("dst"), a.get("src")) if v is not None]


def parse_dif(b: int) -> dict:
    """Parse a byte as an IEC 13757-3 DIF."""
    return dict(
        extension=bool(b & 0x80),
        function=DIF_FUNCTION[(b >> 5) & 0b11],
        function_bits=(b >> 5) & 0b11,
        storage=(b >> 4) & 0b1,
        data_len_code=b & 0x0F,
        data_len_name=DIF_DATA_LENGTH[b & 0x0F],
    )


def parse_vif(b: int) -> dict:
    """Parse a byte as a WMBus VIF (L+G unit mapping is non-standard)."""
    return dict(extension=bool(b & 0x80), code=b & 0x7F, low_nibble=b & 0x0F)


# ---------------------------------------------------------------------------
# Family catalog + field layouts
# ---------------------------------------------------------------------------
# Family is keyed by (type_byte, total_length). Within a family the CI byte may
# vary (e.g. 0xD5/len-23 carries CI 0x29 or 0x21) without changing the layout.
# Each entry: (human name, cosem_bearing).
FAMILIES = {
    (0xD5, 23): ("0xD5/len-17 — Short mesh control / keepalive", False),
    (0xD5, 28): ("0xD5/len-22 — Directed data", True),
    (0xD5, 29): ("0xD5/len-23 — Directed data variant", True),
    (0xD5, 26): ("0xD5/len-20 — Short directed", False),
    (0xD5, 31): ("0xD5/len-25 — Short directed (COSEM)", True),
    (0xD5, 34): ("0xD5/len-28 — Peer-to-peer directed data", True),
    (0xD5, 35): ("0xD5/len-29 — Rare mesh control", False),
    (0xD5, 77): ("0xD5/len-71 — Status push (richest payload)", True),
    (0xD5, 131): ("0xD5/len-125 — Bulk transfer (longest frame)", False),
    (0x55, 41): ("0x55/len-35 — Broadcast announcement", True),
    (0xA5, 23): ("0xA5/len-18 — Scheduled mesh beacon", False),
    (0xD2, 9): ("0xD2/len-9 — Directed (short, keepalive-like)", False),
    (0xD2, 10): ("0xD2/len-10 — Short directed control", False),
    (0xD2, 15): ("0xD2/len-15 — Plaintext COSEM", True),
    (0xD2, 21): ("0xD2/len-21 — Plaintext COSEM", True),
    (0xD2, 23): ("0xD2/len-23 — Encrypted directed (AEAD)", False),
}

# Field layout per (type, total_length): ordered (start, length, name, kind).
# Offsets are taken directly from docs/gridstream-protocol.md.
_LAYOUTS = {
    (0xD5, 23): [
        (0, 3, "sync", "sync"), (3, 1, "type", "type"), (4, 1, "reserved", "const0"),
        (5, 1, "length", "len"), (6, 1, "CI", "ci"),
        (7, 4, "dst", "lan"), (11, 4, "src", "lan"),
        (15, 6, "mesh_payload", "bytes"), (21, 2, "crc", "crc"),
    ],
    (0xD5, 28): [
        (0, 3, "sync", "sync"), (3, 1, "type", "type"), (4, 1, "reserved", "const0"),
        (5, 1, "length", "len"), (6, 1, "CI", "ci"),
        (7, 4, "dst", "lan"), (11, 4, "src", "lan"), (15, 3, "session", "bytes"),
        (18, 2, "class_id", "class_id"), (20, 1, "cc_tag", "cc09"), (21, 1, "cc_len", "cclen"),
        (22, 2, "seq_nonce", "seqnonce"), (24, 1, "DIF", "dif"), (25, 1, "VIF", "vif"),
        (26, 2, "crc", "crc"),
    ],
    (0xD5, 29): [
        (0, 3, "sync", "sync"), (3, 1, "type", "type"), (4, 1, "reserved", "const0"),
        (5, 1, "length", "len"), (6, 1, "CI", "ci"),
        (7, 4, "dst", "lan"), (11, 4, "src", "lan"), (15, 3, "session", "bytes"),
        (18, 2, "class_id", "class_id"), (20, 1, "cc_tag", "cc09"), (21, 1, "cc_len", "cclen"),
        (22, 1, "sub_selector", "u8"), (23, 2, "seq_nonce", "seqnonce"),
        (25, 1, "DIF", "dif"), (26, 1, "VIF", "vif"), (27, 2, "crc", "crc"),
    ],
    (0xD5, 26): [
        (0, 3, "sync", "sync"), (3, 1, "type", "type"), (4, 1, "reserved", "const0"),
        (5, 1, "length", "len"), (6, 1, "CI", "ci"),
        (7, 4, "dst", "lan"), (11, 4, "src", "lan"),
        (15, 9, "payload (07 00 03 tag)", "bytes"), (24, 2, "crc", "crc"),
    ],
    (0xD5, 31): [
        (0, 3, "sync", "sync"), (3, 1, "type", "type"), (4, 1, "reserved", "const0"),
        (5, 1, "length", "len"), (6, 1, "CI", "ci"),
        (7, 4, "dst", "lan"), (11, 4, "src", "lan"), (15, 3, "session", "bytes"),
        (18, 2, "class_id", "class_id"), (20, 1, "cc_tag", "cc09"), (21, 1, "cc_len", "cclen"),
        (22, 3, "tag (07 00 03)", "bytes"), (25, 4, "value", "bytes"), (29, 2, "crc", "crc"),
    ],
    (0xD5, 34): [
        (0, 3, "sync", "sync"), (3, 1, "type", "type"), (4, 1, "reserved", "const0"),
        (5, 1, "length", "len"), (6, 1, "CI", "ci"),
        (7, 4, "dst", "lan"), (11, 4, "src", "lan"), (15, 3, "session", "bytes"),
        (18, 2, "class_id", "class_id"), (20, 1, "cc_tag", "cc09"), (21, 1, "cc_len", "cclen"),
        (22, 1, "sub_selector", "u8"), (23, 5, "obis_prefix", "obis"),
        (28, 2, "seq_nonce", "seqnonce"), (30, 1, "DIF", "dif"), (31, 1, "VIF", "vif"),
        (32, 2, "crc", "crc"),
    ],
    (0xD5, 35): [
        (0, 3, "sync", "sync"), (3, 1, "type", "type"), (4, 1, "reserved", "const0"),
        (5, 1, "length", "len"), (6, 1, "CI", "ci"),
        (7, 4, "dst", "lan"), (11, 4, "src", "lan"),
        (15, 18, "control_payload", "bytes"), (33, 2, "crc", "crc"),
    ],
    (0xD5, 77): [
        (0, 3, "sync", "sync"), (3, 1, "type", "type"), (4, 1, "reserved", "const0"),
        (5, 1, "length", "len"), (6, 1, "CI", "ci"),
        (7, 4, "dst", "lan"), (11, 4, "src", "lan"),
        (15, 1, "unknown_hi", "bytes"),
        (16, 4, "unix_time", "u32time"), (20, 1, "sep", "const0"), (21, 1, "b21", "u8"),
        (22, 2, "digest", "bytes"), (24, 4, "uptime", "u32"),
        (28, 2, "proto_const (A4 0B)", "bytes"), (30, 2, "routing (01 01)", "bytes"),
        (32, 1, "sentinel (FE)", "bytes"), (33, 4, "src_repeat", "lan"),
        (37, 1, "sep", "const0"), (38, 4, "src_repeat", "lan"), (42, 1, "sep", "const0"),
        (43, 3, "routing_end (01 03 25)", "bytes"), (46, 11, "zero_pad", "bytes"),
        (57, 3, "payload_transition", "bytes"), (60, 2, "class_id", "class_id"),
        (62, 1, "cc_tag", "cc09"), (63, 1, "cc_len", "cclen"), (64, 1, "sep", "u8"),
        (65, 1, "selector", "u8"), (66, 5, "obis_prefix", "obis"),
        (71, 2, "seq_nonce", "seqnonce"), (73, 1, "DIF", "dif"), (74, 1, "VIF", "vif"),
        (75, 2, "crc", "crc"),
    ],
    (0xD5, 131): [
        (0, 3, "sync", "sync"), (3, 1, "type", "type"), (4, 1, "reserved", "const0"),
        (5, 1, "length", "len"), (6, 1, "CI", "ci"),
        (7, 4, "dst", "lan"), (11, 4, "src", "lan"),
        (15, 12, "bulk_marker", "bytes"), (27, 4, "dst_repeat", "lan"),
        (31, 4, "src_repeat", "lan"), (35, 12, "bulk_header", "bytes"),
        (47, 82, "bulk_data", "bytes"), (129, 2, "crc", "crc"),
    ],
    (0x55, 41): [
        (0, 3, "sync", "sync"), (3, 1, "type", "type"), (4, 1, "reserved", "const0"),
        (5, 1, "length", "len"), (6, 1, "CI", "ci"),
        (7, 7, "dst (broadcast)", "bcast"), (14, 4, "src", "lan"),
        (18, 2, "session", "bytes"), (20, 4, "session_sub", "bytes"),
        (24, 2, "proto_const (A4 0B)", "bytes"), (26, 4, "src_repeat", "lan"),
        (30, 1, "b30 (01)", "u8"), (31, 2, "class_id", "class_id"),
        (33, 2, "cc (09 03)", "bytes"), (35, 2, "object_id", "objid"),
        (37, 1, "trailer (7E)", "bytes"), (38, 1, "status", "u8"), (39, 2, "crc", "crc"),
    ],
    (0xA5, 23): [
        (0, 3, "sync", "sync"), (3, 1, "type", "type"), (4, 1, "length", "len"),
        (5, 1, "CI", "ci"), (6, 4, "src", "lan"), (10, 4, "body", "bytes"),
        (14, 1, "slot_counter", "u8"), (15, 6, "body2", "bytes"), (21, 2, "crc", "crc"),
    ],
    (0xD2, 9): [
        (0, 3, "sync", "sync"), (3, 1, "type", "type"), (4, 1, "length", "len"),
        (5, 1, "CI", "ci"), (6, 1, "seq", "u8"), (7, 2, "body", "bytes"),
    ],
    (0xD2, 10): [
        (0, 3, "sync", "sync"), (3, 1, "type", "type"), (4, 1, "length", "len"),
        (5, 1, "CI", "ci"), (6, 1, "seq", "u8"), (7, 3, "body", "bytes"),
    ],
    (0xD2, 21): [
        (0, 3, "sync", "sync"), (3, 1, "type", "type"), (4, 1, "length", "len"),
        (5, 1, "CI", "ci"), (6, 1, "seq", "u8"), (7, 2, "aad (01 01)", "bytes"),
        (9, 2, "class_id", "class_id"), (11, 2, "cc (09 03)", "bytes"),
        (13, 1, "selector", "u8"), (14, 5, "obis_prefix", "obis"), (19, 2, "trailer", "bytes"),
    ],
    (0xD2, 23): [
        (0, 3, "sync", "sync"), (3, 1, "type", "type"), (4, 1, "length", "len"),
        (5, 1, "CI", "ci"), (6, 1, "seq/nonce input", "u8"), (7, 2, "aad (01 02)", "bytes"),
        (9, 4, "counter", "u32"), (13, 2, "aad (00 01)", "bytes"),
        (15, 6, "ciphertext", "bytes"), (21, 2, "auth_tag", "bytes"),
    ],
    # 0xD2/len-15 has no fixed documented layout; the COSEM scanner handles it.
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class CRCInfo:
    covered: bool                 # is this frame type covered by the 0x142A CRC?
    ok: Optional[bool] = None     # None when not covered / not checkable
    computed: Optional[int] = None
    packet: Optional[int] = None

    def to_dict(self) -> dict:
        d = {"covered": self.covered, "ok": self.ok}
        if self.computed is not None:
            d["computed"] = f"0x{self.computed:04X}"
        if self.packet is not None:
            d["packet"] = f"0x{self.packet:04X}"
        return d


@dataclass
class FieldInfo:
    start: int
    end: int                      # exclusive
    name: str
    kind: str
    hex: str
    interp: str
    ok: Optional[bool] = None     # None = no constant expectation

    def to_dict(self) -> dict:
        d = {"range": f"[{self.start}:{self.end}]", "name": self.name,
             "kind": self.kind, "hex": self.hex, "interp": self.interp}
        if self.ok is not None:
            d["ok"] = self.ok
        return d


@dataclass
class Cosem:
    class_id: Optional[int] = None
    class_name: Optional[str] = None
    calling_convention: Optional[str] = None   # e.g. "09 03"
    selector: Optional[int] = None
    obis_prefix: Optional[str] = None
    obis_ok: Optional[bool] = None
    seq_nonce: Optional[str] = None
    object_id: Optional[str] = None
    dif: Optional[dict] = None
    vif: Optional[dict] = None

    def to_dict(self) -> dict:
        out = {}
        if self.class_id is not None:
            out["class_id"] = f"0x{self.class_id:04X} ({self.class_id})"
            out["class_name"] = self.class_name
        if self.calling_convention:
            out["calling_convention"] = self.calling_convention
        if self.selector is not None:
            out["selector"] = f"0x{self.selector:02X}"
        if self.obis_prefix is not None:
            out["obis_prefix"] = self.obis_prefix
            out["obis_ok"] = self.obis_ok
        if self.seq_nonce is not None:
            out["seq_nonce"] = self.seq_nonce
        if self.object_id is not None:
            out["object_id"] = self.object_id
        if self.dif is not None:
            out["dif"] = self.dif
        if self.vif is not None:
            out["vif"] = self.vif
        return out


@dataclass
class ParsedFrame:
    raw_hex: str
    length: int
    valid_sync: bool
    type_byte: Optional[int] = None
    type_name: Optional[str] = None
    header_len: Optional[int] = None
    length_field: Optional[int] = None
    length_consistent: Optional[bool] = None
    ci_byte: Optional[int] = None
    ci_name: Optional[str] = None
    ci_class: Optional[str] = None
    family: Optional[str] = None
    cosem_bearing: bool = False
    decoded_via: str = "header-only"   # "layout" | "heuristic" | "header-only"
    addresses: dict = field(default_factory=dict)
    fields: list = field(default_factory=list)
    cosem: Optional[Cosem] = None
    crc: Optional[CRCInfo] = None
    derived: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        out = {
            "raw_hex": self.raw_hex,
            "length": self.length,
            "valid_sync": self.valid_sync,
        }
        if self.type_byte is not None:
            out["type"] = f"0x{self.type_byte:02X} ({self.type_name})"
        out["header_len"] = self.header_len
        if self.length_field is not None:
            out["length_field"] = self.length_field
            out["length_consistent"] = self.length_consistent
        if self.ci_byte is not None:
            out["ci"] = f"0x{self.ci_byte:02X} ({self.ci_name})"
            out["ci_class"] = self.ci_class
        out["family"] = self.family
        out["cosem_bearing"] = self.cosem_bearing
        out["decoded_via"] = self.decoded_via
        if self.addresses:
            out["addresses"] = self.addresses
        if self.cosem is not None:
            out["cosem"] = self.cosem.to_dict()
        if self.crc is not None:
            out["crc"] = self.crc.to_dict()
        if self.derived:
            out["derived"] = self.derived
        out["fields"] = [f.to_dict() for f in self.fields]
        if self.warnings:
            out["warnings"] = self.warnings
        return out


def _scan_cosem(p: bytes, start: int, end: int) -> Optional[dict]:
    """Best-effort: locate the L+G `09 <len>` calling convention preceded by a
    plausible 2-byte BE COSEM class_id (1..0x70). Returns offsets or None.
    """
    for i in range(max(start, 2), min(end, len(p) - 1)):
        if p[i] == 0x09 and p[i + 1] in (0x02, 0x03, 0x04):
            cid = (p[i - 2] << 8) | p[i - 1]
            if 0x0001 <= cid <= 0x0070:
                return {"class_id_off": i - 2, "cc_off": i, "cc_len": p[i + 1]}
    return None


def _ci_describe(ci: int) -> tuple:
    return CI_NAMES.get(ci, "unknown"), CI_CLASS.get(ci >> 4, "unknown")


def _render(p: bytes, layout: list, header_len: int, frame: ParsedFrame) -> None:
    """Walk a field layout, populating frame.fields / addresses / cosem / derived."""
    cosem = Cosem()
    has_cosem = False
    ts_vals = {}

    for start, length, name, kind in layout:
        end = start + length
        raw = p[start:end]
        hexs = raw.hex().upper()
        interp = ""
        ok = None

        if end > len(p):
            interp = "(out of range / truncated)"
            frame.warnings.append(f"field {name} [{start}:{end}] exceeds frame ({len(p)} B)")
            frame.fields.append(FieldInfo(start, end, name, kind, hexs, interp, False))
            continue

        if kind == "sync":
            ok = raw == SYNC
            interp = "sync" + ("" if ok else " (corrupt)")
        elif kind == "type":
            interp = TYPE_NAMES.get(raw[0], "unknown")
        elif kind == "len":
            interp = f"{raw[0]} body bytes"
        elif kind == "ci":
            nm, cls = _ci_describe(raw[0])
            interp = f"{nm} (class 0x{raw[0] >> 4:X}X = {cls})"
        elif kind == "lan":
            ok = looks_like_lan_id(raw)
            interp = "LAN ID" + ("" if ok else " (unexpected prefix)")
            role = "src" if name.startswith("src") else ("dst" if name.startswith("dst") else name)
            frame.addresses.setdefault(role, hexs)
        elif kind == "bcast":
            ok = raw == bytes([0xFF] * 6 + [0xFE])
            interp = "broadcast" + ("" if ok else " (unexpected)")
            frame.addresses["dst"] = hexs
        elif kind == "class_id":
            cid = (raw[0] << 8) | raw[1]
            nm = COSEM_CLASSES.get(cid, "unknown / out-of-range")
            interp = f"{cid} = {nm}"
            cosem.class_id, cosem.class_name = cid, nm
            has_cosem = True
        elif kind == "cc09":
            ok = raw[0] == 0x09
            interp = "octet-string tag" + ("" if ok else " (expected 09)")
        elif kind == "cclen":
            interp = f"calling-convention length {raw[0]}"
            cosem.calling_convention = f"09 {raw[0]:02X}"
            has_cosem = True
        elif kind == "seqnonce":
            interp = "per-packet seq/nonce (unique; not a value)"
            cosem.seq_nonce = hexs
            has_cosem = True
        elif kind == "objid":
            interp = "object identifier (stable / repeating)"
            cosem.object_id = hexs
            has_cosem = True
        elif kind == "obis":
            ok = raw == OBIS_PREFIX
            interp = "L+G OBIS-like prefix" + ("" if ok else " (unexpected)")
            cosem.obis_prefix, cosem.obis_ok = hexs, ok
            has_cosem = True
        elif kind == "dif":
            d = parse_dif(raw[0])
            interp = f"{d['data_len_name']}, {d['function']}, storage={d['storage']}"
            cosem.dif = d
            has_cosem = True
        elif kind == "vif":
            v = parse_vif(raw[0])
            ok = v["low_nibble"] == 0
            interp = f"unit class hi-nibble 0x{raw[0] >> 4:X}" + ("" if ok else " (low nibble != 0)")
            cosem.vif = v
            has_cosem = True
        elif kind == "u8":
            interp = str(raw[0])
            if name == "selector":
                cosem.selector = raw[0]
        elif kind == "u16":
            interp = str((raw[0] << 8) | raw[1])
        elif kind in ("u32", "u32time"):
            val = int.from_bytes(raw, "big")
            interp = str(val)
            ts_vals[name] = val
            if kind == "u32time":
                try:
                    iso = datetime.datetime.fromtimestamp(val, datetime.timezone.utc).isoformat()
                    interp = f"{val} = {iso}"
                except (OverflowError, OSError, ValueError):
                    interp = f"{val} (not a plausible Unix time)"
        elif kind == "const0":
            ok = raw == bytes(length)
            interp = "0x00" if ok else "(expected zero)"
        else:  # "bytes"
            interp = ""

        frame.fields.append(FieldInfo(start, end, name, kind, hexs, interp, ok))

    if has_cosem:
        frame.cosem = cosem
    # Derived signal: status-push last power-on = unix_time - uptime.
    if "unix_time" in ts_vals and "uptime" in ts_vals:
        last_on = ts_vals["unix_time"] - ts_vals["uptime"]
        try:
            iso = datetime.datetime.fromtimestamp(last_on, datetime.timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            iso = "(implausible)"
        frame.derived["last_power_on"] = f"{last_on} = {iso}"


def parse_frame(frame_input) -> ParsedFrame:
    """Decode one GridStream frame (hex string or bytes) into a ParsedFrame."""
    if isinstance(frame_input, str):
        hexs = "".join(frame_input.split())
        try:
            p = bytes.fromhex(hexs)
        except ValueError as e:
            raise ValueError(f"not valid hex: {e}") from None
    else:
        p = bytes(frame_input)

    frame = ParsedFrame(raw_hex=p.hex().upper(), length=len(p), valid_sync=p[:3] == SYNC)
    if not frame.valid_sync:
        frame.warnings.append("sync word is not 80 FF 2A (preamble corruption?)")
    if len(p) < 5:
        frame.warnings.append("frame too short to decode")
        return frame

    frame.type_byte = p[3]
    frame.type_name = TYPE_NAMES.get(p[3], "unknown")
    hl = header_len_for(p[3])
    frame.header_len = hl
    frame.length_field = p[4] if hl == 5 else p[5]
    frame.length_consistent = (hl + frame.length_field == len(p))
    if not frame.length_consistent:
        frame.warnings.append(
            f"length self-check failed: header {hl} + length {frame.length_field} != {len(p)}")

    ci_off = 5 if hl == 5 else 6
    if len(p) > ci_off:
        frame.ci_byte = p[ci_off]
        frame.ci_name, frame.ci_class = _ci_describe(p[ci_off])

    fam = FAMILIES.get((p[3], len(p)))
    if fam:
        frame.family, frame.cosem_bearing = fam

    # CRC: covered for 0x55/0xA5/0xD5 only.
    if p[3] in (0x55, 0xA5, 0xD5) and len(p) >= hl + 2:
        body = p[hl:len(p) - 2]
        computed = crc16_gridstream(body)
        packet = (p[len(p) - 2] << 8) | p[len(p) - 1]
        frame.crc = CRCInfo(covered=True, ok=(computed == packet), computed=computed, packet=packet)
    else:
        note = "auth tag (CI=0x52) or unchecked plaintext framing" if p[3] == 0xD2 else "not applicable"
        frame.crc = CRCInfo(covered=False)
        frame.derived["crc_note"] = note

    layout = _LAYOUTS.get((p[3], len(p)))
    if layout:
        frame.decoded_via = "layout"
        _render(p, layout, hl, frame)
    else:
        # No documented layout: header-only, but try to surface COSEM if present.
        frame.decoded_via = "header-only"
        scan = _scan_cosem(p, hl, len(p) - 1)
        if scan:
            frame.decoded_via = "heuristic"
            frame.cosem_bearing = True
            cid = (p[scan["class_id_off"]] << 8) | p[scan["class_id_off"] + 1]
            cosem = Cosem(
                class_id=cid, class_name=COSEM_CLASSES.get(cid, "unknown"),
                calling_convention=f"09 {scan['cc_len']:02X}")
            frame.cosem = cosem
            frame.warnings.append(
                f"no documented layout for (0x{p[3]:02X}, len {len(p)}); "
                f"COSEM marker found at offset {scan['cc_off']}")
        elif not fam:
            frame.warnings.append(f"unrecognized family (0x{p[3]:02X}, len {len(p)})")

    return frame


# ---------------------------------------------------------------------------
# CLI rendering
# ---------------------------------------------------------------------------
def _mark(ok: Optional[bool]) -> str:
    return "" if ok is None else ("  ok" if ok else "  FAIL")


def format_frame(f: ParsedFrame) -> str:
    out = [f"Frame: {f.raw_hex}  ({f.length} bytes)"]
    if f.type_byte is not None:
        out.append(f"  Type      0x{f.type_byte:02X}  {f.type_name}")
    out.append(f"  Family    {f.family or '(unrecognized)'}"
               + ("   [COSEM]" if f.cosem_bearing else ""))
    if f.length_field is not None:
        cons = "consistent" if f.length_consistent else "INCONSISTENT"
        out.append(f"  Length    {f.length_field}  (header {f.header_len} + {f.length_field} "
                   f"= {f.header_len + f.length_field}, {cons})")
    if f.ci_byte is not None:
        out.append(f"  CI        0x{f.ci_byte:02X}  {f.ci_name}  (class = {f.ci_class})")
    if f.crc is not None:
        if f.crc.covered:
            verdict = "OK" if f.crc.ok else "MISMATCH"
            out.append(f"  CRC       0x{f.crc.packet:04X}  computed 0x{f.crc.computed:04X}  -> {verdict}")
        else:
            out.append(f"  CRC       not covered ({f.derived.get('crc_note', '')})")
    if f.addresses:
        out.append("  Addresses")
        for role, val in f.addresses.items():
            out.append(f"    {role:<6}  {val}")
    if f.cosem is not None:
        out.append("  COSEM")
        c = f.cosem
        if c.class_id is not None:
            out.append(f"    class_id  0x{c.class_id:04X} ({c.class_id})  {c.class_name}")
        if c.calling_convention:
            out.append(f"    calling   {c.calling_convention}")
        if c.selector is not None:
            out.append(f"    selector  0x{c.selector:02X}")
        if c.obis_prefix is not None:
            out.append(f"    obis      {c.obis_prefix}{_mark(c.obis_ok)}")
        if c.object_id is not None:
            out.append(f"    object_id {c.object_id}")
        if c.seq_nonce is not None:
            out.append(f"    seq/nonce {c.seq_nonce}")
        if c.dif is not None:
            out.append(f"    DIF       {c.dif['data_len_name']}, {c.dif['function']}, "
                       f"storage={c.dif['storage']}")
        if c.vif is not None:
            out.append(f"    VIF       hi-nibble unit class, low={c.vif['low_nibble']}")
    if f.derived:
        for k, v in f.derived.items():
            if k == "crc_note":
                continue
            out.append(f"  Derived   {k} = {v}")
    if f.fields:
        out.append("  Fields")
        for fl in f.fields:
            out.append(f"    [{fl.start:>3}:{fl.end:<3}] {fl.name:<22} {fl.hex:<26} "
                       f"{fl.interp}{_mark(fl.ok)}")
    if f.warnings:
        out.append("  Warnings")
        for w in f.warnings:
            out.append(f"    - {w}")
    return "\n".join(out)


def _iter_input_lines(args: list):
    """Yield frame hex strings from positional args, --file PATH, or stdin.

    Every source is run through `_extract_hex`, so a raw capture line
    ("[CRC: OK] <hex> Baudrate: ...", ANSI colour, or spaced hex) yields just the
    frame hex and "# ..." / blank lines are skipped. A positional arg falls back
    to its raw token when no hex is found, so a malformed argument still reaches
    parse_frame and errors visibly rather than being silently dropped.
    """
    hexes, as_file, want_stdin = [], None, False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--file":
            i += 1
            as_file = args[i] if i < len(args) else None
        elif a == "--stdin":
            want_stdin = True
        else:
            hexes.append(a)
        i += 1
    if hexes:
        for a in hexes:
            yield _extract_hex(a) or a
        return
    src = None
    if as_file:
        with open(as_file) as fh:
            src = fh.read().splitlines()
    elif want_stdin or not sys.stdin.isatty():
        src = sys.stdin.read().splitlines()
    if src:
        for line in src:
            h = _extract_hex(line)
            if h:
                yield h


def main(argv: list) -> int:
    args = argv[1:]
    as_json = "--json" in args
    args = [a for a in args if a != "--json"]
    if "-h" in args or "--help" in args or (not args and sys.stdin.isatty()):
        print(__doc__)
        return 0

    frames = list(_iter_input_lines(args))
    if not frames:
        print("No frames given. Pass hex args, --file PATH, or pipe via stdin.", file=sys.stderr)
        return 1

    results = []
    rc = 0
    for hx in frames:
        try:
            f = parse_frame(hx)
        except ValueError as e:
            print(f"skip {hx!r}: {e}", file=sys.stderr)
            rc = 1
            continue
        if f.crc and f.crc.covered and not f.crc.ok:
            rc = 1
        if as_json:
            results.append(f.to_dict())
        else:
            print(format_frame(f))
            print()
    if as_json:
        print(json.dumps(results if len(results) != 1 else results[0], indent=2))
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
