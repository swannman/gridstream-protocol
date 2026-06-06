"""Protocol-doc validator.

Encodes the protocol spec from `docs/gridstream-protocol.md`
as Python data, then walks every CRC-good packet in the corpus and verifies:

  1. Coverage: % of corpus that matches a known cluster (by type, b4, b5, len)
  2. Constants: for each packet, all bytes claimed constant in the doc match
  3. Address-field validity: dst/src bytes look like 4-byte LAN IDs or broadcast
  4. COSEM markers: where the doc claims a class_id or L+G marker, it's there
  5. CRC offsets: last 2 bytes pass CRC-16/CCITT with init 0x142A
  6. ID-field cardinality: the directed-frame 2-byte field after the calling
     convention is per-packet-unique (a seq/nonce), while the broadcast frame's
     is a stable, repeating object identifier

Output: pass/fail per cluster, list of any violations.
"""
import os, re, sys, glob
from collections import Counter, defaultdict

ANSI = re.compile(r"\x1b\[[0-9;]*m")
LINE = re.compile(r"\[CRC: ?OK\]\s+([0-9A-Fa-f]+)")
# Capture logs to validate against, in priority order:
#   1. command-line args (paths or globs):  python validate_protocol_doc.py 'capture/*.log'
#   2. GRIDSTREAM_LOGS env var (colon-separated paths or globs)
#   3. fallback: ./capture/*.log  (the anonymized corpus shipped in this repo)
# Each line is "[CRC: OK] <hex>" — the published corpus format, which is also a
# prefix of the raw gr-smart_meters log line (see capture/README.md).
def _resolve_logs():
    sources = sys.argv[1:]
    if not sources and os.environ.get("GRIDSTREAM_LOGS"):
        sources = os.environ["GRIDSTREAM_LOGS"].split(":")
    if not sources:
        sources = ["capture/*.log"]
    paths = []
    for s in sources:
        paths.extend(sorted(glob.glob(s)) or [s])
    return paths

LOGS = _resolve_logs()

# =====================================================================
# CLUSTER SPECS — encode what the protocol doc claims for each cluster
# =====================================================================
# Each spec keyed by (type, b4, b5, length)
# Fields:
#   name: human-readable
#   constants: list of (offset, expected_byte) asserted to hold for every packet
#   addr_fields: list of (offset_start, offset_end, role) where role ∈ {src, dst, bcast}
#   crc_offsets: (start, end) for CRC bytes
#   cosem_class_id_offset: offset of 2-byte BE class_id (or None)
#   idfield_offset / idfield_role: offset of the 2-byte BE field after the COSEM
#       calling convention, and its role — "seqnonce" (directed frames; unique
#       per packet) or "objid" (broadcast; stable/repeating). Checked at corpus
#       scale, not per-packet (a seq/nonce has no fixed value range).
#   ci_allowed: set of permitted CI bytes where a cluster has more than one (else
#       the CI is pinned via a constant on byte 6)
#   notes: free-form text

CLUSTER_SPECS = {
    (0xD5, 0x00, 0x11, 23): dict(
        name="0xD5/0x11 — Short mesh control",
        constants=[(3,0xD5),(4,0x00),(5,0x11)],
        addr_fields=[(7,10,"dst"),(11,14,"src")],
        crc_offsets=(21,22),
        cosem_class_id_offset=None,
    ),
    (0xD5, 0x00, 0x16, 28): dict(
        name="0xD5/0x16 — Directed data",
        # byte 20 = 0x09 (COSEM octet-string tag); byte 21 is the following
        # length, which is NOT constant (0x03 ~89%, also 0x02/0x04) — not asserted.
        constants=[(3,0xD5),(4,0x00),(5,0x16),(17,0x01),(20,0x09)],
        addr_fields=[(7,10,"dst"),(11,14,"src")],
        crc_offsets=(26,27),
        cosem_class_id_offset=18,
        idfield_offset=22, idfield_role="seqnonce",  # bytes 22-23: per-packet seq/nonce
        wmbus_dif_offset=24,        # DIF at byte 24
        wmbus_vif_offset=25,        # VIF at byte 25
    ),
    (0xD5, 0x00, 0x17, 29): dict(
        name="0xD5/0x17 — Directed data variant",
        # byte 20 = 0x09 (~99.1%; a ~0.9% sub-variant carries 0x50 with a
        # different class_id). byte 21 is the octet-string length (not constant).
        constants=[(3,0xD5),(4,0x00),(5,0x17),(20,0x09)],
        addr_fields=[(7,10,"dst"),(11,14,"src")],
        crc_offsets=(27,28),
        cosem_class_id_offset=18,
        idfield_offset=23, idfield_role="seqnonce",  # bytes 23-24: per-packet seq/nonce
        wmbus_dif_offset=25,        # DIF at byte 25
        wmbus_vif_offset=26,        # VIF at byte 26
    ),
    (0xD5, 0x00, 0x1C, 34): dict(
        name="0xD5/0x1C — Peer-to-peer data",
        # byte 21 (octet-string length) is not constant; OBIS prefix at 23-27.
        constants=[(3,0xD5),(4,0x00),(5,0x1C),(6,0x22),(20,0x09),
                   (23,0x20),(24,0x30),(25,0x2D),(26,0x84),(27,0x80)],
        addr_fields=[(7,10,"dst"),(11,14,"src")],
        crc_offsets=(32,33),
        cosem_class_id_offset=18,
        idfield_offset=28, idfield_role="seqnonce",  # bytes 28-29: per-packet seq/nonce
        wmbus_dif_offset=30,        # DIF at byte 30
        wmbus_vif_offset=31,        # VIF at byte 31
    ),
    (0xD5, 0x00, 0x1D, 35): dict(
        name="0xD5/0x1D — Rare control",
        constants=[(3,0xD5),(4,0x00),(5,0x1D)],
        addr_fields=[(7,10,"dst"),(11,14,"src")],
        crc_offsets=(33,34),
        cosem_class_id_offset=None,
    ),
    (0xD5, 0x00, 0x14, 26): dict(
        name="0xD5/0x14 — Short directed",
        # Rare directed frame: dst+src LAN, then a 07 00 03 tag (no 09 03).
        constants=[(3,0xD5),(4,0x00),(5,0x14),(6,0x22)],
        addr_fields=[(7,10,"dst"),(11,14,"src")],
        crc_offsets=(24,25),
        cosem_class_id_offset=None,
    ),
    (0xD5, 0x00, 0x19, 31): dict(
        name="0xD5/0x19 — Short directed + COSEM",
        # Rare directed frame: the 07 00 03 tag plus a 09 03 COSEM marker.
        constants=[(3,0xD5),(4,0x00),(5,0x19),(6,0x22)],
        addr_fields=[(7,10,"dst"),(11,14,"src")],
        crc_offsets=(29,30),
        cosem_class_id_offset=None,
    ),
    (0xD5, 0x00, 0x7D, 131): dict(
        name="0xD5/0x7D — Bulk transfer (longest frame)",
        # Single observed frame; mostly high-entropy payload (structure unknown).
        constants=[(3,0xD5),(4,0x00),(5,0x7D),(6,0x81)],
        addr_fields=[(7,10,"dst"),(11,14,"src")],
        crc_offsets=(129,130),
        cosem_class_id_offset=None,
    ),
    (0xD5, 0x00, 0x47, 77): dict(
        name="0xD5/0x47 — Status push",
        # CI is 0x51 (routine push, ~95%) or 0x55 (event-driven sibling, ~5%).
        # byte 16 is the MSB of the Unix timestamp (bytes 16-19), not a constant.
        # byte 62 = 0x09 (octet-string tag) is constant; byte 63 (length) and
        # byte 64 (separator) vary (0x02/0x03/0x04 and 0x00/0x01) — not asserted.
        ci_allowed={0x51, 0x55},
        constants=[(3,0xD5),(4,0x00),(5,0x47),
                   (20,0x00),
                   (28,0xA4),(29,0x0B),(30,0x01),(31,0x01),(32,0xFE),
                   (37,0x00),(42,0x00),(43,0x01),(44,0x03),(45,0x25),
                   # 11 zero bytes 46-56
                   (46,0x00),(47,0x00),(48,0x00),(49,0x00),(50,0x00),(51,0x00),
                   (52,0x00),(53,0x00),(54,0x00),(55,0x00),(56,0x00),
                   (60,0x00),(62,0x09),
                   (66,0x20),(67,0x30),(68,0x2D),(69,0x84),(70,0x80),],
        addr_fields=[(7,10,"dst"),(11,14,"src")],
        crc_offsets=(75,76),
        cosem_class_id_offset=60,
        # 16-bit object selector at 64-65; the class field at 60-61 is the
        # deterministic bin class = (selector + 8) >> 4 (verified 97/97 selectors).
        selector_offset=64, class_selector_invariant=True,
        idfield_offset=71, idfield_role="seqnonce",  # bytes 71-72: per-packet seq/nonce
        wmbus_dif_offset=73,        # DIF at byte 73
        wmbus_vif_offset=74,        # VIF at byte 74
        # bytes 33-36 and 38-41 should equal bytes 11-14 (src repeated)
        src_repeat_offsets=[33, 38],
    ),
    (0x55, 0x00, 0x23, 41): dict(
        name="0x55/0x23 — Broadcast announcement",
        # byte 33 = 0x09 (octet-string tag); byte 34 (length) varies (not asserted).
        # byte 37 = 0x7E is constant; byte 38 = 0x70 is ~99.1% (not asserted).
        constants=[(3,0x55),(4,0x00),(5,0x23),(6,0x30),
                   # 7-byte broadcast destination
                   (7,0xFF),(8,0xFF),(9,0xFF),(10,0xFF),(11,0xFF),(12,0xFF),(13,0xFE),
                   (24,0xA4),(25,0x0B),(30,0x01),
                   (33,0x09),
                   (37,0x7E)],
        addr_fields=[(7,13,"bcast"),(14,17,"src")],
        crc_offsets=(39,40),
        cosem_class_id_offset=31,
        idfield_offset=35, idfield_role="objid",  # bytes 35-36: stable object identifier
    ),
    (0xA5, 0x12, 0x3C, 23): dict(
        # NB: 0xA5 has 1-byte length at offset 4 (not 2-byte subtype).
        # byte 4 = 0x12 = packet_len; byte 5 = 0x3C is first body byte (sub-type marker).
        # So (b4, b5) in this dict's key is really (packet_len, first_body_byte).
        name="0xA5/0x3C — Scheduled mesh beacon (header_len=5)",
        constants=[(3,0xA5),(4,0x12),(5,0x3C)],
        addr_fields=[(6,9,"src")],  # src LAN ID starts at byte 6 (not 7)
        crc_offsets=(21,22),
        cosem_class_id_offset=None,
    ),
}

# =====================================================================
# Load all CRC-good packets
# =====================================================================
all_pkts = []
for log in LOGS:
    try:
        with open(log) as f:
            for line in f:
                m = LINE.search(ANSI.sub("", line))
                if not m: continue
                try: data = bytes.fromhex(m.group(1))
                except ValueError: continue
                if len(data) < 6: continue
                all_pkts.append(data)
    except FileNotFoundError: pass

print(f"Total CRC-good packets: {len(all_pkts)}")
if not all_pkts:
    print("\nNo packets loaded. Point the validator at capture logs, e.g.:")
    print("  python tools/validate_protocol_doc.py 'capture/*.log'")
    print("  (or set GRIDSTREAM_LOGS). See capture/README.md to produce them.")
    sys.exit(1)

# =====================================================================
# CRC-16/CCITT helpers
# =====================================================================
def crc16_gridstream(data, init=0x142A):
    """Match gr-smart_meters GridStream_impl::crc16 exactly:
       - Poly 0x1021, byte-MSB-first
       - Input: just the body bytes (caller pre-strips header & CRC tail)
    """
    crc = init
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc

def header_len_for(p):
    """Per gr-smart_meters: header_len=5 for 0xA5/0xD2 (1-byte length field),
       header_len=6 for 0x55/0xD5 (2-byte length/subtype)."""
    if p[3] in (0xA5, 0xD2):
        return 5
    return 6

# =====================================================================
# WMBus DIF / VIF parsing (IEC 13757-3)
# =====================================================================
DIF_DATA_LENGTH = {
    0x0: "no data",
    0x1: "8-bit int",
    0x2: "16-bit int",
    0x3: "24-bit int",
    0x4: "32-bit int",
    0x5: "32-bit real",
    0x6: "48-bit int",
    0x7: "64-bit int",
    0x8: "selection for readout",
    0x9: "2-digit BCD",
    0xA: "4-digit BCD",
    0xB: "6-digit BCD",
    0xC: "8-digit BCD",
    0xD: "variable length",
    0xE: "12-digit BCD",
    0xF: "special functions",
}
DIF_FUNCTION = {
    0b00: "instantaneous",
    0b01: "maximum",
    0b10: "minimum",
    0b11: "error",
}

def parse_dif(b):
    """Parse a byte as a WMBus DIF and return its components.
    Returns dict with keys: extension, function, storage, data_len_code, data_len_name.
    """
    extension = bool(b & 0x80)
    function = (b >> 5) & 0b11
    storage = (b >> 4) & 0b1
    data_len = b & 0x0F
    return dict(
        extension=extension,
        function=DIF_FUNCTION[function],
        function_bits=function,
        storage=storage,
        data_len_code=data_len,
        data_len_name=DIF_DATA_LENGTH[data_len],
    )

def validate_dif(b):
    """Return a violation string if byte 'b' doesn't parse as our expected DIF
    (instantaneous, storage=1, no extension). Returns None if valid."""
    d = parse_dif(b)
    if d["extension"]:
        return f"DIF extension bit set (0x{b:02X})"
    if d["function_bits"] != 0b00:
        return f"DIF function not instantaneous (0x{b:02X}, function={d['function']})"
    if d["storage"] != 1:
        return f"DIF storage bit not set (0x{b:02X})"
    return None

# VIF parsing — speculative for now; we know the X0 pattern but not the L+G mapping
def parse_vif(b):
    """Parse a byte as a WMBus VIF.
    For now just describe its structure; L+G mapping is non-standard."""
    extension = bool(b & 0x80)
    # bits 6-0 are unit+multiplier code in standard VIF
    code = b & 0x7F
    return dict(
        extension=extension,
        code=code,
    )

# =====================================================================
# Validation
# =====================================================================
def validate_packet(p, spec):
    """Return list of violation strings (empty = passes).
    Note: bytes 0-2 are NOT validated as constants — they're the preamble,
    OUTSIDE CRC coverage, so any drift there is bit-flip corruption that
    snuck past the sync detector, not a protocol feature.
    """
    violations = []

    # Bit-flip drift in preamble (informational only, not a violation)
    if len(p) >= 3 and (p[0] != 0x80 or p[1] != 0xFF or p[2] != 0x2A):
        # tracked but not counted as a violation
        pass

    # Constants
    for off, expected in spec.get("constants", []):
        if off >= len(p):
            violations.append(f"byte {off} out of range")
            continue
        if p[off] != expected:
            violations.append(f"byte {off} = 0x{p[off]:02X} (expected 0x{expected:02X})")

    # CI byte: some clusters permit more than one CI (e.g. status push 0x51/0x55)
    ci_allowed = spec.get("ci_allowed")
    if ci_allowed is not None and len(p) > 6 and p[6] not in ci_allowed:
        allowed = "/".join(f"0x{c:02X}" for c in sorted(ci_allowed))
        violations.append(f"CI byte = 0x{p[6]:02X} (expected {allowed})")

    # Address fields
    for start, end, role in spec.get("addr_fields", []):
        if end >= len(p):
            violations.append(f"addr field {start}-{end} out of range")
            continue
        field = p[start:end+1]
        # src/dst LAN IDs are validated *structurally* — by position, plus the
        # src-repeat and CRC checks below — not by a prefix allowlist. A prefix
        # heuristic ({0x80,0x90,0x50}) would falsely flag the utility's data
        # collector, whose 0x40-prefixed address is a legitimate node we never
        # whitelisted. The broadcast destination, by contrast, IS a fixed
        # constant and is checked exactly.
        if role == "bcast":
            expected = bytes([0xFF]*6 + [0xFE])
            if field != expected:
                violations.append(f"broadcast addr {start}-{end} = {field.hex().upper()} (expected FFFFFFFFFFFFFE)")

    # Source LAN ID repeats (specific to 0xD5/0x47)
    if "src_repeat_offsets" in spec:
        src = p[11:15]
        for off in spec["src_repeat_offsets"]:
            if p[off:off+4] != src:
                violations.append(f"src LAN ID repeat at {off}-{off+3} = {p[off:off+4].hex().upper()} (expected {src.hex().upper()})")

    # COSEM class_id sanity (if claimed)
    cid_off = spec.get("cosem_class_id_offset")
    if cid_off is not None and cid_off + 2 <= len(p):
        cid = (p[cid_off] << 8) | p[cid_off+1]
        # We expect class_id in 0x0001-0x0070 range (standard COSEM classes)
        # OR the rare 0xFA00-0xFAFF range (Association)
        if not (0x0001 <= cid <= 0x0070 or 0xFA00 <= cid <= 0xFAFF):
            violations.append(f"COSEM class_id at {cid_off} = 0x{cid:04X} not in standard range")

    # Class/selector invariant: the class field is a deterministic bin of the
    # 16-bit object selector — class = (selector + 8) >> 4.
    sel_off = spec.get("selector_offset")
    if (spec.get("class_selector_invariant") and cid_off is not None
            and sel_off is not None and sel_off + 2 <= len(p)):
        cid = (p[cid_off] << 8) | p[cid_off+1]
        sel = (p[sel_off] << 8) | p[sel_off+1]
        expected = (sel + 8) >> 4
        if cid != expected:
            violations.append(
                f"class/selector invariant broken: selector {sel} at {sel_off} "
                f"implies class {expected}, but class field at {cid_off} = {cid}")

    # The 2-byte id field (idfield_offset) has no fixed per-packet value range:
    # in directed frames it is a per-packet seq/nonce, in the broadcast frame a
    # stable object identifier. Its claim is validated at corpus scale instead —
    # see the ID-FIELD CARDINALITY section below.

    # WMBus DIF validation (if claimed)
    dif_off = spec.get("wmbus_dif_offset")
    if dif_off is not None and dif_off < len(p):
        err = validate_dif(p[dif_off])
        if err:
            violations.append(f"DIF at {dif_off}: {err}")

    # WMBus VIF: check the X0 low-nibble pattern (speculative)
    vif_off = spec.get("wmbus_vif_offset")
    if vif_off is not None and vif_off < len(p):
        if p[vif_off] & 0x0F != 0:
            violations.append(f"VIF at {vif_off} = 0x{p[vif_off]:02X} has low nibble != 0 (breaks observed pattern)")

    # CRC verification — matches gr-smart_meters
    crc_start, crc_end = spec["crc_offsets"]
    if crc_end < len(p):
        hdr = header_len_for(p)
        body = p[hdr:crc_start]  # skip header, exclude CRC
        expected_crc = (p[crc_start] << 8) | p[crc_end]
        computed = crc16_gridstream(body)
        if computed != expected_crc:
            violations.append(f"CRC mismatch: body→0x{computed:04X}, packet→0x{expected_crc:04X}")

    return violations

# =====================================================================
# Run validation
# =====================================================================
print("\n" + "=" * 70)
print("VALIDATION RESULTS")
print("=" * 70)

cluster_stats = defaultdict(lambda: {"total":0, "pass":0, "violations":Counter()})
uncovered = []

for p in all_pkts:
    if len(p) < 6:
        uncovered.append(("too short", p))
        continue
    key = (p[3], p[4], p[5], len(p))
    if key not in CLUSTER_SPECS:
        uncovered.append((key, p))
        continue
    spec = CLUSTER_SPECS[key]
    cluster_stats[key]["total"] += 1
    vio = validate_packet(p, spec)
    if not vio:
        cluster_stats[key]["pass"] += 1
    else:
        for v in vio:
            # bucket violations by category
            cat = v.split(" = ")[0].split(" (")[0].split(" at ")[0]
            cluster_stats[key]["violations"][cat] += 1

# Count preamble bit-flips (informational — these are bit-flip artifacts that
# passed the sync detector but aren't protocol variants; preamble is OUTSIDE CRC coverage)
preamble_drift = sum(1 for p in all_pkts if len(p) >= 3 and (p[0] != 0x80 or p[1] != 0xFF or p[2] != 0x2A))

# Print per-cluster results
total = len(all_pkts)
total_covered = sum(s["total"] for s in cluster_stats.values())
total_pass = sum(s["pass"] for s in cluster_stats.values())
print(f"\nCoverage: {total_covered}/{total} ({100*total_covered/total:.1f}%) match a documented cluster")
print(f"Of those, {total_pass}/{total_covered} ({100*total_pass/max(1,total_covered):.2f}%) pass all spec checks")
print(f"Uncovered: {len(uncovered)} packets")
print(f"Preamble bit-flip drift (informational, NOT counted as violations): {preamble_drift} packets")

# =====================================================================
# WMBus DIF/VIF distribution stats across the corpus
# =====================================================================
print("\n" + "=" * 70)
print("WMBus DIF/VIF distribution per cluster")
print("=" * 70)
for key, spec in CLUSTER_SPECS.items():
    dif_off = spec.get("wmbus_dif_offset")
    vif_off = spec.get("wmbus_vif_offset")
    if dif_off is None: continue
    pkts_cluster = [p for p in all_pkts
                    if len(p) == key[3] and p[3] == key[0]
                    and (key[0] == 0xA5 or p[4] == key[1])
                    and (key[0] == 0xA5 or p[5] == key[2])]
    if not pkts_cluster: continue
    print(f"\n  {spec['name']} (n={len(pkts_cluster)}, DIF@{dif_off}, VIF@{vif_off})")
    # byte 6 (CI) distribution
    ci_vals = Counter(p[6] for p in pkts_cluster)
    print(f"    CI byte (offset 6) distribution:")
    for v, c in ci_vals.most_common(10):
        print(f"      0x{v:02X}: {c} ({100*c/len(pkts_cluster):.1f}%)")
    # DIF data length distribution
    dif_lens = Counter()
    for p in pkts_cluster:
        d = parse_dif(p[dif_off])
        dif_lens[d["data_len_name"]] += 1
    print(f"    DIF data-length distribution:")
    for name, c in dif_lens.most_common():
        print(f"      {name:>22}: {c} ({100*c/len(pkts_cluster):.1f}%)")
    # VIF distribution (top values)
    vif_vals = Counter(p[vif_off] for p in pkts_cluster)
    print(f"    VIF byte distribution (top 10):")
    for v, c in vif_vals.most_common(10):
        print(f"      0x{v:02X}: {c} ({100*c/len(pkts_cluster):.1f}%)")

print(f"\n{'Cluster':<40} {'n':>5} {'pass':>5} {'pass%':>6}")
print(f"{'-'*40} {'-'*5} {'-'*5} {'-'*6}")
for key in sorted(cluster_stats.keys(), key=lambda k: -cluster_stats[k]["total"]):
    s = cluster_stats[key]
    name = CLUSTER_SPECS[key]["name"]
    pct = 100 * s["pass"] / s["total"] if s["total"] else 0
    print(f"{name:<40} {s['total']:>5} {s['pass']:>5} {pct:>5.1f}%")

# Print violations per cluster
print("\n=== VIOLATION DETAILS ===")
for key, s in cluster_stats.items():
    if not s["violations"]: continue
    print(f"\n{CLUSTER_SPECS[key]['name']}:")
    for cat, c in s["violations"].most_common(10):
        print(f"  {c:>5} packets: {cat}")

# =====================================================================
# ID-field cardinality — validates the seq/nonce vs object-id claim
# (directed frames carry a per-packet-unique seq/nonce; the broadcast
#  frame carries a stable, repeating object identifier)
# =====================================================================
print("\n" + "=" * 70)
print("ID-FIELD CARDINALITY (seqnonce → ~unique per packet; objid → repeating)")
print("=" * 70)
for key, spec in CLUSTER_SPECS.items():
    off = spec.get("idfield_offset")
    role = spec.get("idfield_role")
    if off is None:
        continue
    sel = [p for p in all_pkts
           if (p[3], p[4], p[5], len(p)) == key and off + 1 < len(p)]
    if not sel:
        continue
    vals = [(p[off] << 8) | p[off+1] for p in sel]
    distinct = len(set(vals))
    frac = distinct / len(sel)
    if role == "seqnonce":
        verdict = "OK (per-packet)" if frac >= 0.10 else "UNEXPECTED: looks stable"
    else:  # objid
        verdict = "OK (stable)" if frac <= 0.05 else "UNEXPECTED: looks per-packet"
    print(f"  {spec['name']:<42} {role:<9} n={len(sel):<6} "
          f"distinct={distinct} ({100*frac:.1f}%) -> {verdict}")

# Uncovered packets (singletons / flag variants)
if uncovered:
    print(f"\n=== UNCOVERED PACKETS ({len(uncovered)}) ===")
    uncov_keys = Counter(k for k, _ in uncovered)
    for k, c in uncov_keys.most_common(20):
        print(f"  {c}x: {k}")
