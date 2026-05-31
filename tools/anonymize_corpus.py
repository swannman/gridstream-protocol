#!/usr/bin/env python3
"""Anonymize a GridStream capture corpus for safe publication.

Rewrites neighbor meter LAN IDs to synthetic IDs while preserving every
structural property the protocol reference depends on:

  * Each distinct real LAN ID maps to exactly one synthetic ID (a bijection),
    so distinct-meter counts and per-meter frame counts are unchanged.
  * A synthetic ID keeps the real ID's first byte (its network prefix — the
    common 0x80/0x90/0x50 meter prefixes as well as the 0x40 collector/gateway)
    and is otherwise a sequential placeholder, so prefix distributions are
    preserved.
  * The author's own meter is rewritten too, to the fixed synthetic 90000000 — so
    the published corpus contains no real meter ID at all, not even the author's.
    The real ID to match is supplied out-of-band via the GRIDSTREAM_AUTHOR_REAL
    environment variable (an 8-hex-digit LAN ID), so it never appears in this
    published source; if unset, no frame is treated as the author's. 90000000 is
    the ``..0000`` slot the sequential counter never reaches (it starts at 1), so
    it cannot collide with a neighbour's synthetic. The 90000000 mapping is
    documented publicly, which keeps the protocol doc's "our meter" figures
    reproducible against the committed corpus.
  * For CRC-covered frames (0x55/0xA5/0xD5) the 0x142A CRC is recomputed after
    the rewrite, so anonymized frames still validate.
  * Corrupt frames are dropped. Only CRC-valid frames and the 0xD2 family are
    kept. 0xD2 fails the 0x142A CRC by design but carries no LAN-ID fields, so it
    is safe to publish; every other CRC-BAD frame is discarded, because a bit
    error there could leave a real meter ID only a bit or two off — close enough
    to re-identify, yet not the exact match the value sweep would rewrite.

The real LAN-ID set is gathered from the source and destination address fields
of every CRC-OK frame (all frame lengths), located structurally by position
(``gridstream_parser.lan_ids``) rather than by guessing which bytes look like an
ID — so a collector/gateway with an unusual prefix is mined like any meter. CRC-BAD
frames are not mined for IDs — their bit errors would mint synthetic mappings for
noise. Replacement is then value-based: every occurrence of a known real ID, at
any offset in any frame, is rewritten, so a real meter is still scrubbed where it
appears in a CRC-BAD frame too.

Output is normalized to ``[CRC: OK] <hex>`` / ``[CRC: BAD] <hex>`` with ANSI
colour codes and per-line capture metadata (Baudrate/SNR/Pwr) stripped — that
metadata is capture-rig specific, not part of the protocol, and can fingerprint
the receiver.

Usage:
    python tools/anonymize_corpus.py OUT.log IN.log [IN2.log ...]
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gridstream_parser import (  # noqa: E402
    SYNC, crc16_gridstream, header_len_for, lan_ids,
)

ANSI = re.compile(r"\x1b\[[0-9;]*m")
LINE = re.compile(r"\[CRC:\s?(OK|BAD)\]\s+([0-9A-Fa-f]+)")

# Author's own meter. Rewritten like every neighbour so the public corpus carries
# no real meter ID, but to a fixed, documented synthetic (not a sequential one) so
# the protocol doc's "our meter" figures stay reproducible. 90000000 is safe: the
# sequential counter starts at 1, so no neighbour is ever assigned ..0000.
# The real ID is read from the environment so it never lives in this published
# source; set GRIDSTREAM_AUTHOR_REAL=<8 hex digits> when regenerating the corpus
# from a private raw capture. If unset, no frame is treated as the author's.
_author_real = os.environ.get("GRIDSTREAM_AUTHOR_REAL", "").strip()
AUTHOR_REAL = bytes.fromhex(_author_real) if _author_real else None
AUTHOR_SYNTH = bytes.fromhex("90000000")

COVERED = (0x55, 0xA5, 0xD5)  # frame types under the 0x142A CRC


def read_frames(paths):
    """Yield (status, packet_bytes) for each sync-intact frame (len >= 6)."""
    for path in paths:
        with open(path, errors="replace") as fh:
            for raw in fh:
                m = LINE.search(ANSI.sub("", raw))
                if not m:
                    continue
                try:
                    p = bytes.fromhex(m.group(2))
                except ValueError:
                    continue
                if len(p) < 6 or p[:3] != SYNC:
                    continue
                yield m.group(1), p


def build_map(frames):
    """real LAN ID -> synthetic LAN ID, gathered from the src/dst address fields
    of CRC-OK frames only (corrupt frames are never mined — their bit errors are
    not real meters). Addresses are located structurally by ``lan_ids`` (by
    position), so no prefix heuristic decides what counts as an ID."""
    ids = set()
    for status, p in frames:
        if status != "OK":
            continue
        ids.update(lan_ids(p))
    mapping, counter = {}, 0
    for real in sorted(ids):
        if AUTHOR_REAL is not None and real == AUTHOR_REAL:
            mapping[real] = AUTHOR_SYNTH
            continue
        counter += 1
        mapping[real] = bytes([real[0], 0x00, (counter >> 8) & 0xFF, counter & 0xFF])
    # No synthetic may collide with a real ID (would alias the value sweep).
    synths = {v for k, v in mapping.items() if v != k}
    assert not (synths & ids), "synthetic/real ID collision"
    return mapping


def anonymize(p, mapping):
    """Value-based, non-overlapping rewrite reading from the original bytes."""
    out = bytearray(p)
    i = 0
    while i + 4 <= len(p):
        repl = mapping.get(p[i:i + 4])
        if repl is not None and repl != p[i:i + 4]:
            out[i:i + 4] = repl
            i += 4
        else:
            i += 1
    return out


def main(argv):
    if len(argv) < 3:
        print(__doc__)
        return 1
    out_path, in_paths = argv[1], argv[2:]

    frames = list(read_frames(in_paths))
    mapping = build_map(frames)

    n_out = {"OK": 0, "BAD": 0}
    crc_checked = crc_ok = dropped = 0
    with open(out_path, "w") as out:
        for status, p in frames:
            t, hl = p[3], header_len_for(p[3])
            # Drop corrupt frames except the 0xD2 family (which carries no LAN
            # IDs): a bit error in a covered frame could leave a near-real ID.
            if status != "OK" and t != 0xD2:
                dropped += 1
                continue
            # Self-check: original CRC-OK covered frames must validate under
            # our 0x142A definition before we trust the recompute.
            if status == "OK" and t in COVERED and len(p) >= hl + 2:
                crc_checked += 1
                if crc16_gridstream(p[hl:len(p) - 2]) == (p[-2] << 8 | p[-1]):
                    crc_ok += 1
            a = anonymize(p, mapping)
            if status == "OK" and t in COVERED and len(a) >= hl + 2:
                crc = crc16_gridstream(bytes(a[hl:len(a) - 2]))
                a[-2], a[-1] = (crc >> 8) & 0xFF, crc & 0xFF
                out_status = "OK"
            else:
                out_status = status
            out.write(f"[CRC: {out_status}] {a.hex().upper()}\n")
            n_out[out_status] += 1

    mapped = sum(1 for k, v in mapping.items() if v != k)
    kept = len(mapping) - mapped
    print(f"input frames (sync-intact):  {len(frames)}", file=sys.stderr)
    print(f"distinct real LAN IDs:       {len(mapping)} "
          f"({mapped} remapped, {kept} kept)", file=sys.stderr)
    print(f"CRC self-check (OK covered): {crc_ok}/{crc_checked} "
          f"({100 * crc_ok / crc_checked:.3f}%)", file=sys.stderr)
    print(f"dropped corrupt (non-0xD2):  {dropped}", file=sys.stderr)
    print(f"emitted: OK={n_out['OK']}  BAD={n_out['BAD']}  -> {out_path}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
