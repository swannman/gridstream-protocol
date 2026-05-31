#!/usr/bin/env python3
"""Live GridStream capture monitor — stream a growing log through the decoder.

The SDR pipeline (see ``capture/README.md``) appends one decoded frame per line
to a capture log, e.g.::

    [CRC: OK] 80FF2A55002330FFFFFFFFFFFFFE900000CC...22E0 Baudrate: 9600 SNR: ...

``gridstream_parser.py`` decodes a *finite* batch — it reads all of stdin/the
file before emitting anything, so it cannot follow a log that is still being
written. This tool streams instead: it reads each line as it arrives, pulls the
frame hex out (tolerating the ANSI colour, ``[CRC: OK]`` tag, and
``Baudrate:``/``SNR:``/``Pwr:`` tail via the parser's own ``_extract_hex``),
decodes it, and prints a compact one-line summary — suitable for watching a live
capture scroll by.

Usage::

    # Follow a growing capture log (tail -F semantics: survives logrotate)
    python follow_capture.py --follow /var/log/gridstream/capture.log

    # Pipe a live decoder straight in
    your_sdr_decoder | python follow_capture.py

    # Replay a saved log at full speed
    cat capture/corpus.log | python follow_capture.py

Options::

    --follow PATH   Follow a file, reading new appends as they are written.
    --from-start    With --follow, decode the existing contents first (default:
                    start at end of file, show only newly-written frames).
    --full          Print the parser's full multi-line decode per frame instead
                    of the compact one-liner (handy to drill into a frame you
                    just saw scroll past).

The compact output is one frame per line and greppable — filter with the usual
tools (``... | grep 0xD5``, ``... | grep 'crc BAD'``).
"""
from __future__ import annotations

import os
import sys
import time

from gridstream_parser import ParsedFrame, _extract_hex, format_frame, parse_frame


def compact_line(f: ParsedFrame, ts: str) -> str:
    """One aligned, greppable line summarising a decoded frame."""
    if not f.valid_sync:
        body = f.raw_hex if len(f.raw_hex) <= 32 else f.raw_hex[:32] + "…"
        return f"{ts}  (no sync)  {body}"
    cols = [ts, f"0x{f.type_byte:02X}"]
    cols.append(f"CI 0x{f.ci_byte:02X}" if f.ci_byte is not None else "CI ----")
    if f.crc is None or not f.crc.covered:
        crc = "crc —"
    elif f.crc.ok:
        crc = "crc ok"
    else:
        crc = "crc BAD"
    cols.append(f"{crc:<7}")
    src = f.addresses.get("src", "")
    dst = f.addresses.get("dst", "")
    cols.append(f"src {src:<8}" if src else " " * 12)
    cols.append(f"dst {dst:<14}" if dst else " " * 18)
    if f.cosem and f.cosem.class_id is not None:
        cols.append(f"cls {f.cosem.class_id} {f.cosem.class_name}")
    elif f.ci_name and f.ci_name != "unknown":
        cols.append(f"({f.ci_name})")
    return "  ".join(cols).rstrip()


def _follow_file(path: str, from_start: bool, poll: float = 0.5):
    """Yield appended lines from a growing file, ``tail -F`` style.

    Survives truncation and rotation: when the path's inode changes or the file
    shrinks below our read offset (logrotate, capture-service restart), reopen
    from the top. Partial trailing lines are buffered until their newline lands.
    """
    while True:                                   # (re)open loop
        try:
            fh = open(path, "r")
        except FileNotFoundError:
            time.sleep(poll)
            continue
        try:
            inode = os.fstat(fh.fileno()).st_ino
            if not from_start:
                fh.seek(0, os.SEEK_END)
            from_start = True                     # honour --from-start only once
            buf = ""
            while True:
                chunk = fh.readline()
                if chunk:
                    buf += chunk
                    if buf.endswith("\n"):
                        yield buf
                        buf = ""
                    continue
                try:                              # EOF: rotated/truncated, or just idle?
                    st = os.stat(path)
                except FileNotFoundError:
                    break
                if st.st_ino != inode or st.st_size < fh.tell():
                    break                         # reopen
                time.sleep(poll)
        finally:
            fh.close()


def _follow_stdin():
    """Yield lines from stdin as they arrive (line-buffered, no read-ahead)."""
    while True:
        line = sys.stdin.readline()
        if not line:
            return
        yield line


def main(argv: list) -> int:
    args = argv[1:]
    if "-h" in args or "--help" in args:
        print(__doc__)
        return 0
    full = "--full" in args
    from_start = "--from-start" in args
    args = [a for a in args if a not in ("--full", "--from-start")]
    follow_path = None
    if "--follow" in args:
        idx = args.index("--follow")
        follow_path = args[idx + 1] if idx + 1 < len(args) else None
        del args[idx:idx + 2]
        if not follow_path:
            print("--follow needs a PATH argument", file=sys.stderr)
            return 2

    if follow_path:
        source = _follow_file(follow_path, from_start)
    elif not sys.stdin.isatty():
        source = _follow_stdin()
    else:
        print(__doc__, file=sys.stderr)
        return 2

    try:
        for raw in source:
            h = _extract_hex(raw)
            if not h:
                continue
            ts = time.strftime("%H:%M:%S")
            try:
                f = parse_frame(h)
            except ValueError as e:
                print(f"{ts}  skip: {e}", file=sys.stderr, flush=True)
                continue
            if full:
                print(format_frame(f), flush=True)
                print(flush=True)
            else:
                print(compact_line(f, ts), flush=True)
    except KeyboardInterrupt:
        return 0
    except BrokenPipeError:                       # downstream `head`/`grep` closed
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
