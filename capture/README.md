# Capture / reproduction

How the corpus behind this repository was produced. This is a **receive-only**
pipeline — nothing here transmits.

## Hardware

- **SDR:** AirSpy R2, sampling 10 MS/s real, tuned to cover ~910–920 MHz (about
  80% of the GridStream channel set) simultaneously, without rotation.
- **Antenna:** a 902–928 MHz ISM-band antenna.
- **Host:** a Linux machine (the author uses a small single-board computer).

## Software

GNU Radio with the [`gr-smart_meters`](https://github.com/BitBangingBytes/gr-smart_meters)
out-of-tree module. The flowgraph is opportunistic burst detection rather than a
fixed-grid channelizer — GridStream is frequency-hopping and the spectrum is
idle most of the time, so energy-detect bursts anywhere in the window:

```
AirSpy Soapy source
  → fhss_utils.fft_burst_tagger     (FFT energy-detect bursts)
  → tagged_burst_to_pdu
  → cf_estimate                     (per-burst center-frequency estimate)
  → PDU FIR filter
  → GFSK demod
  → packet sync → CRC → log
```

The flowgraph itself is the stock `GridStream_AirSpy.grc` example shipped with
`gr-smart_meters` (linked above), run on the AirSpy R2 and tuned to the
~910–920 MHz window described here. The block chain above is that example's — no
custom flowgraph is needed, so the capture reproduces from an unmodified
`gr-smart_meters` checkout.

Each decoded packet is appended to a raw log as a line containing
`[CRC: OK] 80FF2A… Baudrate: …`. To watch a capture decode live, follow that log
with [`../tools/follow_capture.py`](../tools/follow_capture.py) — it tolerates the
ANSI colour, `[CRC: OK]` tag, and `Baudrate:`/`SNR:`/`Pwr:` tail of the raw line
format and prints one compact decode per frame. The committed
[`corpus.log`](corpus.log) is the **anonymized, normalized** derivative of such
raw logs (see *Anonymization* below); the tools default to it.

## CRC

GridStream uses CRC-16/CCITT (polynomial `0x1021`). The **PSE deployment uses
init value `0x142A`** — independently confirmed by the rtl_433 `gridstream.c`
decoder. The CRC covers the CI byte through the second-to-last byte; the sync,
type, reserved, and length bytes are outside coverage. See the CRC section of
[`../docs/gridstream-protocol.md`](../docs/gridstream-protocol.md) for exact byte
ranges and a reference implementation.

## Anonymization

The committed [`corpus.log`](corpus.log) is not a raw capture — it is the output
of [`../tools/anonymize_corpus.py`](../tools/anonymize_corpus.py), which makes a
raw log safe to publish while preserving every structural property the protocol
reference depends on. Re-running it on the same raw input reproduces the corpus
deterministically.

What the tool does:

- **Neighbor LAN IDs → synthetic IDs (bijection).** Every distinct real LAN ID
  maps to exactly one synthetic ID, so distinct-meter counts and per-meter frame
  counts are unchanged. A synthetic keeps the real ID's first byte (its network
  prefix — the common `0x80`/`0x90`/`0x50` meter prefixes as well as the `0x40`
  collector/gateway) and is otherwise a sequential placeholder — a zero second
  byte followed by a 16-bit counter — so prefix distributions are preserved.
- **The author's own meter** is rewritten the same way, to the fixed synthetic
  `90000000` — so the corpus contains no real meter ID at all, not even the
  author's. The real ID to match is supplied out-of-band via the
  `GRIDSTREAM_AUTHOR_REAL` environment variable and never appears in the source.
  `90000000` is the `··0000` slot the sequential counter (which starts at 1)
  never reaches, so it cannot collide with a neighbor's synthetic.
- **CRC recomputed.** For the covered frame types (`0x55`/`0xA5`/`0xD5`) the
  `0x142A` CRC is recomputed after the rewrite, so anonymized frames still
  validate. The tool first self-checks that the original CRC-OK frames validate
  under the documented CRC before it trusts the recompute.
- **Corrupt frames dropped**, except the `0xD2` family. `0xD2` fails the
  `0x142A` CRC by design but carries no LAN-ID fields, so it is kept; every other
  CRC-BAD frame is discarded, because a bit error there could leave a real meter
  ID only a bit or two off — close enough to re-identify, yet not the exact value
  the rewrite would catch.
- **Capture-rig metadata stripped.** ANSI colour codes and per-line
  `Baudrate`/`SNR`/`Pwr` fields are removed — they are receiver-specific, can
  fingerprint the capture rig, and are not part of the protocol. Output is
  normalized to `[CRC: OK] <hex>` / `[CRC: BAD] <hex>`, one frame per line.

The rewrite is value-based: every occurrence of a known real ID, at any offset,
is replaced — so a real meter is scrubbed even where it appears inside a frame's
payload, not only in the addressing fields. The real-ID set is mined only from
CRC-OK frames, with addresses located structurally by *position* (the parser's
`lan_ids`) rather than by guessing which bytes look like an ID — so a
collector/gateway with an unusual prefix is captured like any meter, and bit
errors in corrupt frames never mint synthetic mappings for noise.

Every quantitative figure in the protocol doc is drawn from this corpus; the
field-level conformance figures can be re-checked against it with
[`../tools/validate_protocol_doc.py`](../tools/validate_protocol_doc.py).
