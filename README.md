# GridStream Protocol — Landis+Gyr AMI RF (PSE Deployment)

A field-level reference for the **Landis+Gyr GridStream** sub-GHz RF mesh used by
advanced metering infrastructure (AMI), reverse-engineered from passive radio
capture of the **Puget Sound Energy (PSE)** deployment in Woodinville, WA.

GridStream is an L+G-proprietary protocol ("Grid Stream Protocol for Command
Center"). Public documentation of its wire format is thin and scattered; this
repository aims to be the most complete and rigorously-validated open reference
for it — every structural claim is either checked against a full capture corpus,
ground-truthed against real consumption data, or explicitly marked as inferred.

## Why this is different

- **Full-corpus, not anecdotes.** Claims are derived from 71,727 CRC-valid
  `0x55`/`0xA5`/`0xD5` packets (plus 12,614 `0xD2` frames) — 52 meters heard
  transmitting and 461 distinct LAN IDs observed in all (460 meters plus the
  `0x40`-prefixed data collector the meters report to). Every figure is drawn
  from the committed corpus ([`capture/corpus.log`](capture/corpus.log)).
- **Validated vs. hypothesized is explicit.** Every interpretive claim in the
  reference carries a marker: ✓ = validated against the corpus, ground-truth, or
  L+G documentation; ~ = a working hypothesis consistent with the data but not
  independently confirmed.
- **Reproducible.** The spec is encoded as runnable checks
  ([`tools/validate_protocol_doc.py`](tools/validate_protocol_doc.py)) you can
  run against your own capture, and every statistic in the README and reference
  is grounded in the committed corpus
  ([`capture/corpus.log`](capture/corpus.log)).
- **Ground-truthed.** A key negative result — that meter register *values*
  (e.g. kWh) are **not** present on the plaintext wire — was established by
  correlating every plaintext candidate field against PSE Green Button hourly
  consumption.

## Repository layout

```
docs/           gridstream-protocol.md    — the field-level protocol reference (start here)
tools/          gridstream_parser.py      — the reference frame parser (shared by the tools)
                follow_capture.py         — stream a live/growing capture log through the parser
                mesh_topology.py          — render the egocentric mesh activity graph (HTML)
                anonymize_corpus.py       — scrub a raw capture into a publishable corpus
                validate_protocol_doc.py  — spec-as-code validator (run against your own capture)
visualizations/ packet-analyzer.html      — interactive in-browser frame decoder
                packet-crafter.html       — interactive byte-by-byte view of how fields compose a 0xD5 beacon
                mesh_topology.html        — pre-rendered mesh graph from capture/corpus.log (open it)
capture/        corpus.log, README.md     — the anonymized corpus + receive-only SDR reproduction
```

## Quick start

- **Read the spec:** open [`docs/gridstream-protocol.md`](docs/gridstream-protocol.md).
- **Decode a frame:** open [`visualizations/packet-analyzer.html`](https://html-preview.github.io/?url=https://github.com/swannman/gridstream-protocol/blob/main/visualizations/packet-analyzer.html)
  in any browser and click **Try example**, or paste any hex string — every line
  of [`capture/corpus.log`](capture/corpus.log) is a real CRC-valid frame, and the
  [protocol reference](docs/gridstream-protocol.md) has annotated examples inline.
  For a terminal decode, pass the same hex to the parser:
  ```bash
  python tools/gridstream_parser.py 80FF2A...      # one frame, fully labelled
  cat capture/corpus.log | python tools/gridstream_parser.py   # a whole log
  ```
- **Build a frame to see how the bytes fit:** open
  [`visualizations/packet-crafter.html`](https://html-preview.github.io/?url=https://github.com/swannman/gridstream-protocol/blob/main/visualizations/packet-crafter.html)
  in any browser — an interactive, byte-by-byte view of the `0xD5` status-push
  beacon. Edit a field (address, timestamp, object selector, CRC init…) and watch
  the frame and its CRC recompute live, with a per-byte breakdown of what each
  field means and how confident the interpretation is. Useful for building
  intuition about field relationships — e.g. how the derived `class = (selector +
  8) >> 4` bin tracks the selector.
- **Watch a live capture:** stream a growing capture log (or a piped decoder)
  through the parser, one compact line per frame:
  ```bash
  python tools/follow_capture.py --follow /path/to/capture.log
  ```
- **See the mesh:** open [`visualizations/mesh_topology.html`](https://html-preview.github.io/?url=https://github.com/swannman/gridstream-protocol/blob/main/visualizations/mesh_topology.html) in any browser
  for an interactive, egocentric activity graph (who addresses whom, scrubbable
  through capture sequence). Regenerate it from any corpus with:
  ```bash
  python tools/mesh_topology.py visualizations/mesh_topology.html capture/corpus.log
  ```
  Read its bias note first — a single-receiver capture maps *proximity to the
  antenna*, not network centrality.
- **Validate against your own capture:**
  ```bash
  python tools/validate_protocol_doc.py 'captures/*.log'
  ```
  (logs are produced by the capture pipeline in [`capture/`](capture/)).

## Scope

- **Covered:** PHY parameters, the CRC-16 variant and its byte coverage, the
  frame header and CI-byte model, a catalog of every observed packet family with
  full field layouts, the COSEM-style application layer (class IDs, DIF/VIF
  metadata), the encrypted `0xD2`/CI=`0x52` frame structure, the documented L+G
  security model, and derived signals (outage detection, mesh-metadata privacy).
- **Not covered:** decryption of the encrypted frame type (requires the
  per-endpoint AES-256 key, which is not on the wire), the upstream Command
  Center / C12.22 head-end internals, and anything requiring transmission.

## Ethics and legality

This is **receive-only** research on radio that the author's own meter — and the
surrounding neighborhood — broadcasts in the license-free 902–928 MHz ISM band.

- Nothing in this repository transmits, injects, or commands meters.
- No encryption is broken. The one encrypted frame type is documented
  *structurally only*; its contents are not recoverable without the
  per-endpoint key, and no key-recovery is attempted here.
- **Consumption data is not exposed.** Register values are not present on the
  plaintext wire (this is a measured result, not an assumption). This project
  does not enable reading anyone's energy usage.
- What *is* visible to any passive listener is mesh **metadata** (neighbor
  count, which objects each meter advertises, broadcast timing, outage state).
  It is documented here for transparency about the deployment's privacy posture,
  not to profile anyone — no neighbor data is published.
- Receiving radio communications you are not the intended recipient of may be
  regulated where you live. You are responsible for complying with your local
  laws. This material is provided for interoperability, education, and defensive
  understanding of AMI infrastructure.

## Prior work and credits

This builds on the open-source GridStream community:

- **RECESSIM** — the [Recessim wiki GridStream
  page](https://wiki.recessim.com/view/Landis%2BGyr_GridStream_Protocol) and the
  [`gr-smart_meters`](https://github.com/BitBangingBytes/gr-smart_meters) GNU Radio
  module, which this capture pipeline depends on.
- **rtl_433** — its [`gridstream.c`](https://github.com/merbanan/rtl_433/blob/master/src/devices/gridstream.c)
  decoder independently confirms the PSE CRC init value `0x142A`.

L+G product/security documentation is *referenced* (see the protocol doc's
References section), not redistributed.

## License

- **Code** (`tools/`): MIT — see [`LICENSE`](LICENSE).
- **Documentation** (`docs/`, the README files): CC BY-SA 4.0 — see
  [`LICENSE-docs.md`](LICENSE-docs.md).

## Disclaimer

Not affiliated with, endorsed by, or sponsored by Landis+Gyr or Puget Sound
Energy. "Landis+Gyr", "GridStream", and "Command Center" are trademarks of their
respective owners and are used here only for identification.
