# Landis+Gyr GridStream Protocol — PSE Deployment

Field-level reference for the Landis+Gyr GridStream sub-GHz RF mesh as deployed by Puget Sound Energy (PSE). The protocol is L+G-proprietary ("Grid Stream Protocol for Command Center"); this document describes its wire format as observed by passive RF capture, with PSE-specific constants.

**Observational basis:** passive AirSpy R2 capture at a residential location in Woodinville, WA. The figures here are drawn from the committed, anonymized corpus — 71,727 CRC-valid `0x55`/`0xA5`/`0xD5` packets plus 12,614 `0xD2` frames (which the `0x142A` CRC does not cover; see *0xD2 Directed Mesh*). The corpus records **52 distinct meters heard transmitting** and **461 distinct LAN IDs** across all address fields: 460 meters (the other 408 appearing only as relay destinations addressed by frames we received) plus the utility's data collector — a `0x40`-prefixed node the meters address as a destination but which we never hear transmit. Every quantitative figure in this document is drawn from the committed `capture/corpus.log`. Field layouts are given by byte offset; representative captured frames are included for each packet family.

**Notation.** ✓ marks a claim **validated** against the full capture corpus, ground-truth consumption data (PSE Green Button), or L+G documentation. ~ marks an **inferred** interpretation: consistent with the data but not independently confirmed — a working hypothesis. Byte offsets and on-the-wire constants are direct observations and are left unmarked. Fields whose purpose is unknown are labelled as such.

## Scope

- **Endpoint under study:** Landis+Gyr FOCUS AXRe-SD electric meter. In the committed corpus the author's own meter appears under the anonymized LAN ID `90000000` (its real ID is scrubbed — see [`tools/anonymize_corpus.py`](../tools/anonymize_corpus.py)).
- **Collector / head-end:** not directly observed. Relayed mesh traffic is visible; the head-end (Command Center) is upstream of the RF layer.

## Capture Setup

GridStream uses frequency-hopping spread spectrum (FHSS) across roughly 50 channels in the 902–928 MHz US ISM band; a meter transmits on a different channel at each transmission following a pseudo-random schedule. Capture runs on an AirSpy R2 sampling 10 MS/s real, covering ~910–920 MHz (about 80% of the channel set) simultaneously without rotation.

The flowgraph is opportunistic burst detection rather than a fixed-grid channelizer: AirSpy Soapy source → `fhss_utils.fft_burst_tagger` (FFT energy-detect bursts anywhere in the window) → `tagged_burst_to_pdu` → `cf_estimate` (per-burst center-frequency estimate) → PDU FIR filter → GFSK demod → packet sync → CRC → log. Because FHSS traffic does not sit on a clean fixed grid and the spectrum is idle most of the time, event-driven detection gives broad coverage at low CPU cost.

## Layer Model

```
┌──────────────────────────────────────────────────────────────────┐
│ APPLICATION LAYER: COSEM-style data model, WMBus-style metadata  │
│   • COSEM interface-class id (2B BE), classes 8-20               │
│   • L+G calling convention `09 03` (in place of a DLMS APDU)     │
│   • Register identity = class_id + selector byte                 │
│   • Per-packet sequence/value field (not a stable identifier)    │
│   • WMBus-style DIF (1B) + VIF (1B): value type + unit metadata  │
│   • Register VALUES are not present in plaintext                 │
├──────────────────────────────────────────────────────────────────┤
│ SESSION HEADER (in long frames): L+G proprietary                 │
│   • Unix timestamp (4B, 1 Hz monotonic)                          │
│   • Uptime since power-on (4B, 1 Hz monotonic)                   │
│   • Protocol constant `A4 0B`                                    │
│   • Routing trailer: FE + LAN + 00 + LAN + 00 + zero padding     │
│   • Per-message digest (keyed; mesh duplicate/integrity tag)     │
├──────────────────────────────────────────────────────────────────┤
│ MAC LAYER: WMBus-style framing over L+G addresses                │
│   • Sync word `80 FF 2A`                                         │
│   • Type byte: 0x55 broadcast / 0xA5 scheduled / 0xD5,0xD2 mesh  │
│   • Reserved byte (always 0x00)                                  │
│   • Length byte (WMBus L-field equivalent)                       │
│   • CI byte (WMBus CI equivalent) — packet class + transport     │
│   • Destination: 4B LAN ID, or 7B broadcast `FF×6 FE`            │
│   • Source: 4B LAN ID                                            │
├──────────────────────────────────────────────────────────────────┤
│ PHY: L+G proprietary, US-band GFSK                               │
│   • FHSS GFSK, 902-928 MHz US ISM                                │
│   • Symbol rates 9.6 / 19.2 / 38.4 kbps (auto-detected)          │
│   • Per-packet CRC-16/CCITT poly 0x1021, init 0x142A (PSE)       │
└──────────────────────────────────────────────────────────────────┘
```

The short mesh-control frames (the dominant `0xD5`/len-17 keepalive class and the `0xA5` beacon) carry no COSEM content — they are pure mesh housekeeping. Only the longer data-bearing frames carry the COSEM application payload.

## Physical Layer

| Parameter | Value |
|---|---|
| Band | 902–928 MHz US ISM (33 cm, FCC Part 15) |
| Modulation | 2-FSK / 2-GFSK (L+G-proprietary) |
| Symbol rates observed | 9.6 / 19.2 / 38.4 kbps (auto-detected per packet) |
| FHSS channels | ~50 across the band |
| Output power | +26 dBm ±1 dBm (~400 mW), up to 500 mW max per newer data sheet |
| Receive sensitivity | −108 dBm nominal |
| Adjacent channel power | 39 dBc nominal |

A separate 2.4 GHz ZigBee radio (2405–2480 MHz) exists on the meter module for the HAN side; it is unrelated to the sub-GHz GridStream RF described here.

## CRC-16

Polynomial `0x1021`, byte-MSB-first, **PSE init `0x142A`**.

**Coverage:** the CRC is computed from the CI byte through the second-to-last byte. The bytes *before* the CI — sync (0–2), type (3), the reserved byte, and the length byte — are **outside CRC coverage**:

- `0x55` / `0xD5` (6-byte header): CRC body starts at byte 6 (CI); bytes 3, 4, 5 are uncovered.
- `0xA5` (5-byte header): CRC body starts at byte 5.

Because the type, reserved, and length bytes are uncovered, a reception bit-flip in any of them passes CRC undetected and misframes nothing the CRC can catch. Anomalies confined to those bytes (a rare nonzero reserved byte, an occasional type-bit flip that makes a `0xD5` frame look like `0x55`) are reception errors, not protocol variants — parsers should key on the CRC-protected **CI byte**, which always reflects the true frame class. A flip in the length byte, by contrast, misframes the packet so the CRC runs over the wrong region and fails; consequently any length that passes CRC is a genuine format (length self-consistency — `length + header == captured bytes` — holds for 100% of the corpus).

```python
def crc16_gridstream(body, init=0x142A):
    crc = init
    for b in body:
        crc ^= (b << 8)
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc
```

The two CRC bytes are the last two bytes of the packet (high byte first).

`0xD2` frames are not covered by this CRC. The `0xD2`/CI=`0x52` variant ends in a 2-byte authentication tag (see *Security Model*); the other `0xD2` variants are plaintext but use a framing the standard validator does not check.

## Frame Header

There is no "subtype" field. A packet's format is keyed by **(type byte, length byte, CI byte)**. The same type with a different length is a different message format, and within a (type, length) family the **CI byte is the sub-discriminator** — e.g. `0xD5`/len-17 appears with CI `0x21`, `0x22`, and `0x29`.

### 0x55 / 0xD5 — 6-byte header

| Offset | Width | Field | Notes |
|---|---|---|---|
| 0–2 | 3 B | Sync / preamble | `80 FF 2A` |
| 3 | 1 B | Type | `0x55` broadcast, `0xD5` directed mesh |
| 4 | 1 B | Reserved | `0x00` |
| 5 | 1 B | Length | Body length, excluding the 6-byte header (`0x47` → 71 body bytes, 77 B total) |
| 6 | 1 B | CI (Control Information) | Frame class + transport sub-mode (see below) |

### 0xA5 / 0xD2 — 5-byte header

| Offset | Width | Field | Notes |
|---|---|---|---|
| 0–2 | 3 B | Sync / preamble | `80 FF 2A` |
| 3 | 1 B | Type | `0xA5` scheduled, `0xD2` directed mesh |
| 4 | 1 B | Length | Body length, excluding the 5-byte header (`0x12` → 18 body bytes, 23 B total) |
| 5 | 1 B | CI (Control Information) | Frame class + transport sub-mode |

`0xA5` and `0xD2` share only the header framing. Their bodies are unrelated: `0xA5` is a plaintext mesh beacon; `0xD2` is a directed-mesh family whose CI=`0x52` member is encrypted.

### CI byte

The CI byte (WMBus Control-Information analog) encodes two things:

- **High nibble = frame class (✓).** `0x2X` = directed data, `0x3X` = broadcast, `0x5X` = status push, `0x8X` = bulk transfer. This matches the family split in the catalog.
- **Low nibble = link/transport sub-mode (~).** Within the `0x2X` directed-data class, the values `0x21` / `0x22` / `0x29` are **validated not to encode direction** (✓ the same endpoint is the source under every value; reversed address pairs are vanishingly rare) and **not to select application type** (✓ the COSEM class mix and DIF/VIF distributions are statistically identical across them). That the low nibble instead selects a transport sub-mode — ARQ class, hop handling, or fragmentation state — is **inferred**, not confirmed; the exact meaning cannot be pinned down from passive capture. `0x22` shows a usage tendency toward small scalar reports but carries the same application objects as `0x21`/`0x29`.

| CI | Frame class | Used in |
|---|---|---|
| `0x21` `0x22` `0x29` | Directed data | `0xD5` len-17/20/22/23/25/28/29; `0xD2` len-10/15/21 |
| `0x30` | Broadcast | `0x55` len-35 |
| `0x3C` | Scheduled beacon | `0xA5` len-18 |
| `0x51` | Status push | `0xD5` len-71 (routine) |
| `0x52` | Encrypted directed | `0xD2` len-23 |
| `0x53` | Directed (short) | `0xD2` len-9 |
| `0x55` | Status push | `0xD5` len-71 (event-driven sibling of `0x51`) |
| `0x81` | Bulk transfer | `0xD5` len-125 |

## Packet Catalog

CRC-valid `0x55`/`0xA5`/`0xD5` traffic (71,727 packets). Counts and percentages are from `capture/corpus.log`; the `%` column is each cluster's share of all CRC-OK frames. `0xD2` is cataloged separately below.

| Type | Len (b5) | Total | CI (b6) | Count | % | Purpose | COSEM |
|---|---|---|---|---|---|---|---|
| `0xD5` | 17 (`0x11`) | 23 B | `0x29` / `0x21` / `0x22` | 12,644 / 5,735 / 2,779 | 29.50% | Short mesh control / keepalive | No |
| `0xD5` | 22 (`0x16`) | 28 B | `0x29` / `0x22` / `0x21` | 8,119 / 5,447 / 5,244 | 26.22% | Directed data | Yes |
| `0x55` | 35 (`0x23`) | 41 B | `0x30` | 15,440 | 21.53% | Broadcast announcement | Yes |
| `0xD5` | 23 (`0x17`) | 29 B | `0x29` / `0x21` | 6,526 / 2,264 | 12.25% | Directed data variant | Yes |
| `0xD5` | 71 (`0x47`) | 77 B | `0x51` / `0x55` | 4,927 / 272 | 7.25% | Status push (richest payload) | Yes |
| `0xA5` | 18 (`0x12`) | 23 B | `0x3C` | 1,827 | 2.55% | Scheduled mesh beacon | No |
| `0xD5` | 28 (`0x1C`) | 34 B | `0x22` / `0x29` / `0x21` | 442 / 3 / 1 | 0.62% | Peer-to-peer directed data | Yes |
| `0xD5` | 29 (`0x1D`) | 35 B | `0x29` | 20 | 0.03% | Rare mesh control | No |
| `0xD5` | 25 (`0x19`) | 31 B | `0x22` | 3 | <0.01% | Short directed | Yes |
| `0xD5` | 20 (`0x14`) | 26 B | `0x22` | 2 | <0.01% | Short directed | No |
| `0xD5` | 125 (`0x7D`) | 131 B | `0x81` | 1 | <0.01% | Bulk transfer (longest frame) | — |

These eleven documented clusters account for 71,696 of the 71,727 CRC-valid frames; the remaining **31** are type-bit reception flips (a `0x55`↔`0xD5` flip pairs one type with the other's length/CI byte), confirming the CI-byte-keyed parsing model.

## 0xD5 Mesh Control (len-17, len-29)

L+G mesh-routing / keepalive traffic with no COSEM content.

**len-17 (CI `0x29` dominant):**

| Offset | Width | Field |
|---|---|---|
| 0–5 | 6 B | Common header |
| 6 | 1 B | CI |
| 7–10 | 4 B | Destination LAN ID |
| 11–14 | 4 B | Source LAN ID |
| 15–20 | 6 B | Mesh control payload (no COSEM markers) |
| 21–22 | 2 B | CRC-16 |

**len-29 (CI `0x29`)** — a rare 35-byte control variant: header, destination + source LAN, an 18-byte control payload, CRC. Example:

```
80 FF 2A D5 00 1D 29 | 90 00 00 D5 | 90 00 00 FD | 5D C0 08 00 74 50 05 0C 01 2B 83 4F 81 5E 16 EA 24 00 | 51 AB
```

## 0xD5 Directed COSEM (len-22, len-23, len-28; rare len-20, len-25)

These share a body structure: header + addresses + session bytes + COSEM class_id + `09 03` calling convention + a length-dependent attribute payload.

| Offset | Width | Field | Notes |
|---|---|---|---|
| 0–5 | 6 B | Common header | |
| 6 | 1 B | CI | family-specific (`0x29`/`0x21`/`0x22`) |
| 7–10 | 4 B | Destination LAN ID | |
| 11–14 | 4 B | Source LAN ID | |
| 15–17 | 3 B | Session / sequence | |
| 18–19 | 2 B | COSEM class_id (BE) | |
| 20 | 1 B | `09` | L+G calling-convention marker |
| 21 | 1 B | `03` | (or `04` for the 4-byte-length variant) |
| 22+ | var | Attribute payload | length-dependent (below) |
| last 2 | 2 B | CRC-16 | |

**Payload by length:**

- **len-22 (28 B):** 4-byte payload at 22–25 — a 2-byte sequence/value field, then **byte 24 = DIF** (data type), **byte 25 = VIF** (unit). CRC at 26–27.
- **len-23 (29 B):** an extra sub-selector byte (`0x04`) at offset 22 precedes the 4-byte payload.
- **len-28 (34 B):** sub-selector `0x05`, the 5-byte L+G OBIS-like prefix `20 30 2D 84 80` at 23–27, then a 4-byte value. The richest directed-COSEM form; our meter originates these.

**Rare short-directed variants:**

- **len-20 (26 B, CI `0x22`):** dest + src LAN, then a `07 00 03` tag; no `09 03`.
  ```
  80 FF 2A D5 00 14 22 | 90 00 00 57 | 90 00 00 C7 | 51 0F 07 00 03 16 A4 1B 10 | 9E 1F
  ```
- **len-25 (31 B, CI `0x22`):** the `07 00 03` tag plus a `09 03` COSEM marker.
  ```
  80 FF 2A D5 00 19 22 | 90 00 01 A3 | 90 00 00 BE | 93 0F 01 00 0D 09 03 07 00 03 12 14 1A 70 | 70 24
  ```

## 0xD5 Status Push (len-71)

The 77-byte `0x47` frame — the richest plaintext payload. A long L+G session header (timestamps, routing trailer, padding) followed by a COSEM payload at byte 57+. CI is `0x51` for the routine push; `0x55` is an event-driven sibling (same `A4 0B` + OBIS structure, emitted on an irregular, jittery cadence rather than a clock-aligned period).

| Offset | Width | Field | Notes |
|---|---|---|---|
| 0–2 | 3 B | Sync | `80 FF 2A` |
| 3 | 1 B | Type | `0xD5` |
| 4 | 1 B | Reserved | `0x00` |
| 5 | 1 B | Length | `0x47` (71) |
| 6 | 1 B | CI | `0x51` (routine) / `0x55` (event-driven) |
| 7–10 | 4 B | Destination LAN ID | relayed / directed routing |
| 11–14 | 4 B | Source LAN ID | originating meter |
| 15 | 1 B | (high-entropy; purpose not determined) | |
| 16–19 | 4 B | Unix timestamp | 1 Hz monotonic, UTC seconds ✓ |
| 20 | 1 B | `0x00` | separator |
| 21 | 1 B | `0x01` (mostly) | |
| 22–23 | 2 B | Per-message digest | deterministic per (object, source, DIF, VIF, timestamp) ✓; keyed (not a plain CRC) and used for mesh duplicate detection ~ |
| 24–27 | 4 B | Uptime since power-on | 1 Hz monotonic ✓ |
| 28–29 | 2 B | Protocol constant | `A4 0B` |
| 30–31 | 2 B | Routing trailer start | `01 01` |
| 32 | 1 B | Sentinel | `FE` |
| 33–36 | 4 B | Source LAN ID (repeat) | equals 11–14 |
| 37 | 1 B | Separator | `00` |
| 38–41 | 4 B | Source LAN ID (repeat) | equals 11–14 |
| 42 | 1 B | Separator | `00` |
| 43–45 | 3 B | Routing trailer end | `01 03 25` |
| 46–56 | 11 B | Zero padding | `00 × 11` |
| 57–59 | 3 B | Payload transition | variable |
| 60–61 | 2 B | COSEM class_id (BE) | |
| 62 | 1 B | `09` | L+G calling-convention marker |
| 63 | 1 B | `03` | |
| 64 | 1 B | `00` | separator |
| 65 | 1 B | Register / attribute selector ~ | small stable per-class set ✓ |
| 66–70 | 5 B | L+G OBIS-like prefix | `20 30 2D 84 80` |
| 71–72 | 2 B | Per-packet sequence / nonce ~ | unique per packet even for a fixed selector ✓; not an identifier and not the value |
| 73 | 1 B | DIF (value type) | parses as IEC 13757-3 in 100% of frames ✓; see *Application Layer* |
| 74 | 1 B | VIF (unit) | low nibble always `0` ✓; high-nibble unit class ~ |
| 75–76 | 2 B | CRC-16 | |

The 15-byte COSEM region (60–74) is: class_id (2) + `09 03` (2) + `00` separator (1) + selector (1) + OBIS-like prefix (5) + per-packet sequence/nonce (2) + DIF (1) + VIF (1). This is COSEM short-name addressing wrapped in L+G's calling convention rather than a standard DLMS APDU.

## 0xD5 Bulk Transfer (len-125)

The longest frame observed — 131 bytes, CI `0x81`. After the 6-byte header: destination LAN, source LAN, then `D6 00 00 00 00 00 1F FE FE FE 7D FE`, the **destination + source LAN pair echoed again**, then `01 2A 28 00 90 07 B0 80 E0 00 11 2D`, followed by ~96 bytes of high-entropy data and the CRC. The tail measures ~6.17 bits/byte ✓ — below the ~8.0 of raw ciphertext — which suggests a bulk/compressed multi-register transfer rather than straight AES output ~ (it passes the standard `0x142A` CRC ✓, which the encrypted `0xD2` family does not). It carries no plaintext COSEM markers. Only one such frame is in the corpus, so the interpretation rests on a single sample.

## 0x55 Broadcast Announcement (len-35)

Advertises object identity to all stations. Announces *which* object has new data; the value is not carried here.

| Offset | Width | Field | Notes |
|---|---|---|---|
| 0–2 | 3 B | Sync | `80 FF 2A` |
| 3 | 1 B | Type | `0x55` |
| 4 | 1 B | Reserved | `0x00` |
| 5 | 1 B | Length | `0x23` (35) |
| 6 | 1 B | CI | `0x30` |
| 7–13 | 7 B | Broadcast destination | `FF FF FF FF FF FF FE` |
| 14–17 | 4 B | Source LAN ID | |
| 18–19 | 2 B | Session | |
| 20–23 | 4 B | Session sub-field | |
| 24–25 | 2 B | Protocol constant | `A4 0B` |
| 26–29 | 4 B | Source LAN ID (repeat) | |
| 30 | 1 B | `01` | |
| 31–32 | 2 B | COSEM class_id (BE) | |
| 33–34 | 2 B | `09 03` | calling-convention marker |
| 35–36 | 2 B | Object identifier | stable, repeating across packets ✓; advertised short-name ~ |
| 37 | 1 B | Trailer marker | `0x7E` |
| 38 | 1 B | Status code | `0x70` dominant ✓; `0x10`/`0x80`/`0x90`/`0x00` rare; meaning not determined |
| 39–40 | 2 B | CRC-16 | |

The object identifier at 35–36 is a genuinely repeating value ✓ (a given identifier recurs across many packets) — distinct from the per-packet-unique sequence/nonce field in directed frames. Its role as a network-advertised short-name is inferred (~); meters across the neighborhood broadcast a shared set of identifiers ✓, which is consistent with PSE provisioning all endpoints with a common object dictionary (~).

## 0xA5 Scheduled Mesh Beacon (len-18)

Pure mesh control, no COSEM. A periodic beacon ✓ — its mesh time-sync purpose is inferred (~). Uses the 5-byte header (length at byte 4, CI `0x3C` at byte 5, source LAN from byte 6). Byte 14 decrements roughly once per 30 minutes ✓; its role as a network-wide slot counter is inferred (~).

## 0xD2 Directed Mesh

A family of distinct sub-variants differentiated by CI byte (and length). Most are plaintext; only the CI=`0x52` variant is encrypted. All fail the standard `0x142A` CRC — the encrypted variant because its trailing bytes are an auth tag, the plaintext variants because they use a framing the standard validator does not check.

| Length | Body | Count | CI | Payload | Structure |
|---|---|---|---|---|---|
| 9 B | 4 | 3,389 | `0x53` (90%) | Plaintext (short) | sync + type + len + CI + seq + 2 body bytes (keepalive-like) |
| 10 B | 5 | 1,749 | `0x22` (97%) | Plaintext | sync + type + len + CI + seq + 3 body bytes (short directed control) |
| 15 B | 10 | 3,335 | `0x22` (98%) | Plaintext COSEM | class_id + `09 03` + object identity |
| 21 B | 16 | 289 | `0x22` (94%) | Plaintext COSEM | class_id + `09 03` + `05` sub-selector + OBIS prefix + value |
| 23 B | 18 | 3,198 | `0x52` (95%) | Encrypted | truncated-MAC AEAD (below) |

These five clusters are 11,960 of the 12,614 `0xD2` frames; the remaining ~654 are reception-damaged (corrupted length/CI). Because `0xD2` is not under the `0x142A` CRC, the parser cannot reject these the way it rejects a flipped covered frame, so they survive as a long low-count tail. The per-cluster CI percentages above are the dominant CI's share within each length.

**CI distinguishes encryption status:** CI=`0x22` ⇒ plaintext; CI=`0x52` ⇒ encrypted.

The plaintext CI=`0x22` variants are directed-mesh siblings of `0xD5` len-22/23/28 — the same `[class_id][09 03][…]` COSEM structure carried on the 5-byte-header `0xD2` framing — and decode the same way. Examples:

```
0xD2 len-9  (CI 0x53):  80 FF 2A D2 04 53 | BE | 06 FC
0xD2 len-10 (CI 0x22):  80 FF 2A D2 05 22 | C6 | 01 E9 24
0xD2 len-21 (CI 0x22):  80 FF 2A D2 10 22 | 86 | 01 01 | 00 0C | 09 03 | 05 | 20 30 2D 84 80 | 34 9C
```

### Encrypted variant (CI=0x52, 23 B)

| Offset | Width | Field | Notes |
|---|---|---|---|
| 0–2 | 3 B | Sync | `80 FF 2A` |
| 3 | 1 B | Type | `0xD2` |
| 4 | 1 B | Length | `0x12` (18) |
| 5 | 1 B | CI | `0x52` |
| 6 | 1 B | Sequence / nonce input ~ | |
| 7–8 | 2 B | AAD (mostly `01 02`) ~ | |
| 9–12 | 4 B | Plaintext counter ~ | timestamp-like; serves as nonce/counter input ~ |
| 13–14 | 2 B | AAD (mostly `00 01`) ~ | |
| 15–20 | 6 B | Ciphertext | high-entropy ✓ |
| 21–22 | 2 B | Authentication tag ~ | truncated MAC, not a CRC |

The frame partitions into a plaintext header, a 6-byte high-entropy ciphertext ✓, and a 2-byte trailing tag — a truncated-MAC AEAD shape ✓. The specific construction is inferred to be a WMBus-style AES-CCM (or AES-CTR + truncated CMAC) ~; the 6-byte ciphertext rules out a block-aligned CBC mode ✓. Taking the **9-byte header (bytes 6–14) as the nonce** (~), it is essentially unique across the corpus ✓ (2,916 distinct values across the 3,042 canonical 23 B encrypted frames); the 126 repeats are FHSS multi-path receptions of the same transmission or single-bit reception errors, not nonce reuse ✓ — so there is no exploitable nonce reuse. The 6-byte ciphertext is too small to hold full COSEM with addresses, so it most likely carries a mesh-internal command (route update, key operation, ACK) or a compressed directed-poll response (~). Its contents are not recoverable without the key.

## Application Layer

Data-bearing frames carry an L+G payload structured like COSEM short-name addressing. The skeleton is:

```
[class_id 2B BE] [09 03] [selector] [OBIS-like prefix] [seq/value] [DIF] [VIF]
```

### COSEM class IDs

The 2-byte big-endian class_id occupies the **standard IEC 62056-6-2 COSEM interface-class numbering space**, observed contiguous from 8 to 20 ✓. Standard classes appear alongside numbers (13, 14, 16, 20) that carry no standard COSEM class; reading those as L+G vendor extensions is inferred (~). The *numbering* is standard ✓, but the object/OBIS *allocations* behind the classes are L+G-specific.

Shares below are over the 5,199 CRC-valid status-push (`0xD5` len-71) frames in the corpus, every class 8–20 present:

| Class | COSEM interface class | Standard? | Share |
|---|---|---|---|
| 8 (`0x08`) | Clock | Standard | 1.40% |
| 9 (`0x09`) | Script_table | Standard | 0.56% |
| 10 (`0x0A`) | Schedule | Standard | 0.02% |
| 11 (`0x0B`) | Special_days_table | Standard | 1.40% |
| 12 (`0x0C`) | **Association_SN** | Standard | **59.53%** |
| 13 (`0x0D`) | L+G vendor extension | Non-standard | 19.43% |
| 14 (`0x0E`) | L+G vendor extension | Non-standard | 1.06% |
| 15 (`0x0F`) | **Association_LN** | Standard | 5.21% |
| 16 (`0x10`) | L+G vendor extension | Non-standard | 10.69% |
| 17 (`0x11`) | SAP_assignment | Standard | 0.27% |
| 18 (`0x12`) | Image_transfer | Standard | 0.02% |
| 19 (`0x13`) | IEC_local_port_setup | Standard | 0.06% |
| 20 (`0x14`) | L+G vendor extension | Non-standard | 0.35% |

Association_SN dominates at 59.53% ✓, consistent with meters advertising their short-name object directory (~). Our meter advertises 170 distinct `(class_id, DIF, VIF)` register objects across its len-71 status-push frames ✓.

### Markers and fields

- **`09 03`** — constant regardless of class ✓; read as an L+G "attribute value follows" calling convention (~). A `09 04` variant (A-XDR octet-string length 4 instead of 3) occurs in 9.14% of status-push (len-71) frames ✓ at the same offset (byte 63) — a benign length-prefix variant in the same role (~).
- **Selector** (byte 65 in len-71) — small and stable per class ✓, and its high nibble tracks the advertised class_id ✓; reading it as a register/attribute index under short-name addressing is inferred (~).
- **OBIS-like prefix `20 30 2D 84 80`** — a 5-byte constant ✓, and not a standard OBIS code ✓ (byte 0 `0x20` exceeds the IEC 62056-61 medium range); read as a vendor logical-name reference (~).
- **Per-packet sequence / nonce** (bytes 71–72 in len-71; the post-`09 03` 2-byte field in directed frames) — unique per packet even for a fixed selector ✓; not a stable identifier and not the measured value ✓. Whether it is a sequence counter or a nonce is not determined.

### DIF / VIF metadata

The two bytes after the addressing fields are WMBus-style metadata declaring the value's type and unit — not the value itself.

**DIF (Data Information Field, byte 73 in len-71)** is a structurally valid IEC 13757-3 §6.2.2 byte in 100% of frames ✓:

```
Bit 7    : Extension flag (0 = no DIFE)
Bits 6-5 : Function field (00 = instantaneous)
Bit 4    : Storage number LSB (1)
Bits 3-0 : Data length / coding
```

99.98% of status-push DIFs (5,198 / 5,199) have bit 7 = 0, function = instantaneous, storage = 1 — so the byte falls in `0x11`–`0x1F` — with a single `0x20` frame (function = maximum) the lone exception ✓. Shares of the 5,199 frames:

| DIF | Type | Share |
|---|---|---|
| `0x11` | uint8 | 43.12% |
| `0x12` | uint16 | 12.18% |
| `0x13` | uint24 | 10.00% |
| `0x14` | uint32 | 10.21% |
| `0x15` | float32 | 7.89% |
| `0x16` | uint48 | 5.64% |
| `0x17` | uint64 | 4.04% |
| `0x18` | selection-for-readout | 3.23% |
| `0x19`–`0x1B` | 2/4/6-digit BCD | 3.19% |
| `0x1C`–`0x1F` | 8-digit BCD … special functions | 0.48% |
| `0x20` | function = maximum (non-instantaneous) | 0.02% |

**VIF (Value Information Field, byte 74 in len-71)** — read as the unit field (~). The low nibble is `0` in 100% of frames ✓; the high nibble varies across `0x0`–`0x9` ✓. Reading the high nibble as a unit class under a custom L+G VIF mapping with the multiplier bits zeroed is inferred (~); translating a code to a physical unit requires the meter's object dictionary.

### Register values are not in plaintext

The plaintext RF channel carries register **identity** (class_id + selector) and **metadata** (DIF type, VIF unit) — an Association_SN-style "object X has new data, of type Y, in unit Z" advertisement — but **not the register value (✓, ground-truthed against PSE Green Button)**. No monotone cumulative register (e.g. kWh) appears in any plaintext field, and the candidate value fields do not correlate with metered consumption ✓. Cumulative energy and instantaneous measurements are therefore not on the plaintext wire; they most plausibly travel in the encrypted `0xD2`/CI=`0x52` channel under per-endpoint AES-256 (~), which is not passively recoverable either way. The authoritative source for consumption data is PSE Green Button (opower) hourly export.

## Security Model

**Two-layer architecture.** The RF wire layer is the L+G-proprietary "Grid Stream Protocol for Command Center." Upstream, Command Center acts as an **ANSI C12.22 Master Relay and Gateway**: it assigns a C12.22 App Title to each endpoint and maintains C12.19 extended tables (decades 12–13, network control/status) per endpoint. C12.22 IDs and the wire→C12.19 mapping live at the head-end, not on the RF wire.

**Encryption (per L+G Security Architecture, §6.2/§6.4):**

| Key | Used for | Scope |
|---|---|---|
| Individual endpoint key | Unicast upstream/downstream to a specific endpoint | Per-endpoint AES-256, vaulted in HES Key Manager |
| Segment key | Broadcast downstream commands to all endpoints in a collector's mesh pocket | Per-mesh-pocket AES-256 |
| System key | Migration target replacing individual keys | Network-wide |

The key hierarchy above is documented by L+G ✓. Mapping it onto our capture: the encrypted `0xD2`/CI=`0x52` frames are inferred to use the individual endpoint key for the source/destination pair (~) — the AEAD shape and unicast addressing fit, but we cannot decrypt to confirm. Per the same documentation, downstream commands are additionally ECDSA-signed against the utility ECC private key (root-of-trust in a Thales LUNA HSM) ✓. Keys never appear on the wire ✓; recovering plaintext requires Key Manager access or firmware extraction.

## Derived Signals

**Outage detection.** `unix_time (bytes 16–19) − uptime (bytes 24–27)` from any len-71 frame gives the meter's last power-on moment. Across neighbors this resolves to a common timestamp matching the known PSE neighborhood outage of late October 2025 ✓. A sudden uptime reset signals power loss for that meter.

**Mesh visibility / privacy.** From a single antenna at one residence, 52 distinct meters were heard transmitting directly and 461 distinct LAN IDs appear across all address fields ✓ (the other 409 only as destinations addressed by frames we received: 408 relay meters plus the utility's `0x40`-prefixed data collector — see the egocentric-capture note in [`tools/mesh_topology.py`](../tools/mesh_topology.py)). Broadcast, beacon, and status-push frames (`0x55`, `0xA5`, most `0xD5`) are plaintext, so neighborhood mesh **metadata** — household count, which objects each meter advertises, broadcast cadence and timing, outage state — is fully visible to passive capture ✓. The actual measured **values** are absent from the plaintext air (✓) and travel only in the encrypted channel (~), so consumption data is not exposed.

## Validation

Every constant and field layout above is machine-checkable against the committed corpus, and two independent measurements converge on near-total agreement:

- **Catalog coverage: 99.96%** — 71,696 / 71,727 CRC-valid frames fall in one of the eleven documented `(type, length, CI)` clusters; the 31-frame remainder are type-bit reception flips (a `0x55`↔`0xD5` flip pairs one type with the other's length/CI). This count keys only on the CRC-protected discriminators, so a reception flip in an *uncovered* header byte still counts toward its true cluster.
- **Field-level conformance ([`tools/validate_protocol_doc.py`](../tools/validate_protocol_doc.py)): 99.8% / 99.75%** — this validator encodes each cluster's full field spec and applies a stricter match: it *also* requires the CRC-uncovered header bytes to be pristine (reserved byte `0x00`, exact type), so reception flips in those bytes fall out as "uncovered" instead of folding into a cluster. Under that stricter test 71,595 / 71,727 (99.8%) match a documented cluster, and **99.75%** of those (71,415 / 71,595) pass *every* field check — all asserted constants (`A4 0B`, the OBIS-like prefix `20 30 2D 84 80`, the `0x55` byte-37 `0x7E` sentinel, the status-push routing trailer), the fixed broadcast-destination address (`FF…FE`), COSEM `class_id` range, the WMBus DIF (instantaneous / storage = 1 / no-extension) and VIF low-nibble = 0 patterns, the repeated source LAN ID, and the CRC. The residual 0.25% (180 frames) matched a cluster but tripped one of these deliberately-conservative inner rules. They are **not** reception damage — every one re-validates under the CRC and the deviating bytes all sit inside the CRC-covered region, so they are real minority protocol values the strict spec doesn't model. The violations (a frame can trip several) are dominated by ~157 DIFs that are non-instantaneous or have storage ≠ 1 (maximum/minimum or stored-historical register reports) and ~74 `0xD5/0x17` frames carrying an out-of-range `class_id` with a non-standard byte 20 (a minority sub-variant). They are surfaced here rather than hidden; the *CRC-16* section's reception-flip story explains the 132 **uncovered** frames, not these.
- **Length self-consistency 100%** — `length + header == captured bytes` for every CRC-valid frame, and the CRC re-validates under init `0x142A` for 71,727 / 71,727.

The two coverage figures differ only in how they treat reception bit-flips in the CRC-*uncovered* header bytes (type, reserved, length): the catalog count folds them into their true cluster, the validator counts them as uncovered. Both are grounded in the committed `capture/corpus.log`; the field-level conformance figure is reproducible with [`tools/validate_protocol_doc.py`](../tools/validate_protocol_doc.py).

An interactive field-level decoder with a captured example of every packet family is at [`visualizations/packet-analyzer.html`](../visualizations/packet-analyzer.html).

## References

- Recessim wiki — https://wiki.recessim.com/view/Landis%2BGyr_GridStream_Protocol
- `gr-smart_meters` GNU Radio module — https://github.com/RECESSIM/gr-smart_meters
- rtl_433 [`gridstream.c`](https://github.com/merbanan/rtl_433/blob/master/src/devices/gridstream.c) decoder — independent confirmation of the PSE CRC init `0x142A`
- L+G doc 98-9112 Rev AA — *High Speed FOCUS AX Modular Gridstream RF Endpoint Data Sheet*. Confirms the sub-GHz wire protocol as "Grid Stream Protocol for Command Center"; lists ANSI C12.19 as internal data model; ZigBee listed separately for the 2.4 GHz HAN radio.
- L+G doc 98-9108 Rev BA — *RF Mesh Command Center User Guide* v8.1. Command Center as ANSI C12.22 Master Relay + Gateway; App Titles; C12.19 extended tables (decades 12–13).
- L+G Security Architecture (June 2021) — per-endpoint AES-256 individual keys (§6.2), segment keys for mesh-pocket broadcast, ECDSA-signed downstream commands (§6.4), Thales LUNA HSM root-of-trust (§6.1).
- L+G FOCUS AXe data sheet — L+G-proprietary 2-FSK/2-GFSK at 9.6–115.2 kbps in 902–928 MHz.
- IEC 62056-6-2 — COSEM data model and interface-class catalogue.
- IEC TR 62056-61 — short-name (SN) allocation conventions.
- IEC 13757-3 — Wireless M-Bus application layer (DIF/VIF) and security profiles.
- DLMS UA Blue Book — short-name addressing reference.
- gurux-dlms (Python) — https://github.com/Gurux/gurux.dlms.python — authoritative COSEM `ObjectType` enum.
- PSE Green Button hourly consumption (opower) — authoritative metered-energy source.
