# BTsnoop Capture Files — Notes

Notes on the BTsnoop log files in `bt_captures/`.  Nine application-level captures were analysed (plus one HCI connection-level file).  They were produced by recording BLE HCI traffic on the host while interacting with a robot via its companion app.

---

## 1. BTsnoop File Format

All five files conform to the standard **BTsnoop version 1** format ([RFC / Google spec](https://www.fte.com/WebHelpII/Content/Technical_Information/BT_Snoop_File_Format.htm)):

| Field | Value |
|-------|-------|
| File magic | `62 74 73 6e 6f 6f 70 00` (`btsnoop\0`) |
| Version | `1` |
| Datalink type | `1001` — HCI UART (H4) |

Each record in the file has a 24-byte header followed by the packet data:

```
Offset  Size  Content
──────  ────  ──────────────────────────────────────────
 0       4    Original length (big-endian uint32)
 4       4    Included length (big-endian uint32)
 8       4    Packet flags (big-endian uint32)
12       4    Cumulative drops (big-endian uint32)
16       8    Timestamp (big-endian int64, microseconds since Jan 1 2000)
24       N    Packet data (N = included length)
```

**Packet flags** relevant bits:
- Bit 0: `0` = sent (host → controller), `1` = received (controller → host)
- Bit 1: `1` = HCI command or event; `0` = ACL data

---

## 2. File Inventory

| File | Size | Records | H→C pkts | C→H pkts | Counter range | Session |
|------|------|---------|----------|----------|--------------|---------|
| `turn right.log` | 12 554 B | 261 | 92 | 169 | `0x560B – 0x5C53` | 1 |
| `turn left.log` | 18 588 B | 386 | 135 | 251 | `0x5C54 – 0x65C0` | 1 |
| `forward.log` | 16 972 B | 357 | 126 | 231 | `0x65DC – 0x733B` | 1 |
| `backward.log` | 15 065 B | 313 | 110 | 203 | `0x733C – 0x828C` | 1 |
| `park.log` | 31 068 B | 629 | 217 | 412 | `0x838C – 0xF7D9` | 1 |
| `select.log` | — | — | ≈ 9 | — | `0x0656 – 0x0860` | 2 |
| `raise.log` | — | — | ≈ 100 | — | `0x0861 – 0x62A0` | 2 |
| `lower.log` | — | — | ≈ 200 | — | `0x64A1 – 0xAEC5` | 2 |
| `turn right 2.log` | — | 289 | 100 | 189 | `0xAEC7 – 0xBD0E` | 2 |
| `connect.log` | — | — | — | — | — | 2 |

### Chronological order

The shared 16-bit counter proves the first five captures were recorded in sequence on the **same connected session**:

```
turn right  →  turn left  →  forward  →  backward  →  park
0x560B–5C53    0x5C54–65C0    0x65DC–733B   0x733C–828C   0x838C–F7D9
             (continuous)  (gap ≈ 27)   (continuous)  (gap ≈ 255)
```

The **session 2** captures are also in counter sequence, confirming they were recorded in one session after unpairing/re-pairing:

```
select  →  raise  →  [gap]  →  lower  →  turn right 2
0x0656–0860  0x0861–62A0  62A1–64A0   0x64A1–AEC5   0xAEC7–BD0E
```

`connect.log` contains HCI-level connection setup frames (L2CAP CoC credit exchange) and does not contain application-level CoC payloads.

---

## 3. Host → Robot Payload Size Breakdown

Sizes of **L2CAP CoC** payloads sent from host to robot (CID `0x0041` in session 1, `0x0049` in session 2):

| Payload size | fwd | bwd | left | right | park | right2 | raise | lower | select | Meaning |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|--------|
| **5 B** | 11 | 9 | 12 | 8 | 20 | 9 | — | — | — | Unknown short command (see §4) |
| **13 B** | 14 | 15 | 8 | 6 | 113 | 16 | ≈ 80 | ≈ 150 | ≈ 4 | Heartbeat / keep-alive |
| **28 B** | — | — | — | — | 5 | 1 | — | — | — | Extended status report |
| **30 B** | 8 | 10 | 4 | 3 | 66 | 8 | ≈ 10 | ≈ 40 | — | Tick status / sensor frame |
| **34 B** | 88 | 71 | 103 | 70 | 0* | 64 | 0 | 0 | 9 | Movement command |
| **39 B** | — | — | 1 | — | 4 | — | — | — | — | Merged heartbeat + 30-byte frame |
| **44 B** | — | — | — | — | 2 | — | 4 | 0 | — | Park / raise / lower toggle |
| **48 B** | — | — | 1 | — | — | — | — | — | — | Merged 34-byte + 30-byte frame |

\* `park.log` contains **no** 34-byte movement packets — the park button does not drive the motors.

---

### 4.1 — Session-Specific Tokens

A key finding from `turn right 2.log` (a second session after unpairing) is that **three bytes in every packet change between sessions** and are constant within a session:

| Token | Packet byte | Session 1 | Session 2 | Role |
|-------|-------------|-----------|-----------|------|
| `tok_a` | 0 (first byte) | `0x09` | `0x13` | Unknown; present in all packet types |
| `tok_b` | last byte (13B/30B/34B packets) | `0x40` | `0x65` | Previously misidentified as a fixed terminator |
| `tok_c` | byte 13 of 34B movement | `0x02` | `0x03` | Feeds into the `ck2` motor checksum |

The L2CAP CoC CIDs also change per session (dynamically assigned):

| Direction | Session 1 | Session 2 |
|-----------|-----------|----------|
| Host → Robot | `0x0041` | `0x0049` |
| Robot → Host | `0x1407` | `0x0d07` |

The `ck2` formula must include `tok_c`: `ck2 = (0xDA − 2·(m1+m2) − tok_c) % 256`.  The original derivation `(0xD8 − 2·(m1+m2))` was only accidentally correct for session 1 where `tok_c = 0x02`.

The origin of `tok_c`'s value (0x02, 0x03…) suggests it may be a persistent pairing counter stored in the companion app.  The origins of `tok_a` and `tok_b` are unknown without connection setup frames.

### 4.2 — 5-byte mystery command

Only one unique value was observed per session:

| Session | Value |
|---------|-------|
| 1 | `09 ff 01 0a 5c` |
| 2 | `13 ff 01 0a 79` |

Byte 0 matches `tok_a`.  Bytes 1–3 (`ff 01 0a`) are invariant.  The last byte changes with the session but does not equal `tok_b` — its derivation is unknown.

### 4.3 — 28-byte extended status

```
09 ef 31 ff 5a 00 18 40  [ctr_lo] [ctr_hi]  03  [cmp]
00 02 00 00 01 00 01  06  01 02 01  [a]  01  [b]  [ck]  40
```

The magic bytes (`ef 31 ff 5a 00 18 40`) and the `0x06` type byte distinguish it from the movement (type `0x09`) and park (type `0x07`) frames.  It appears only during park sessions, possibly triggered by the transition into or out of park mode.  The `(a, b)` pair follows the same `b = a + 0x08` relationship (not `+0x2A` as in park — values `0x0C/0x14` and `0x0D/0x15` observed).

### 4.4 — 30-byte tick / sensor frame

```
09 ef 35 ff 5a 00 1a 40  [ctr_lo] [ctr_hi]  03  [cmp]
00 02 00 00 01 00 01  07  01 03 01 20 01  [a]  01  [b]  [ck]  40
```

Sent roughly every 10–20 movement packets.  The `(a, b)` values slowly increment over the session — they appear to be an odometry or encoder tick counter internal to the robot, with `b = a + 0x2A` (same as the park packet).  The `0x07` type byte matches the park sub-frame type.

### 4.5 — 39-byte merged frame (ef 47)

The 39-byte frame is a **protocol-level merge**, not a simple L2CAP concatenation.  Its structure:

```
Bytes  0–11  (12 B): heartbeat header with magic ef 47 (instead of ef 13), WITHOUT tok_b
                    i.e. tok_a ef 47 ff 5a 00 09 40 lo hi 00 cmp
Bytes 12–38  (27 B): 30-byte tick frame body, WITHOUT its first 3 bytes (tok_a ef 35)
                    i.e. ff 5a 00 1a 40 lo hi 03 cmp ... ck tok_b
```

The complement constant for the ef 47 header is `0x5E` (same as a normal heartbeat).  The complement constant for the embedded tick portion is `0x4A` (same as a standalone 30-byte tick).  Both portions share a common counter value.

This appears to be a host-side optimisation that merges a due heartbeat with a due tick update, using a distinct magic byte (`0x47`) for the combined packet.

---

## 5. Robot → Host Reply Packets

The robot sends replies on a dynamically assigned remote CID (`0x1407` in session 1, `0x0d07` in session 2).  Three reply sizes were consistently observed:

| Size | Frequency | Notes |
|------|-----------|-------|
| 7 B | Very frequent | Short ACK: `13 05 01 0d 00 01 00`.  Sent after nearly every host packet. |
| 22 B | Frequent | Periodic status.  Bytes 16–17 appear to echo the counter; byte 20 counts down. |
| 25–66 B | Occasional | Larger sensor / state frames.  Not yet decoded. |

The 7-byte ACK is the robot's acknowledgement that the previous packet was received and processed.

---

## 6. Capture Quality Notes

- All captures start **mid-session** — the BLE connection setup (advertising, `LE_Create_Connection`, `LE_Connection_Complete`, L2CAP CoC credit exchange) is not present.  The PSM cannot be read from these files.
- Timestamps in the BTsnoop headers use a reference epoch of **1 January 2000** (not Unix epoch).  The raw timestamp values are very large numbers because the captures appear to have been taken years after 2000.
- No packets were dropped — the `cumulative drops` field is `0` in all records.
- The `CTRL→HOST` packet count is always higher than `HOST→CTRL` because the robot sends an ACK for (nearly) every host packet, plus unsolicited status frames.

---

## 7. Parsing the Files

A minimal Python parser:

```python
import struct

MAGIC = b'btsnoop\x00'

def parse_btsnoop(path):
    with open(path, 'rb') as f:
        data = f.read()
    assert data[:8] == MAGIC, "Not a BTsnoop file"
    # version = struct.unpack_from('>I', data, 8)[0]  # == 1
    # datalink = struct.unpack_from('>I', data, 12)[0]  # == 1001
    offset = 16
    records = []
    while offset + 24 <= len(data):
        orig_len, inc_len, flags, drops = struct.unpack_from('>IIII', data, offset)
        ts_hi, ts_lo = struct.unpack_from('>II', data, offset + 16)
        # timestamp in microseconds since 2000-01-01 00:00:00 UTC
        timestamp_us = (ts_hi << 32) | ts_lo
        payload = data[offset + 24 : offset + 24 + inc_len]
        records.append({
            'sent':    not (flags & 1),   # True = host→controller
            'ts_us':  timestamp_us,
            'data':   payload,
        })
        offset += 24 + inc_len
    return records
```

To extract the L2CAP CoC application payload from an ACL data record:

```python
def l2cap_coc_payload(hci_acl_bytes):
    """Return (cid, payload) or None if not a valid first-fragment ACL packet."""
    if len(hci_acl_bytes) < 8:
        return None
    # bytes 0-1: handle + PB/BC flags (little-endian)
    # bytes 2-3: total data length
    l2cap_len = struct.unpack_from('<H', hci_acl_bytes, 4)[0]
    cid        = struct.unpack_from('<H', hci_acl_bytes, 6)[0]
    payload    = hci_acl_bytes[8 : 8 + l2cap_len]
    return cid, payload
```

The robot's command channel is **CID `0x0041`** (host → robot) in session 1, **`0x0049`** in session 2.
