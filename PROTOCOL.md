# BLE Robot Protocol

Reverse-engineered from six BTsnoop captures (`bt_captures/`) using a BLE-connected robot.  All findings were validated against 396 captured movement packets with 0 errors (332 from the original session + 64 from a second session after unpairing).

> **Session-specific bytes** — Three bytes in every packet are set once per BLE connection and remain constant for the lifetime of that session (see §3.4).  They are labelled `tok_a`, `tok_b`, and `tok_c` in the packet layouts below.

---

## 1. BLE Transport

| Parameter | Value |
|-----------|-------|
| Protocol | BLE L2CAP **Credit-Based CoC** (not GATT Write) |
| Robot MAC address | `78:83:A0:A8:EC:66` |
| Address type | Public (`0x00`) |
| Local CID (host → robot) | Dynamically assigned (e.g. `0x0041`, `0x0049`) |
| Remote CID (robot → host) | Dynamically assigned (e.g. `0x1407`, `0x0d07`) |
| L2CAP PSM | **Not visible in captures** — connection setup preceded snoop recording.  Run `--discover-psm` or try `0x0025` first. |

The host opens a SOCK_SEQPACKET L2CAP socket and connects to the robot's PSM.  Each `send()` call is one L2CAP CoC SDU.  Each command is a self-contained raw byte payload — there is no GATT characteristic involved.

---

## 2. Shared Counter

Every packet (movement and heartbeat) carries a **shared 16-bit little-endian counter** at bytes 8–9.  The counter increments by 1 with every packet sent, regardless of packet type.  The robot appears to use it for sequencing / duplicate detection.

There is no strict requirement on the initial counter value — any starting value is accepted.

---

## 3. Packet Types

### 3.1 — Movement (34 bytes)

Sent repeatedly while a direction button is held (~20 Hz in captures).

```
Offset  Len  Value / Formula
──────  ───  ───────────────────────────────────────────────────────
 0       1   tok_a  (session token A — see §3.4)
 1–7     7   ef 3d ff 5a 00 1e 40  (fixed magic)
 8       1   counter_lo  (low byte of 16-bit LE counter)
 9       1   counter_hi
10       1   0x03  (constant)
11       1   cmp  = (0x46 − counter_lo − counter_hi) mod 256
12       1   0x00  (fixed)
13       1   tok_c  (session token C — feeds into CK2, see §3.4)
14–24   11   00 00 01 00 01 09 01 01 01 05 01  (fixed)
25       1   m1  — throttle / left-motor value
26       1   0x01  (separator)
27       1   m2  — steering / right-motor value
28–30    3   01 00 01  (fixed)
31       1   ck1 = (m1 + m2 + 0x0F) mod 256
32       1   ck2 = (0xDA − 2·(m1 + m2) − tok_c) mod 256
33       1   tok_b  (session token B — see §3.4)
```

#### Motor value encoding

Both `m1` and `m2` use a single unsigned byte centred on **`0x7f` = neutral/stop**:

| Value | Meaning |
|-------|---------|
| `0x7f` | Neutral / no drive |
| `0x80`–`0xFF` | Forward / left  (higher = faster) |
| `0x00`–`0x7E` | Backward / right (lower = faster) |

#### Named commands

| Command | m1 | m2 | Notes |
|---------|----|----|-------|
| Forward | `0xFE` | `0x7F` | m1 = max forward |
| Backward | `0x3F` | `0x7F` | captured value; `0x00` = full backward |
| Turn Left | `0x7F` | `0xFE` | m2 = max left |
| Turn Right | `0x7F` | `0x01` | m2 = max right; `0x00` would be further |
| Stop / Neutral | `0x7F` | `0x7F` | both motors neutral |

#### Checksum algebra

`ck1` and `ck2` encode the motor sum and its complement so the robot can verify both the sum and scaled difference of the motor values independently:

- `ck1 = (m1 + m2 + 0x0F) mod 256`
- `ck2 = (0xDA − 2·(m1 + m2) − tok_c) mod 256`

`ck1` is purely a function of `m1` and `m2`.  `ck2` additionally includes `tok_c` (the session token at byte 13).  An earlier derivation of `ck2` as `(0xD8 − 2·(m1+m2)) mod 256` was only correct for the first observed session where `tok_c = 0x02`; the general formula includes `tok_c` explicitly.

Neither checksum covers the counter or the other fixed fields.

---

### 3.2 — Heartbeat / Keep-Alive (13 bytes)

Sent approximately every 250 ms while any command session is active, interleaved with movement packets.  Uses the same shared counter.

```
Offset  Len  Value / Formula
──────  ───  ──────────────────────────────────────────
 0       1   tok_a  (session token A)
 1–7     7   ef 13 ff 5a 00 09 40  (fixed magic, differs from movement)
 8       1   counter_lo
 9       1   counter_hi
10       1   0x00  (constant — differs from movement's 0x03)
11       1   cmp  = (0x5E − counter_lo − counter_hi) mod 256
12       1   tok_b  (session token B)
```

The only structural difference from the movement packet header is the magic bytes (offset 1–7) and the complement constant (`0x5E` vs `0x46`).

---

### 3.3 — Park / Unpark Toggle (44 bytes)

Sent **once** per button press.  The robot **toggles** between parked and unparked on each receipt — there is no separate "park" vs "unpark" opcode.

```
Offset  Len  Value / Formula
──────  ───  ──────────────────────────────────────────────────────────────
 0       1   tok_a  (session token A)
 1–7     7   ef 51 ff 5a 00 28 40  (fixed magic)
 8       1   counter_lo
 9       1   counter_hi
10       1   0x03  (constant)
11       1   cmp  = (0x46 − counter_lo − counter_hi) mod 256  (same as movement)
            ── sub-frame 1 ──────────────────────────────────────────────
12–18    7   00 02 00 00 01 00 01  (fixed preamble)
19       1   0x07  (type indicator — differs from movement's 0x09)
20–24    5   01 03 01 20 01
25       1   a1  — robot odometry tick (low byte, slowly increments)
26       1   0x01
27       1   b1  = (a1 + 0x2A) mod 256
            ── sub-frame 2 ──────────────────────────────────────────────
28–29    2   00 00  (separator)
30–30    1   0x01
31–38    8   00 01 07 01 03 01 20 01  (fixed)
39       1   a2  — reference tick (typically 0x8E)
40       1   0x01
41       1   b2  = (a2 + 0x2A) mod 256  = typically 0xB8
42       1   ck  = (0x9E − a1 − b1 − a2 − b2) mod 256
43       1   tok_b  (session token B)
```

The `(a, b)` pairs appear to represent a robot internal odometry / state counter.  `b` is always `a + 0x2A`.  The sub-frame 2 reference values (`a2=0x8E, b2=0xB8`) were constant across both park events in the capture.

---

### 3.4 — Session Tokens (tok_a, tok_b, tok_c)

Three bytes in every packet change when the device is unpaired and re-paired, and remain constant for all packets within a single BLE session:

| Token | Location | Session 1 | Session 2 | Notes |
|-------|----------|-----------|-----------|-------|
| `tok_a` | byte 0 of every packet | `0x09` | `0x13` | First byte of every packet |
| `tok_b` | last byte of every packet (except 5-byte) | `0x40` | `0x65` | Terminator position |
| `tok_c` | byte 13 of movement (34B) packets | `0x02` | `0x03` | Also incorporated into `ck2` |

The 5-byte mystery packet (`09/13 ff 01 0a XX`) also has `tok_a` at byte 0 and a session-specific last byte, but the last byte value differs from `tok_b` and has not been independently derived.

These tokens are set during connection negotiation (specifically, during L2CAP CoC credit exchange or a subsequent handshake that precedes all logged captures).  Without captures of the connection setup they cannot be derived from first principles, but in practice they must be read from the connection or brute-forced.  `tok_c` appears to increment by 1 per pairing (0x02 → 0x03), suggesting it is a small persistent session counter stored on the phone.

---

## 4. Observed Packet Interleaving

A typical interaction looks like:

```
HOST → ROBOT  [movement 34B]   forward
HOST → ROBOT  [movement 34B]   forward
…  (repeated ~50 ms apart)  …
HOST → ROBOT  [heartbeat 13B]  keep-alive
HOST → ROBOT  [movement 34B]   forward
…
(button released)
HOST → ROBOT  [movement 34B]   neutral / stop
```

Heartbeat packets are sent periodically even between movement commands and share the same counter sequence.

---

## 5. Robot's Reply Packets

The robot sends back on remote CID `0x1407` (captured as `CTRL→HOST` in the snoop files).  Three reply types were observed:

| Length | Identified purpose |
|--------|-------------------|
| 22 B | Periodic status / ACK (contains counter echo, likely sensor data) |
| 7 B | Short ACK: `13 05 01 0d 00 01 00` |
| 25–66 B | Larger status frames (sensor readings, orientation, etc.) |

The reply payloads have not been fully decoded but follow a similar counter-echo structure.

---

## 6. Files

| File | Session | Description |
|------|---------|-------------|
| `bt_captures/forward.log` | 1 | Forward movement command session |
| `bt_captures/backward.log` | 1 | Backward movement command session |
| `bt_captures/turn left.log` | 1 | Turn-left command session |
| `bt_captures/turn right.log` | 1 | Turn-right command session |
| `bt_captures/park.log` | 1 | Park button pressed multiple times (park + unpark cycles) |
| `bt_captures/turn right 2.log` | 2 | Turn-right after unpair/repair — used to confirm session-token findings |
| `robot_control.py` | — | Python implementation of the full protocol |

---

## 7. Implementation Notes

- `RobotPacketBuilder` in `robot_control.py` constructs all packet types; call `.movement(m1, m2)`, `.heartbeat()`, `.park()`, or the named helpers (`.forward()`, `.backward()`, etc.).
- `RobotController` wraps a BlueZ L2CAP CoC socket and runs a background heartbeat thread automatically.
- L2CAP CoC sockets require `CAP_NET_RAW`: run as root or `sudo setcap cap_net_raw+eip $(which python3)`.
- The PSM was not captured; use `--discover-psm` to read it from GATT characteristics, or try `0x0025` as a starting point.
- `python3 robot_control.py --self-test` re-derives the exact captured bytes and confirms 0 errors across all 332 movement packets.
