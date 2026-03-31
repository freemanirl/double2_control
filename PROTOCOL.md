# BLE Robot Protocol

Reverse-engineered from six BTsnoop captures (`bt_captures/`) using a BLE-connected robot.  All findings were validated against 396 captured movement packets with 0 errors (332 from the original session + 64 from a second session after unpairing).

> **Session-specific bytes** — Three bytes in every packet are set once per BLE connection and remain constant for the lifetime of that session (see §3.4).  They are labelled `tok_a`, `tok_b`, and `tok_c` in the packet layouts below.

---

## 1. BLE Transport

| Parameter | Value |
|-----------|-------|
| Protocol | BLE L2CAP **Credit-Based CoC** (not GATT Write) |
| Robot MAC address | `78:83:A0:A8:EC:66` |
| BLE advertising name | "Double 10-0" (Microchip RN-series BT module — iAP firmware) |
| Address type | Public (`0x00`) |
| L2CAP PSM | **`0x0003`** — confirmed from `connect.log` (Transparent UART / iAP CoC channel) |
| Local CID (host → robot) | Dynamically assigned by device per session (e.g. `0x0041`, `0x0049`) |
| Remote CID (robot → host) | Dynamically assigned by host per session (e.g. `0x1407`, `0x0d07`) |

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

### 3.3 — Park / Unpark / Raise / Lower Toggle (44 bytes)

Sent **once** per button press.  The robot **toggles** state on each receipt — the same 44-byte packet structure is used for park/unpark, raise-arm, and lower-arm; the robot determines the action from its current state.

```
Offset  Len  Value / Formula
──────  ───  ──────────────────────────────────────────────────────────────
 0       1   tok_a  (session token A)
 1–7     7   ef 51 ff 5a 00 28 40  (fixed magic)
 8       1   counter_lo
 9       1   counter_hi
10       1   0x03  (constant)
11       1   cmp  = (0x3C − counter_lo − counter_hi) mod 256
            ── sub-frame 1 ──────────────────────────────────────────────
12       1   0x00  (fixed)
13       1   tok_c  (session token C)
14–18    5   00 00 01 00 01  (fixed)
19       1   0x07  (type indicator — differs from movement's 0x09)
20–24    5   01 03 01 20 01
25       1   a1  — robot odometry tick (low byte, slowly increments)
26       1   0x01
27       1   b1  = (a1 + 0x2A) mod 256
            ── sub-frame 2 ──────────────────────────────────────────────
28–29    2   00 00  (separator)
30–30    1   0x01
31–38    8   00 01 07 01 03 01 20 01  (fixed)
39       1   a2  = (a1 + 1) mod 256  (next tick value)
40       1   0x01
41       1   b2  = (a2 + 0x2A) mod 256
42       1   ck  = (0xA0 − tok_c − a1 − b1 − a2 − b2) mod 256
43       1   tok_b  (session token B)
```

The `(a, b)` pairs represent a robot internal odometry / state counter.  `b` is always `a + 0x2A`.  The two sub-frames carry consecutive tick values (a2 = a1 + 1).  `tok_c` at byte 13 and in the checksum means the full formula is session-specific — exactly analogous to `ck2` in the movement packet.

---

### 3.4 — Session Tokens (tok_a, tok_b, tok_c)

Three bytes in every packet change when the device is unpaired and re-paired, and remain constant for all packets within a single BLE session:

| Token | Location | Session 1 | Session 2 | Notes |
|-------|----------|-----------|-----------|-------|
| `tok_a` | byte 0 of every host packet | `0x09` | `0x13` | Assigned during iAP2 session setup; the **robot also has its own tok_a** (`0x11` in session 2) used in robot-originated data packets |
| `tok_b` | last byte of every host packet (except 5-byte) | `0x40` | `0x65` | Terminator position |
| `tok_c` | byte 13 of movement (34B) and park (44B) packets | `0x02` | `0x03` | Session counter; also feeds into `ck2` / park checksum |

#### Token origin (from `connect.log`)

All three tokens are negotiated during the **iAP2 session setup phase** that runs over the same L2CAP CoC channel before the robot-control protocol begins.  The key exchange is a pair of 14-byte `ef 15` frames:

```
Host → Robot: [tok_a_pre] ef 15 83 [robot_tok_a] 04 f0 00 00 ef [tok_c] 00 00 70
Robot → Host: [pre]       ef 15 81 [robot_tok_a] 04 e0 00 00 7f 00 00 00 aa
```

- `tok_c` (byte 10 of the host frame = `0x03` for session 2) is a **persistent pairing counter** that increments by 1 each time the device is re-paired.
- `tok_a` for the host and for the robot are set just before this in a 4-byte init exchange (`[tok_a] 3f 01 XX` from host, `[tok_a] 73 01 XX` from robot).
- `tok_b` first appears as the last byte of the first `ef 13` heartbeat packet after setup completes.

**Important:** the robot sends its own data packets (heartbeats, status frames, etc.) with its own tok_a as byte 0 (`0x11` in session 2), **not** the host's tok_a.  However, robot ACK packets copy the **host's** tok_a (`0x13`) as a session-echoing acknowledgement.

The 5-byte mystery packet (`09/13 ff 01 0a XX`) has `tok_a` at byte 0. The last byte (e.g. `0x79` in session 2) is **not** tok_b and its derivation is unknown; it appears to be the robot's tok_a passed back via a separate token mechanism.

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

The robot sends back on its assigned remote CID (`0x1407` in session 1, `0x0d07` in session 2).  The robot's byte 0 is its **own tok_a** (`0x11` in session 2), **not** the host's tok_a (`0x13`).  Exception: 7-byte ACK packets echo the host's tok_a.

| Length | Identified purpose |
|--------|-------------------|
| 7 B | Short ACK: `[host_tok_a] 05 01 YY 00 ZZ 00`.  Sent after nearly every host packet; byte 0 mirrors the host's tok_a. |
| 13 B | Robot heartbeat `ef 13` — same structure as host heartbeat but with robot's tok_a at byte 0 (`0x11`). |
| 14 B | Chunked data header (robot → host `ff 13` format during session setup). |
| 25–66 B | Larger sensor / state frames (`ef fd`, `ef ff` multi-chunk, etc.).  Not fully decoded; contain robot orientation/position data. |

The 7-byte ACK echoing the host tok_a is how the robot acknowledges that a command was received and processed.

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
| `bt_captures/select.log` | 2 | Connection / menu interaction — only neutral movement packets |
| `bt_captures/raise.log` | 2 | Arm-raise button pressed — 4× 44-byte toggle packets |
| `bt_captures/lower.log` | 2 | Arm-lower sequence — heartbeats and tick frames only (no command packets) |
| `bt_captures/connect.log` | 2 | Full connection capture: iAP2 MFi authentication (Apple certificate chain), token negotiation (`ef 15` frame establishes tok_a/tok_c), first CoC protocol packets |
| `robot_control.py` | — | Python implementation of the full protocol |

---

## 7. Implementation Notes

- `RobotPacketBuilder` in `robot_control.py` constructs all packet types; call `.movement(m1, m2)`, `.heartbeat()`, `.park()`, `.raise_arm()`, `.lower_arm()`, or the named helpers (`.forward()`, `.backward()`, etc.).
- `RobotController` wraps a BlueZ L2CAP CoC socket and runs a background heartbeat thread automatically.
- L2CAP CoC sockets require `CAP_NET_RAW`: run as root or `sudo setcap cap_net_raw+eip $(which python3)`.
- PSM is `0x0003` (confirmed from `connect.log`). Connect directly with `--psm 0x0003`, or use `--discover-psm` to read it from GATT if the device firmware has been updated.
- `python3 robot_control.py --self-test` re-derives the exact captured bytes and confirms 0 errors across all 332 movement + park/raise packets.
