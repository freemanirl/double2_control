#!/usr/bin/env python3
"""
BLE Robot Controller — reverse-engineered from BTsnoop captures.

Transport:  BLE L2CAP Credit-Based CoC
             CIDs are dynamically assigned (e.g. 0x0041/0x1407 or 0x0049/0x0d07)
Device MAC: 78:83:A0:A8:EC:66  (bytes in captures: 66 ec a8 a0 83 78 = LSB-first)

Protocol summary
================
All commands are sent as raw bytes over the L2CAP CoC channel.

Session tokens
--------------
Three bytes change each time the device is paired / a new BLE session starts
and remain constant for the lifetime of that session:

  tok_a  : byte  0 of every HOST→ROBOT packet  (session 1 = 0x09, session 2 = 0x13)
  tok_b  : last byte of 13/30/34-byte host pkts (session 1 = 0x40, session 2 = 0x65)
  tok_c  : byte 13 of 34-byte movement pkts     (session 1 = 0x02, session 2 = 0x03)

The robot also has its own tok_a used in ROBOT→HOST data packets (0x11 in session 2).
This code only generates host→robot packets so only the host tok_a values matter here.

All tokens are negotiated during the iAP2 session setup phase (see connect.log): tok_a
and tok_c are exchanged in the 14-byte `ef 15` negotiation frame; the host assigns its
own tok_a immediately after via a short 4-byte init packet.

Packet types found in captures
-------------------------------
A) 34-byte MOVEMENT packet  (sent repeatedly while a direction button is held)
   Byte  0    : tok_a  (session token A)
   Bytes 1-7  : ef 3d ff 5a 00 1e 40  (fixed magic)
   Bytes 8-9  : counter (uint16-LE, increments every packet)
   Byte  10   : 0x03  (constant)
   Byte  11   : cmp  = (0x46 - ctr_lo - ctr_hi) mod 256
   Byte  12   : 0x00  (fixed)
   Byte  13   : tok_c  (session token C)
   Bytes 14-24: 00 00 01 00 01 09 01 01 01 05 01  (fixed)
   Byte  25   : m1  (left / throttle motor value, neutral = 0x7f)
   Byte  26   : 0x01 (separator)
   Byte  27   : m2  (right / steering motor value, neutral = 0x7f)
   Bytes 28-30: 01 00 01 (fixed)
   Byte  31   : ck1 = (m1 + m2 + 0x0f) mod 256
   Byte  32   : ck2 = (0xda - 2*(m1 + m2) - tok_c) mod 256
   Byte  33   : tok_b  (session token B)

   Motor values (0x7f = neutral/stop):
     Forward  : m1=0xfe, m2=0x7f   (m1 > 0x7f → forward, < 0x7f → backward)
     Backward : m1=0x3f, m2=0x7f   (0x3f captured; range 0x00–0x7e available)
     Turn Left: m1=0x7f, m2=0xfe   (m2 > 0x7f → left,    < 0x7f → right)
     Turn Right: m1=0x7f, m2=0x01
     Stop/Neutral: m1=0x7f, m2=0x7f

B) 13-byte HEARTBEAT / keep-alive  (sent periodically regardless of movement,
                                    ~every 200-400 ms while any command is active)
   Byte  0    : tok_a
   Bytes 1-7  : ef 13 ff 5a 00 09 40  (fixed magic)
   Bytes 8-9  : counter (same shared counter as movement packets)
   Byte  10   : 0x00 (constant, differs from movement's 0x03)
   Byte  11   : cmp  = (0x5e - ctr_lo - ctr_hi) mod 256
   Byte  12   : tok_b

C) 44-byte PARK / UNPARK / RAISE / LOWER toggle command
   Sent once per button press to toggle the robot between states.
   Magic: ef 51 ff 5a 00 28 40  (complement constant: 0x3c, NOT 0x46)
   Two sub-frames each carry a (a, b) tick pair where b = (a + 0x2a) mod 256.
   Checksum: ck = (0xa0 - tok_c - a1 - b1 - a2 - b2) mod 256
   a1/a2 slowly increment over the robot's lifetime (odometry/position counter).
   All of: park/unpark, raise-arm, lower-arm use this identical packet structure;
   the robot toggles state on each receipt.

Checksum formulas verified across 396 movement packets + park/raise packets with 0 errors.

Connection
==========
The device uses BLE L2CAP Credit-Based CoC (not standard GATT writes).
- BLE advertising name: "Double 10-0" (Microchip RN-series BT module, iAP firmware).
- PSM = 0x0003 (confirmed from connect.log; Transparent UART / iAP CoC channel).
- Device address type is PUBLIC (0x00).
- CIDs are dynamically assigned per session by the robot's BT stack.

IMPORTANT — iAP2 MFi authentication requirement:
  After establishing the L2CAP CoC channel the robot runs the full iAP2 handshake
  (Apple MFi certificate exchange + feature negotiation) before it will respond to
  any robot-control packets.  This code does NOT implement that handshake — to send
  live commands you must first complete the iAP2 setup (or replay the exact byte
  sequence from connect.log) before calling any movement/park methods.

  iap2_handshake() in this module implements a *replay* approach: it sends the
  exact host-side bytes observed in connect.log (with tok_a/tok_c patched to the
  live values) and reads+discards the robot's responses.  The auth challenge nonce
  is replayed verbatim from the capture, so the robot may or may not enforce nonce
  uniqueness.  If the robot rejects the stale challenge the full iAP2 crypto
  (RSA/ECDSA certificate verification) would be required — that in turn requires
  the Apple MFi root CA certificate, which is only available under Apple's MFi
  developer license.

Dependencies
============
    pip install bleak

Usage
=====
    python robot_control.py
    python robot_control.py --scan     # just scan and show nearby devices
    python robot_control.py --address 78:83:A0:A8:EC:66 --psm 0x0003
"""

import argparse
import asyncio
import ctypes
import ctypes.util
import errno
import os
import select
import socket
import struct
import sys
import threading
import time

# ──────────────────────────────────────────────────────────────────────────────
# Known device parameters (from BTsnoop captures)
# ──────────────────────────────────────────────────────────────────────────────

ROBOT_ADDRESS = "00:06:66:EC:A8:A0"  # discovered live unit; captures used 78:83:A0:A8:EC:66

# L2CAP CoC PSM.  Confirmed 0x0003 from connect.log (L2CAP Connection Request
# observed connecting to PSM 0x0003 to establish the Transparent UART / iAP CoC
# channel on this Microchip RN-series module).  The CoC CID is dynamically
# assigned per session by the device; it is NOT the same value as the PSM.
DEFAULT_PSM = 0x0003

# Motor value constants
MOTOR_NEUTRAL   = 0x7F  # stop / no movement
MOTOR_FWD_MAX   = 0xFE  # full forward  (0x80–0xFF forward range)
MOTOR_BWD_MED   = 0x3F  # medium backward (captured value)
MOTOR_BWD_MAX   = 0x00  # full backward
MOTOR_TURN_MAX  = 0xFE  # full turn in one direction
MOTOR_TURN_OPP  = 0x01  # full turn in opposite direction

# Tick values used for the park/unpark sub-frame reference
PARK_REF_A = 0x8E
PARK_REF_B = PARK_REF_A + 0x2A  # always b = a + 0x2a


# ──────────────────────────────────────────────────────────────────────────────
# Packet builder
# ──────────────────────────────────────────────────────────────────────────────

class RobotPacketBuilder:
    """Builds protocol packets for the BLE robot.

    The 16-bit counter increments with every packet sent (heartbeat and
    movement share the same counter).

    tok_a, tok_b, tok_c are the HOST's session-specific tokens that change
    each time the device is paired / a new BLE session is established.  The
    robot has its own distinct tok_a (seen in ROBOT→HOST packets) but that
    value is not used here — only the host-side tokens affect the packets this
    class builds.  Use the default values (from session 1 of the captures)
    unless you have observed the tokens for the current session.

    Session token defaults (session 1, host-side):
        tok_a = 0x09  (first byte of every host packet)
        tok_b = 0x40  (last byte of 13/30/34-byte host packets)
        tok_c = 0x02  (byte 13 of movement packets; also feeds into ck2)
    """

    def __init__(self, initial_counter: int = 0x0000,
                 tok_a: int = 0x09, tok_b: int = 0x40, tok_c: int = 0x02):
        self._counter = initial_counter & 0xFFFF
        self._tok_a = tok_a & 0xFF
        self._tok_b = tok_b & 0xFF
        self._tok_c = tok_c & 0xFF
        # Internal "tick" value that slowly increments (used by park / 30-byte
        # status frames).  Start at the most commonly observed initial value.
        self._tick_a = PARK_REF_A

    # ── private helpers ──────────────────────────────────────────────────────

    def _next_counter(self) -> tuple[int, int]:
        """Return (lo, hi) for current counter then advance it."""
        lo = self._counter & 0xFF
        hi = (self._counter >> 8) & 0xFF
        self._counter = (self._counter + 1) & 0xFFFF
        return lo, hi

    @staticmethod
    def _move_cmp(lo: int, hi: int) -> int:
        """Complement byte for 34-byte movement and 30-byte tick packets (constant 0x46)."""
        return (0x46 - lo - hi) & 0xFF

    @staticmethod
    def _hb_cmp(lo: int, hi: int) -> int:
        """Complement byte for 13-byte heartbeat packets (constant 0x5e)."""
        return (0x5E - lo - hi) & 0xFF

    @staticmethod
    def _park_cmp(lo: int, hi: int) -> int:
        """Complement byte for 44-byte park/raise/lower toggle packets (constant 0x3c)."""
        return (0x3C - lo - hi) & 0xFF

    @staticmethod
    def _ck1(m1: int, m2: int) -> int:
        return (m1 + m2 + 0x0F) & 0xFF

    def _ck2(self, m1: int, m2: int) -> int:
        return (0xDA - 2 * (m1 + m2) - self._tok_c) & 0xFF

    def _park_ck(self, a1: int, b1: int, a2: int, b2: int) -> int:
        """Checksum for 44-byte park/raise/lower toggle packets."""
        return (0xA0 - self._tok_c - a1 - b1 - a2 - b2) & 0xFF

    # ── public packet constructors ───────────────────────────────────────────

    def movement(self, m1: int, m2: int) -> bytes:
        """34-byte movement command.

        m1 controls the left/throttle motor:
            0x00 = full backward … 0x7f = neutral … 0xFF = full forward
        m2 controls the right/steering motor (same scale).
        """
        lo, hi = self._next_counter()
        cmp = self._move_cmp(lo, hi)
        ck1 = self._ck1(m1, m2)
        ck2 = self._ck2(m1, m2)
        return bytes([
            self._tok_a, 0xEF, 0x3D, 0xFF, 0x5A, 0x00, 0x1E, 0x40,
            lo, hi, 0x03, cmp,
            0x00, self._tok_c, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x09, 0x01, 0x01, 0x01, 0x05, 0x01,
            m1, 0x01, m2, 0x01, 0x00, 0x01,
            ck1, ck2, self._tok_b,
        ])

    def heartbeat(self) -> bytes:
        """13-byte keep-alive packet sent periodically."""
        lo, hi = self._next_counter()
        cmp = self._hb_cmp(lo, hi)
        return bytes([
            self._tok_a, 0xEF, 0x13, 0xFF, 0x5A, 0x00, 0x09, 0x40,
            lo, hi, 0x00, cmp, self._tok_b,
        ])

    def stop(self) -> bytes:
        """Neutral / stop movement."""
        return self.movement(MOTOR_NEUTRAL, MOTOR_NEUTRAL)

    def forward(self, speed: int = MOTOR_FWD_MAX) -> bytes:
        """Move forward.  speed: 0x80–0xFF (0xFF = full forward)."""
        speed = max(0x80, min(0xFF, speed))
        return self.movement(speed, MOTOR_NEUTRAL)

    def backward(self, speed: int = MOTOR_BWD_MAX) -> bytes:
        """Move backward.  speed: 0x00–0x7E (0x00 = full backward)."""
        speed = max(0x00, min(0x7E, speed))
        return self.movement(speed, MOTOR_NEUTRAL)

    def turn_left(self, speed: int = MOTOR_TURN_MAX) -> bytes:
        """Turn left.  speed: 0x80–0xFF (steering motor value)."""
        speed = max(0x80, min(0xFF, speed))
        return self.movement(MOTOR_NEUTRAL, speed)

    def turn_right(self, speed: int = MOTOR_TURN_OPP) -> bytes:
        """Turn right.  speed: 0x00–0x7E (0x00 = full right)."""
        speed = max(0x00, min(0x7E, speed))
        return self.movement(MOTOR_NEUTRAL, speed)

    def park(self) -> bytes:
        """44-byte park/unpark/raise/lower toggle command.

        Sends two sub-frames each carrying a (a, b) tick pair where
        b = (a + 0x2a) mod 256.  Sub-frame 2 uses the next tick value
        (a2 = a1 + 1).  The robot toggles state on each receipt.
        """
        lo, hi = self._next_counter()
        cmp = self._park_cmp(lo, hi)

        # Sub-frame 1: current tick
        a1 = self._tick_a
        b1 = (a1 + 0x2A) & 0xFF

        # Sub-frame 2: next tick (a2 = a1 + 1)
        a2 = (a1 + 1) & 0xFF
        b2 = (a2 + 0x2A) & 0xFF

        ck = self._park_ck(a1, b1, a2, b2)

        pkt = bytes([
            self._tok_a, 0xEF, 0x51, 0xFF, 0x5A, 0x00, 0x28, 0x40,
            lo, hi, 0x03, cmp,
            # sub-frame 1 body
            0x00, self._tok_c, 0x00, 0x00, 0x01, 0x00, 0x01,
            0x07, 0x01, 0x03, 0x01, 0x20, 0x01, a1, 0x01, b1,
            # separator
            0x00, 0x00,
            # sub-frame 2 body
            0x01, 0x00, 0x01, 0x07, 0x01, 0x03, 0x01, 0x20, 0x01,
            a2, 0x01, b2,
            ck, self._tok_b,
        ])
        # Advance tick for next park call
        self._tick_a = (self._tick_a + 1) & 0xFF
        return pkt

    def raise_arm(self) -> bytes:
        """Raise arm toggle command (identical 44-byte packet to park())."""
        return self.park()

    def lower_arm(self) -> bytes:
        """Lower arm toggle command (identical 44-byte packet to park())."""
        return self.park()


# ──────────────────────────────────────────────────────────────────────────────
# L2CAP CoC connection (BlueZ / Linux)
# ──────────────────────────────────────────────────────────────────────────────

# sockaddr_l2 layout: family(2) + psm(2) + bdaddr[6] + cid(2) + bdaddr_type(1)
_SOCKADDR_L2_FMT = "<HH6sHB"
_AF_BLUETOOTH    = socket.AF_BLUETOOTH   # 31
_BTPROTO_L2CAP   = socket.BTPROTO_L2CAP  # 0
_BDADDR_BREDR      = 0  # classic BR/EDR
_BDADDR_LE_PUBLIC  = 1
_BDADDR_LE_RANDOM  = 2


def _parse_addr(addr_str: str) -> bytes:
    """Convert "AA:BB:CC:DD:EE:FF" → 6-byte little-endian bdaddr."""
    return bytes.fromhex(addr_str.replace(":", ""))[::-1]


# ctypes handle for the C library – used to call connect() directly because
# Python's socket.connect() for AF_BLUETOOTH/BTPROTO_L2CAP only accepts a
# (bdaddr_str, psm) tuple and does NOT expose the l2_bdaddr_type field needed
# to distinguish LE public/random addresses from classic BR/EDR.
_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def connect_coc(address: str, psm: int,
                addr_type: int = _BDADDR_BREDR,
                connect_timeout: float = 15.0) -> socket.socket:
    """Connect to a robot via L2CAP (BR/EDR or BLE Credit-Based CoC).

    Returns a connected SOCK_SEQPACKET socket.  Each send()/recv() call
    corresponds to exactly one L2CAP SDU.

    addr_type: _BDADDR_BREDR (0) for classic BT, _BDADDR_LE_PUBLIC (1) or
               _BDADDR_LE_RANDOM (2) for BLE.

    Note: requires CAP_NET_RAW (run as root or
    sudo setcap cap_net_raw+eip $(which python3.13)).
    """
    # BR/EDR connection-oriented L2CAP requires SOCK_STREAM in modern kernels.
    # SOCK_SEQPACKET is reserved for LE CoC (credit-based) channels; using it
    # with BDADDR_BREDR causes the kernel to return SO_ERROR=ENOSYS after the
    # async connect resolves.
    if addr_type == _BDADDR_BREDR:
        sock_type = socket.SOCK_STREAM
    else:
        sock_type = socket.SOCK_SEQPACKET
    sock = socket.socket(_AF_BLUETOOTH, sock_type, _BTPROTO_L2CAP)

    bd = _parse_addr(address)
    sa = struct.pack(_SOCKADDR_L2_FMT,
                     _AF_BLUETOOTH, psm, bd, 0, addr_type)

    # Python's socket.connect() for BTPROTO_L2CAP rejects raw bytes and
    # silently zero-fills l2_bdaddr_type (forcing BDADDR_BREDR=0).  Call the
    # C-library connect() directly so the kernel sees the full sockaddr_l2
    # including the LE address-type byte we packed above.
    #
    # SO_SNDTIMEO has no effect on BT socket connect()s in BlueZ.  Instead,
    # make the socket non-blocking so connect() returns EINPROGRESS
    # immediately, then use select() to enforce the timeout cleanly.
    sock.setblocking(False)
    addr_label = {_BDADDR_BREDR: "bredr",
                  _BDADDR_LE_PUBLIC: "le-public",
                  _BDADDR_LE_RANDOM: "le-random"}.get(addr_type, str(addr_type))
    print(f"  [BLE] connecting → {address} PSM=0x{psm:04x} "
          f"addr_type={addr_label}  timeout={connect_timeout:.0f}s")

    ret = _libc.connect(sock.fileno(),
                        ctypes.c_char_p(sa),
                        ctypes.c_int(len(sa)))
    if ret != 0:
        err = ctypes.get_errno()
        if err not in (errno.EINPROGRESS, errno.EWOULDBLOCK):
            sock.close()
            raise OSError(err, os.strerror(err))
        # Poll until the connection completes or the deadline expires
        _, writable, _ = select.select([], [sock], [], connect_timeout)
        if not writable:
            sock.close()
            raise OSError(errno.ETIMEDOUT,
                          f"No response from {address} within "
                          f"{connect_timeout:.0f}s (device not advertising?)")
        conn_err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if conn_err:
            sock.close()
            raise OSError(conn_err, os.strerror(conn_err))

    sock.setblocking(True)
    print("  [BLE] L2CAP CoC channel open.")
    return sock


# ──────────────────────────────────────────────────────────────────────────────
# iAP2 session handshake (replay from connect.log)
# ──────────────────────────────────────────────────────────────────────────────

def iap2_handshake(sock: socket.socket,
                   tok_a: int = 0x13,
                   tok_c: int = 0x03,
                   tok_b: int = 0x65,
                   verbose: bool = False) -> tuple[int, int, int]:
    """Perform the iAP2 session setup handshake over an already-connected CoC socket.

    Replays the exact host-side byte sequence observed in bt_captures/connect.log
    with tok_a, tok_c and tok_b patched to the current session values.  After the
    handshake the robot sends its first 44-byte ef-51 toggle and the first heartbeat;
    this function reads and discards all robot frames until a 13-byte heartbeat is
    seen, then returns the negotiated session tokens.

    The replay sends the auth-challenge nonce from the original capture verbatim.
    Whether the robot enforces nonce uniqueness is unknown — if it does, the full
    iAP2 crypto path (RSA/ECDSA + Apple MFi CA cert) would be required.

    Args:
        sock:    Connected SOCK_SEQPACKET L2CAP CoC socket.
        tok_a:   Host session token A (byte 0 of host packets).  Default = session 2.
        tok_c:   Session token C (pairing counter).  Default = session 2.
        tok_b:   Token B (last byte of host packets).  Default = session 2.
        verbose: Print each sent/received packet if True.

    Returns:
        (tok_a, tok_b, tok_c) — the tokens to pass to RobotPacketBuilder.

    Sequence (from connect.log, records 255–345):
        Phase 1 — token negotiation (fully static after patching)
        Phase 2 — feature negotiation (ef09 frames, static)
        Phase 3 — certificate auth (ef21 challenge, ef2b robot response — replayed)
        Phase 4 — ef0d, first 30B tick, app info (ef21 types)
        Phase 5 — robot sends ef51 + heartbeat → control protocol begins
    """

    def _send(label: str, pkt: bytes) -> None:
        if verbose:
            print(f"  TX {label:20s} ({len(pkt):3d}B)  {pkt[:16].hex(' ')}")
        sock.send(pkt)

    def _recv_until(stop_len: int, max_packets: int = 30) -> bytes | None:
        """Drain packets until one of length stop_len is received."""
        for _ in range(max_packets):
            readable, _, _ = select.select([sock], [], [], 3.0)
            if not readable:
                return None  # timeout
            try:
                pkt = sock.recv(512)
            except OSError:
                return None
            if verbose:
                print(f"  RX                      ({len(pkt):3d}B)  {pkt[:16].hex(' ')}")
            if len(pkt) == stop_len:
                return pkt
        return None

    # ── Phase 1: token negotiation ──────────────────────────────────────────
    # Record [255]: 4B pre-session init (tok_a_pre=0x03 in capture; may be static)
    _send("init-4B-pre",   bytes([0x03, 0x3f, 0x01, 0x1c]))
    _recv_until(4)  # robot echoes 03 73 01 d7

    # Record [259]: 14B ef-15 session negotiation
    # byte[0]=0x03 (pre-session tok_a), byte[4]=robot_tok_a=0x11, byte[10]=tok_c
    p = bytearray(bytes.fromhex("03ef15831104f00000ef03000070"))
    p[10] = tok_c
    _send("ef15-negotiate", bytes(p))
    _recv_until(14)  # robot ef-15 reply

    # Record [262]: 4B host tok_a assignment
    # checksum byte: (0x00 - tok_a - 0x3f - 0x01) & 0xFF
    ck = (0x00 - tok_a - 0x3f - 0x01) & 0xFF
    _send("init-4B-tok_a", bytes([tok_a, 0x3f, 0x01, ck]))
    _recv_until(4)  # robot echo

    # ── Phase 2: feature negotiation (ef09, fully static) ──────────────────
    # Records [265], [267]
    _send("ef09-feat-1",   bytes.fromhex("03ef09e305138d70"))
    _recv_until(8)
    _send("ef09-feat-2",   bytes.fromhex("03ef09e105130d70"))
    _recv_until(8)

    # Record [271]: 5B mystery command (type 0x0f form, before cert exchange)
    # last byte 0x79 is session-specific — replay from capture for now
    _send("ff-cmd-0f",     bytes([tok_a, 0xff, 0x01, 0x0f, 0x79]))
    _recv_until(5)

    # ── Phase 3: certificate auth (replayed from capture) ──────────────────
    # Robot sends 6 × 131B ef-ff cert fragments — drain them all
    # then host sends ef21 type=0x09 challenge nonce (replayed verbatim):
    # Record [301]: 20B ef21 type=0x09 — auth challenge (nonce at bytes 16–18)
    p = bytearray(bytes.fromhex("13ef21ff5a0010404d00010940400006aa00d065"))
    p[0]  = tok_a
    p[19] = tok_b
    # Drain robot cert chain (expect ~6×131B + 1×14B)
    for _ in range(10):
        readable, _, _ = select.select([sock], [], [], 3.0)
        if not readable:
            break
        try:
            raw = sock.recv(512)
        except OSError:
            break
        if verbose:
            print(f"  RX (cert drain)         ({len(raw):3d}B)  {raw[:8].hex(' ')}")
        # 14B robot ack of first 30B tick is also in this window
        if len(raw) == 14 and raw[2] == 0x13:
            break
    # Drain 30B tick sent by robot before cert auth (record [297])
    # then send ef21 challenge
    _send("ef21-challenge", bytes(p))

    # Drain robot's ef2b (25B signed response) and any intervening packets
    _recv_until(25)

    # ── Phase 4: auth result + app identity ────────────────────────────────
    # Record [329]: ef21 type=0x05 (auth result / accept)
    p = bytearray(bytes.fromhex("13ef21ff5a0010404f02010540400006aa05cb65"))
    p[0]  = tok_a
    p[19] = tok_b
    _send("ef21-auth-ok",  bytes(p))

    # Record [333]: ef21 type=0x04
    p = bytearray(bytes.fromhex("13ef21ff5a00104050020104404000061d005d65"))
    p[0]  = tok_a
    p[19] = tok_b
    _send("ef21-type04",   bytes(p))

    # Record [295]: 10B ef0d
    p = bytearray(bytes.fromhex("13ef0dff550200ee1065"))
    p[0]  = tok_a
    p[9]  = tok_b
    _send("ef0d",          bytes(p))

    # Record [298]: 30B first tick frame (counter 0x004c at bytes 8-9)
    p = bytearray(bytes.fromhex("13ef35ff5a001ac04c000081017fffff05dc000a1e010100010302017065"))
    p[0]  = tok_a
    p[13] = tok_c
    p[29] = tok_b
    _send("30B-tick",      bytes(p))

    # Record [315]: 5B mystery command (type 0x0a form — triggers robot ready)
    _send("ff-cmd-0a",     bytes([tok_a, 0xff, 0x01, 0x0a, 0x79]))

    # Record [339]: ef21 type=0x02 (final app identity)
    p = bytearray(bytes.fromhex("13ef21ff5a00104051030102404000061d025b65"))
    p[0]  = tok_a
    p[19] = tok_b
    _send("ef21-type02",   bytes(p))

    # ── Phase 5: wait for robot's ef51 + first heartbeat ───────────────────
    # Robot sends a 44B ef51 at startup, then a 13B heartbeat
    _recv_until(13, max_packets=20)

    # Ensure the socket is back in fully blocking mode (no timeout) before
    # handing it back to the caller.  The select()-based helpers above never
    # mutate the socket state, but be explicit here as a defensive reset.
    sock.setblocking(True)
    return tok_a, tok_b, tok_c


# ──────────────────────────────────────────────────────────────────────────────
# PSM discovery via GATT
# ──────────────────────────────────────────────────────────────────────────────

async def discover_psm(address: str) -> int | None:
    """Scan the device's GATT services for a PSM characteristic.

    BLE L2CAP CoC devices typically expose the PSM in one of:
      - A 2-byte custom characteristic in a vendor UUIDs service
      - Standard "LE PSM Out-of-Band" characteristic (UUID 0x2902 or 0xXXXX-PSM)

    Returns the PSM as an integer, or None if not found.
    """
    try:
        from bleak import BleakClient
    except ImportError:
        print("bleak not installed: pip install bleak")
        return None

    async with BleakClient(address) as client:
        print(f"Connected to {address} for GATT service discovery …")
        for svc in client.services:
            print(f"  Service: {svc.uuid}")
            for ch in svc.characteristics:
                print(f"    Char: {ch.uuid}  props={ch.properties}")
                # Read characteristics that look like they might hold a PSM
                if "read" in ch.properties:
                    try:
                        val = await client.read_gatt_char(ch.uuid)
                        print(f"      value = {val.hex(' ')}")
                        if len(val) == 2:
                            psm = int.from_bytes(val, "little")
                            if 0x0001 <= psm <= 0x00FF:
                                print(f"      *** Candidate PSM = 0x{psm:04x} ***")
                    except Exception as exc:
                        print(f"      (read failed: {exc})")
    return None


async def scan_devices() -> None:
    """Print nearby BLE devices with their addresses."""
    try:
        from bleak import BleakScanner
    except ImportError:
        print("bleak not installed: pip install bleak")
        return

    print("Scanning for BLE devices (5 s) …")
    devices = await BleakScanner.discover(timeout=5.0)
    for d in devices:
        print(f"  {d.address}  RSSI {d.rssi:+d} dBm  {d.name!r}")


# ──────────────────────────────────────────────────────────────────────────────
# High-level robot controller
# ──────────────────────────────────────────────────────────────────────────────

class RobotController:
    """High-level robot controller.

    Usage::
        ctrl = RobotController(address="78:83:A0:A8:EC:66", psm=0x0003)
        ctrl.connect()
        ctrl.forward(duration=2.0)   # drive forward for 2 seconds
        ctrl.turn_left(duration=0.5)
        ctrl.stop()
        ctrl.park()
        ctrl.disconnect()

    Or use as a context manager::
        with RobotController() as ctrl:
            ctrl.forward(duration=1.0)
    """

    HEARTBEAT_INTERVAL = 0.25   # seconds between keep-alive packets
    COMMAND_REPEAT_INTERVAL = 0.05  # seconds between repeated movement frames
    ACK_TIMEOUT = 3.0             # seconds to wait for a 7-byte ACK

    def __init__(self, address: str = ROBOT_ADDRESS, psm: int = DEFAULT_PSM,
                 addr_type: int = _BDADDR_BREDR,
                 tok_a: int = 0x13, tok_b: int = 0x65, tok_c: int = 0x03,
                 do_handshake: bool = True,
                 verbose: bool = False):
        self.address       = address
        self.psm           = psm
        self.addr_type     = addr_type
        self._tok_a        = tok_a
        self._tok_b        = tok_b
        self._tok_c        = tok_c
        self._do_handshake = do_handshake
        self.verbose       = verbose
        self._builder   = RobotPacketBuilder(tok_a=tok_a, tok_b=tok_b, tok_c=tok_c)
        self._sock: socket.socket | None = None
        self._hb_thread: threading.Thread | None = None
        self._rx_thread: threading.Thread | None = None
        self._stop_event = threading.Event()       # shared stop for both threads
        # Last ACK event: set whenever a 7-byte ACK arrives from the robot
        self._ack_event  = threading.Event()
        self._last_ack:  bytes | None = None

    # ── connection lifecycle ─────────────────────────────────────────────────

    def connect(self) -> None:
        """Connect to the robot and start the heartbeat and reader threads.

        If do_handshake=True (the default) the iAP2 session setup sequence is
        run automatically after the L2CAP CoC channel is established.  Set
        do_handshake=False only if you have already completed the handshake
        externally or are replaying a captured session.
        """
        print(f"Connecting to {self.address}  PSM=0x{self.psm:04x} …")
        self._sock = connect_coc(self.address, self.psm, self.addr_type)
        print("L2CAP CoC connected.")
        if self._do_handshake:
            print("Running iAP2 handshake …")
            iap2_handshake(self._sock,
                           tok_a=self._tok_a, tok_b=self._tok_b, tok_c=self._tok_c,
                           verbose=self.verbose)
            print("iAP2 handshake complete.")
        self._stop_event.clear()
        self._ack_event.clear()
        self._hb_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True, name="hb")
        self._rx_thread = threading.Thread(
            target=self._reader_loop, daemon=True, name="rx")
        self._hb_thread.start()
        self._rx_thread.start()
        # Send one heartbeat and wait for the robot's first ACK before
        # returning — confirms the session is live and the rx path works.
        self._send(self._builder.heartbeat())
        if self._ack_event.wait(timeout=self.ACK_TIMEOUT):
            print(f"  [ACK] session confirmed  last_ack={self._last_ack.hex(' ')}")
        else:
            print("  [ACK] WARNING — no 7-byte ACK received within "
                  f"{self.ACK_TIMEOUT:.0f}s; robot may not be responding")

    def disconnect(self) -> None:
        """Stop heartbeat/reader threads and close the connection."""
        self._stop_event.set()
        if self._hb_thread:
            self._hb_thread.join(timeout=2.0)
        if self._rx_thread:
            self._rx_thread.join(timeout=2.0)
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        print("Disconnected.")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()

    # ── internal ─────────────────────────────────────────────────────────────

    def _send(self, pkt: bytes) -> None:
        if self._sock is None:
            raise RuntimeError("Not connected")
        self._sock.send(pkt)

    def _heartbeat_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._send(self._builder.heartbeat())
            except OSError:
                break
            self._stop_event.wait(self.HEARTBEAT_INTERVAL)

    def _reader_loop(self) -> None:
        """Drain all robot→host frames, log them, and signal ACK events.

        Runs in a background thread.  Uses select() to poll so the socket's
        blocking mode (and send() behaviour in the main thread) is unaffected.
        Every 7-byte frame whose byte[0]==tok_a and byte[1]==0x05 is an ACK.
        """
        sock = self._sock
        if sock is None:
            return
        while not self._stop_event.is_set():
            # Poll for readability without touching the socket's timeout/blocking mode
            try:
                readable, _, _ = select.select([sock], [], [], 0.5)
            except OSError:
                break
            if not readable:
                continue
            try:
                frame = sock.recv(512)
            except OSError:
                break
            if not frame:
                break
            # 7-byte ACK: byte 0 == host tok_a, byte 1 == 0x05
            is_ack = (len(frame) == 7
                      and frame[0] == self._tok_a
                      and frame[1] == 0x05)
            if is_ack:
                self._last_ack = frame
                self._ack_event.set()
                self._ack_event.clear()   # auto-reset for next wait()
            if self.verbose:
                tag = "ACK" if is_ack else f"{len(frame)}B"
                print(f"  [RX {tag:>5}]  {frame.hex(' ')}", flush=True)

    def wait_for_ack(self, timeout: float | None = None) -> bool:
        """Block until the robot sends a 7-byte ACK, then return True.

        Returns False if the timeout (default: ACK_TIMEOUT) expires first.
        Useful after a one-shot command to confirm the robot received it.
        """
        return self._ack_event.wait(
            timeout=timeout if timeout is not None else self.ACK_TIMEOUT)

    # ── commands ─────────────────────────────────────────────────────────────

    def send_movement(self, m1: int, m2: int, duration: float = 0.0) -> None:
        """Send a raw movement packet (m1, m2) for 'duration' seconds.

        If duration is 0, sends a single packet.  The movement is followed
        by a stop packet when duration > 0.
        """
        if duration <= 0:
            self._send(self._builder.movement(m1, m2))
            return
        t_end = time.monotonic() + duration
        while time.monotonic() < t_end:
            self._send(self._builder.movement(m1, m2))
            time.sleep(self.COMMAND_REPEAT_INTERVAL)
        self._send(self._builder.stop())

    def forward(self, duration: float = 0.5,
                speed: int = MOTOR_FWD_MAX) -> None:
        """Drive forward.

        Args:
            duration: seconds to drive (0 = single packet)
            speed:    motor value 0x80–0xFF  (0xFF = max)
        """
        speed = max(0x80, min(0xFF, speed))
        self.send_movement(speed, MOTOR_NEUTRAL, duration)

    def backward(self, duration: float = 0.5,
                 speed: int = MOTOR_BWD_MAX) -> None:
        """Drive backward.

        Args:
            duration: seconds to drive (0 = single packet)
            speed:    motor value 0x00–0x7E  (0x00 = max, captured was 0x3F)
        """
        speed = max(0x00, min(0x7E, speed))
        self.send_movement(speed, MOTOR_NEUTRAL, duration)

    def turn_left(self, duration: float = 0.5,
                  speed: int = MOTOR_TURN_MAX) -> None:
        """Turn left.

        Args:
            duration: seconds to turn
            speed:    steer motor value 0x80–0xFF
        """
        speed = max(0x80, min(0xFF, speed))
        self.send_movement(MOTOR_NEUTRAL, speed, duration)

    def turn_right(self, duration: float = 0.5,
                   speed: int = MOTOR_TURN_OPP) -> None:
        """Turn right.

        Args:
            duration: seconds to turn
            speed:    steer motor value 0x00–0x7E  (0x00 = max right)
        """
        speed = max(0x00, min(0x7E, speed))
        self.send_movement(MOTOR_NEUTRAL, speed, duration)

    def stop(self) -> None:
        """Send a neutral / stop packet."""
        self._send(self._builder.stop())
        if self.verbose:
            print("  [CMD] stop sent")

    def park(self) -> None:
        """Send the park/unpark toggle command."""
        self._send(self._builder.park())
        acked = self.wait_for_ack()
        print(f"  [CMD] park {'ACK ✓' if acked else 'NO ACK ✕'}")

    def raise_arm(self) -> None:
        """Send the arm-raise toggle command."""
        self._send(self._builder.raise_arm())
        acked = self.wait_for_ack()
        print(f"  [CMD] raise_arm {'ACK ✓' if acked else 'NO ACK ✕'}")

    def lower_arm(self) -> None:
        """Send the arm-lower toggle command."""
        self._send(self._builder.lower_arm())
        acked = self.wait_for_ack()
        print(f"  [CMD] lower_arm {'ACK ✓' if acked else 'NO ACK ✕'}")

    def custom_move(self, m1: int, m2: int,
                    duration: float = 0.0) -> None:
        """Send a custom movement with explicit motor values.

        m1 and m2 are raw byte values:
            0x00–0x7E = backward/right  (0x00 = max)
            0x7F      = neutral/stop
            0x80–0xFF = forward/left    (0xFF = max)
        """
        self.send_movement(m1, m2, duration)


# ──────────────────────────────────────────────────────────────────────────────
# Packet verification (self-test)
# ──────────────────────────────────────────────────────────────────────────────

def verify_packets() -> None:
    """Verify packet construction against known values from the captures.

    Session 1 tokens: tok_a=0x09  tok_b=0x40  tok_c=0x02  (default)
    Session 2 tokens: tok_a=0x13  tok_b=0x65  tok_c=0x03
    """
    print("=== Packet self-test ===")
    all_ok = True

    def check(label: str, got: bytes, expected: bytes) -> None:
        nonlocal all_ok
        ok = got == expected
        if not ok:
            all_ok = False
        print(f"  {label}: {'OK' if ok else 'MISMATCH'}")
        if not ok:
            print(f"    got     : {got.hex(' ')}")
            print(f"    expected: {expected.hex(' ')}")

    # ── Session 1 (tok_a=0x09, tok_b=0x40, tok_c=0x02) ───────────────────
    # forward @ counter 0x65dc  (from forward.log)
    b1 = RobotPacketBuilder(initial_counter=0x65DC)
    check("S1 forward  @ 0x65dc",
          b1.movement(0xFE, 0x7F),
          bytes.fromhex("09ef3dff5a001e40dc6503050002000001000109010101050"
                        "1fe017f010001 8cde40".replace(" ", "")))

    # neutral @ counter 0x65dd
    check("S1 neutral  @ 0x65dd",
          b1.movement(0x7F, 0x7F),
          bytes.fromhex("09ef3dff5a001e40dd6503040002000001000109010101050"
                        "17f017f010001 0ddc40".replace(" ", "")))

    # heartbeat @ counter 0x838c  (from park.log)
    bh1 = RobotPacketBuilder(initial_counter=0x838C)
    check("S1 heartbeat @ 0x838c",
          bh1.heartbeat(),
          bytes.fromhex("09ef13ff5a0009408c83004f40"))

    # park toggle @ counter 0xb0ab, tick=0x8d  (first park in park.log)
    bp1 = RobotPacketBuilder(initial_counter=0xB0AB, tok_a=0x09, tok_b=0x40, tok_c=0x02)
    bp1._tick_a = 0x8D
    check("S1 park     @ 0xb0ab",
          bp1.park(),
          bytes.fromhex("09ef51ff5a0028 40abb003e1000200000100010701030120018d01b7"
                        "0000010001070103012001 8e01b81440".replace(" ", "")))

    # ── Session 2 (tok_a=0x13, tok_b=0x65, tok_c=0x03) ───────────────────
    # turn right @ counter 0xaec7  (first movement packet in turn right 2.log)
    b2 = RobotPacketBuilder(initial_counter=0xAEC7,
                            tok_a=0x13, tok_b=0x65, tok_c=0x03)
    check("S2 turn right @ 0xaec7",
          b2.movement(0x7F, 0x01),
          bytes.fromhex("13ef3dff5a001e40c7ae03d10003000001000109010101050"
                        "17f0101010001 8fd765".replace(" ", "")))

    # neutral @ counter 0xaec8
    check("S2 neutral  @ 0xaec8",
          b2.movement(0x7F, 0x7F),
          bytes.fromhex("13ef3dff5a001e40c8ae03d00003000001000109010101050"
                        "17f017f010001 0ddb65".replace(" ", "")))

    # heartbeat @ counter 0xafc7  (from turn right 2.log)
    bh2 = RobotPacketBuilder(initial_counter=0xAFC7,
                             tok_a=0x13, tok_b=0x65, tok_c=0x03)
    check("S2 heartbeat @ 0xafc7",
          bh2.heartbeat(),
          bytes.fromhex("13ef13ff5a0009 40c7af00e865".replace(" ", "")))

    # raise/park toggle @ counter 0x176b, tick=0x97  (first raise in raise.log)
    br2 = RobotPacketBuilder(initial_counter=0x176B,
                             tok_a=0x13, tok_b=0x65, tok_c=0x03)
    br2._tick_a = 0x97
    check("S2 raise    @ 0x176b",
          br2.raise_arm(),
          bytes.fromhex("13ef51ff5a002840 6b1703ba000300000100010701030120019701c1"
                        "0000010001070103012001 9801c2eb65".replace(" ", "")))

    # second raise @ counter 0x2879, tick=0xac  (second raise in raise.log)
    br2._counter = 0x2879
    br2._tick_a = 0xAC
    check("S2 raise    @ 0x2879",
          br2.raise_arm(),
          bytes.fromhex("13ef51ff5a00284079280 39b000300000100010701030120 01ac01d6"
                        "0000010001070103012001 ad01d79765".replace(" ", "")))

    # ── Checksum table ────────────────────────────────────────────────────
    bt = RobotPacketBuilder()
    print()
    print("  Motor value checksum table (session 1 defaults):")
    print("  {:>6}  {:>6}  {:>6}  {:>6}".format("m1", "m2", "ck1", "ck2"))
    for m1, m2 in [(0xFE, 0x7F), (0x7F, 0x7F), (0x3F, 0x7F),
                   (0x7F, 0xFE), (0x7F, 0x01), (0xFF, 0xFF), (0x00, 0x00)]:
        pkt = bt.movement(m1, m2)
        print(f"  0x{m1:02x}    0x{m2:02x}    0x{pkt[31]:02x}    0x{pkt[32]:02x}")

    print()
    print(f"Overall: {'ALL OK' if all_ok else 'FAILURES — see above'}")
    print()


# ──────────────────────────────────────────────────────────────────────────────
# CLI entry-point
# ──────────────────────────────────────────────────────────────────────────────

def _run_demo(ctrl: RobotController) -> None:
    """Simple demo: forward, turn, park/unpark toggle."""
    steps = [
        ("forward 1.0s",   lambda: ctrl.forward(duration=1.0)),
        ("turn_left 0.6s", lambda: ctrl.turn_left(duration=0.6)),
        ("forward 1.0s",   lambda: ctrl.forward(duration=1.0)),
        ("turn_left 0.6s", lambda: ctrl.turn_left(duration=0.6)),
        ("forward 1.0s",   lambda: ctrl.forward(duration=1.0)),
        ("turn_left 0.6s", lambda: ctrl.turn_left(duration=0.6)),
        ("forward 1.0s",   lambda: ctrl.forward(duration=1.0)),
        ("turn_left 0.6s", lambda: ctrl.turn_left(duration=0.6)),
        ("stop",           lambda: ctrl.stop()),
        ("park",           lambda: ctrl.park()),
        ("park (unpark)",  lambda: ctrl.park()),
    ]
    print(f"Demo: {len(steps)} steps")
    for label, fn in steps:
        print(f"  >> {label}")
        fn()
        time.sleep(0.2)


def _interactive(ctrl: RobotController) -> None:
    """Simple WASD keyboard controller (requires pynput or similar)."""
    print("Interactive mode — keys: W=forward  S=backward  A=left  D=right")
    print("                         P=park  Q=quit")
    print("(Each key-press sends one movement packet.)")

    # Very simple stdin-based control (no raw-mode; requires ENTER after key)
    while True:
        try:
            key = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break
        if key == "q":
            break
        elif key == "w":
            ctrl.forward(duration=0.5)
        elif key == "s":
            ctrl.backward(duration=0.5)
        elif key == "a":
            ctrl.turn_left(duration=0.4)
        elif key == "d":
            ctrl.turn_right(duration=0.4)
        elif key == "p":
            ctrl.park()
        else:
            print("  Unknown key. W/S/A/D/P/Q")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BLE robot controller (reverse-engineered)")
    parser.add_argument("--address", default=ROBOT_ADDRESS,
                        help="Robot BLE MAC address (default: %(default)s)")
    parser.add_argument("--psm", default=f"0x{DEFAULT_PSM:04x}",
                        help="L2CAP CoC PSM (default: %(default)s)")
    parser.add_argument("--addr-type", default="bredr",
                        choices=["public", "random", "bredr"],
                        help="Address type: bredr (classic), public (BLE), random (BLE) "
                             "(default: %(default)s)")
    parser.add_argument("--scan", action="store_true",
                        help="Scan for nearby BLE devices and exit")
    parser.add_argument("--discover-psm", action="store_true",
                        help="Connect via GATT and dump characteristics to find PSM")
    parser.add_argument("--self-test", action="store_true",
                        help="Run packet construction self-tests and exit")
    parser.add_argument("--demo", action="store_true",
                        help="Run the built-in square-path demo")
    parser.add_argument("--interactive", action="store_true",
                        help="Launch WASD interactive keyboard control")
    parser.add_argument("--verbose", action="store_true",
                        help="Print every RX frame from the robot")
    args = parser.parse_args()

    if args.self_test:
        verify_packets()
        return

    if args.scan:
        asyncio.run(scan_devices())
        return

    psm = int(args.psm, 0)
    addr_type = {"public": _BDADDR_LE_PUBLIC,
                 "random": _BDADDR_LE_RANDOM,
                 "bredr":  _BDADDR_BREDR}[args.addr_type]

    if args.discover_psm:
        asyncio.run(discover_psm(args.address))
        return

    try:
        with RobotController(args.address, psm, addr_type,
                             verbose=args.verbose) as ctrl:
            if args.demo:
                _run_demo(ctrl)
            elif args.interactive:
                _interactive(ctrl)
            else:
                # Default: run the demo
                _run_demo(ctrl)
    except PermissionError:
        print("Permission denied.  L2CAP CoC requires CAP_NET_RAW:")
        print("  sudo python3 robot_control.py")
        print("  OR: sudo setcap cap_net_raw+eip $(which python3)")
        sys.exit(1)
    except ConnectionRefusedError:
        print(f"Connection refused on PSM 0x{psm:04x}.")
        print("Hint: run --discover-psm to scan for the correct PSM value.")
        sys.exit(1)
    except OSError as e:
        print(f"Connection error: {e}")
        print(f"Tried: address={args.address}, PSM=0x{psm:04x}, type={args.addr_type}")
        sys.exit(1)


if __name__ == "__main__":
    main()
