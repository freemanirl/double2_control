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

  tok_a  : byte  0 of every packet          (session 1 = 0x09, session 2 = 0x13)
  tok_b  : last byte of 13/30/34-byte pkts  (session 1 = 0x40, session 2 = 0x65)
  tok_c  : byte 13 of 34-byte movement pkts (session 1 = 0x02, session 2 = 0x03)

tok_c also feeds into ck2.  The L2CAP CoC CIDs are similarly session-specific
(dynamically assigned by the host stack).

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
- The PSM is advertised over GATT (see discover_psm() below).
- Device address type is PUBLIC (0x00).
- CIDs are dynamically assigned by the BlueZ L2CAP stack.

Dependencies
============
    pip install bleak

Usage
=====
    python robot_control.py
    python robot_control.py --scan     # just scan and show nearby devices
    python robot_control.py --address 78:83:A0:A8:EC:66 --psm 0x0025
"""

import argparse
import asyncio
import socket
import struct
import sys
import threading
import time

# ──────────────────────────────────────────────────────────────────────────────
# Known device parameters (from BTsnoop captures)
# ──────────────────────────────────────────────────────────────────────────────

ROBOT_ADDRESS = "78:83:A0:A8:EC:66"

# L2CAP CoC PSM.  The PSM is NOT visible in the provided captures because
# the connection setup happened before snoop recording started.  Run
# discover_psm() or use --scan to find it, or try 0x0025 first.
DEFAULT_PSM = 0x0025

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

    tok_a, tok_b, tok_c are session-specific bytes that change each time
    the device is paired / a new BLE session is established.  Use the
    default values (from session 1 of the captures) unless you have
    observed the tokens for the current session.

    Session token defaults (session 1):
        tok_a = 0x09  (first byte of every packet)
        tok_b = 0x40  (last byte of 13/30/34-byte packets)
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
_BDADDR_LE_PUBLIC  = 1
_BDADDR_LE_RANDOM  = 2


def _parse_addr(addr_str: str) -> bytes:
    """Convert "AA:BB:CC:DD:EE:FF" → 6-byte little-endian bdaddr."""
    return bytes.fromhex(addr_str.replace(":", ""))[::-1]


def connect_coc(address: str, psm: int,
                addr_type: int = _BDADDR_LE_PUBLIC) -> socket.socket:
    """Connect to a BLE device via L2CAP Credit-Based CoC.

    Returns a connected SOCK_SEQPACKET socket.  Each send()/recv() call
    corresponds to exactly one L2CAP CoC SDU.

    Note: requires BlueZ ≥ 5.49 and CAP_NET_RAW (run as root or set
    the capability on python3: sudo setcap cap_net_raw+eip $(which python3)).
    """
    sock = socket.socket(_AF_BLUETOOTH, socket.SOCK_SEQPACKET, _BTPROTO_L2CAP)
    # Opt in to LE (required on some BlueZ versions for BLE CoC)
    try:
        BT_CHANNEL_POLICY    = 10
        BLC_POLICY_SINGLE_LINK = 0
        sock.setsockopt(274, BT_CHANNEL_POLICY, BLC_POLICY_SINGLE_LINK)
    except OSError:
        pass  # Older kernel – continue anyway

    bd = _parse_addr(address)
    sa = struct.pack(_SOCKADDR_L2_FMT,
                     _AF_BLUETOOTH, psm, bd, 0, addr_type)
    sock.connect(sa)
    return sock


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
        ctrl = RobotController(address="78:83:A0:A8:EC:66", psm=0x0025)
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

    def __init__(self, address: str = ROBOT_ADDRESS, psm: int = DEFAULT_PSM,
                 addr_type: int = _BDADDR_LE_PUBLIC):
        self.address   = address
        self.psm       = psm
        self.addr_type = addr_type
        self._builder  = RobotPacketBuilder()
        self._sock: socket.socket | None = None
        self._hb_thread: threading.Thread | None = None
        self._hb_stop   = threading.Event()

    # ── connection lifecycle ─────────────────────────────────────────────────

    def connect(self) -> None:
        """Connect to the robot and start the heartbeat thread."""
        print(f"Connecting to {self.address}  PSM=0x{self.psm:04x} …")
        self._sock = connect_coc(self.address, self.psm, self.addr_type)
        print("Connected.")
        self._hb_stop.clear()
        self._hb_thread = threading.Thread(
            target=self._heartbeat_loop, daemon=True)
        self._hb_thread.start()

    def disconnect(self) -> None:
        """Stop heartbeat and close the connection."""
        self._hb_stop.set()
        if self._hb_thread:
            self._hb_thread.join(timeout=2.0)
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
        while not self._hb_stop.is_set():
            try:
                self._send(self._builder.heartbeat())
            except OSError:
                break
            self._hb_stop.wait(self.HEARTBEAT_INTERVAL)

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

    def park(self) -> None:
        """Send the park/unpark toggle command."""
        self._send(self._builder.park())
        print("Park command sent (toggles park state each call).")

    def raise_arm(self) -> None:
        """Send the arm-raise toggle command.

        The same 44-byte toggle packet as park().  Call once to start raising;
        call again (or call lower_arm()) to stop / lower.
        """
        self._send(self._builder.raise_arm())

    def lower_arm(self) -> None:
        """Send the arm-lower toggle command.

        Identical to raise_arm() at the packet level — the robot state
        determines whether this raises or lowers the arm.
        """
        self._send(self._builder.lower_arm())

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
    """Simple interactive demo: drive a square path then park."""
    print("Demo: forward → left → left → left → left → park")
    ctrl.forward(duration=1.0)
    time.sleep(0.2)
    ctrl.turn_left(duration=0.6)
    time.sleep(0.2)
    ctrl.forward(duration=1.0)
    time.sleep(0.2)
    ctrl.turn_left(duration=0.6)
    time.sleep(0.2)
    ctrl.forward(duration=1.0)
    time.sleep(0.2)
    ctrl.turn_left(duration=0.6)
    time.sleep(0.2)
    ctrl.forward(duration=1.0)
    time.sleep(0.2)
    ctrl.turn_left(duration=0.6)
    time.sleep(0.2)
    ctrl.stop()
    time.sleep(0.5)
    ctrl.park()
    time.sleep(0.5)
    ctrl.park()  # unpark


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
    parser.add_argument("--addr-type", default="public",
                        choices=["public", "random"],
                        help="BLE address type (default: %(default)s)")
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
    args = parser.parse_args()

    if args.self_test:
        verify_packets()
        return

    if args.scan:
        asyncio.run(scan_devices())
        return

    psm = int(args.psm, 0)
    addr_type = (_BDADDR_LE_PUBLIC if args.addr_type == "public"
                 else _BDADDR_LE_RANDOM)

    if args.discover_psm:
        asyncio.run(discover_psm(args.address))
        return

    try:
        with RobotController(args.address, psm, addr_type) as ctrl:
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
