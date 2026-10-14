"""
Phone leg audio for shorebridge: G.711 mu-law and a small RTP endpoint.

The phone speaks plain RTP with PCMU. The PBX side is handled by pjsua2, which
hands us 16 bit PCM frames. PhoneRtpLeg converts between the two. It receives
RTP from the phone, decodes it to PCM for pjsua2, and encodes PCM from pjsua2
into RTP for the phone. It also carries DTMF (RFC 4733 telephone-event) in
both directions.

This module only needs the Python standard library. The G.711 code is here
because the audioop module was removed from Python in version 3.13.
"""
import array
import os
import select
import socket
import threading
import time

FRAME_SAMPLES = 160                 # 20 ms at 8 kHz
FRAME_BYTES = FRAME_SAMPLES * 2     # 16 bit samples
PCMU_PT = 0

# Jitter buffer limits for audio coming from the phone, in frames.
PREBUFFER_FRAMES = 2
MAX_BUFFER_FRAMES = 10
TRIM_BUFFER_FRAMES = 3

DTMF_DIGITS = "0123456789*#ABCD"
DTMF_CODES = {d: i for i, d in enumerate(DTMF_DIGITS)}


# G.711 mu-law

def _ulaw_to_linear(u):
    u = ~u & 0xFF
    t = (((u & 0x0F) << 3) + 0x84) << ((u & 0x70) >> 4)
    return (0x84 - t) if (u & 0x80) else (t - 0x84)


def _linear_to_ulaw(sample):
    # Reference encoder. It is only used to build the lookup tables below.
    sign = 0
    if sample < 0:
        sample = -sample
        sign = 0x80
    if sample > 32635:
        sample = 32635
    sample += 0x84
    exponent = 7
    mask = 0x4000
    while exponent > 0 and not (sample & mask):
        exponent -= 1
        mask >>= 1
    mantissa = (sample >> (exponent + 3)) & 0x0F
    return ~(sign | (exponent << 4) | mantissa) & 0xFF


_DECODE = [array.array("h", [_ulaw_to_linear(i)]).tobytes() for i in range(256)]
# Encode tables are indexed by magnitude >> 2. Every mu-law segment boundary
# falls on a multiple of 4, so this loses nothing against the reference encoder.
_ENC_POS = [_linear_to_ulaw(i << 2) for i in range(8193)]
_ENC_NEG = [_linear_to_ulaw(-(i << 2) if i else -1) for i in range(8193)]


def ulaw_decode(data):
    """Decode mu-law bytes to native endian 16 bit PCM bytes."""
    table = _DECODE
    return b"".join([table[b] for b in data])


def ulaw_encode(pcm):
    """Encode native endian 16 bit PCM bytes to mu-law bytes."""
    samples = array.array("h")
    samples.frombytes(pcm[:len(pcm) & ~1])
    out = bytearray(len(samples))
    pos, neg = _ENC_POS, _ENC_NEG
    for i, s in enumerate(samples):
        out[i] = pos[s >> 2] if s >= 0 else neg[(-s) >> 2]
    return bytes(out)


# RTP

def parse_rtp(data):
    """Return (payload_type, marker, seq, timestamp, ssrc, payload) or None."""
    if len(data) < 12 or (data[0] >> 6) != 2:
        return None
    off = 12 + 4 * (data[0] & 0x0F)
    if data[0] & 0x10:
        if len(data) < off + 4:
            return None
        off += 4 + 4 * int.from_bytes(data[off + 2:off + 4], "big")
    end = len(data)
    if data[0] & 0x20 and end > 0:
        end -= data[-1]
    if off > end:
        return None
    return (data[1] & 0x7F, data[1] >> 7, int.from_bytes(data[2:4], "big"),
            int.from_bytes(data[4:8], "big"), int.from_bytes(data[8:12], "big"), data[off:end])


def build_rtp(pt, marker, seq, ts, ssrc, payload):
    head = bytes([0x80, (0x80 if marker else 0) | pt]) + seq.to_bytes(2, "big") \
        + ts.to_bytes(4, "big") + ssrc.to_bytes(4, "big")
    return head + payload


class PhoneRtpLeg:
    """The RTP side of a call toward the phone.

    pjsua2 pulls audio with read_frame() and pushes audio with write_frame(),
    both once every 20 ms from its media clock thread. Packets from the phone
    are received on a thread of our own and queued in a small jitter buffer.
    """

    def __init__(self, sock, port, log=None, dbg=None):
        self.sock = sock
        self.port = port
        self.log = log or (lambda m: None)
        self.dbg = dbg or (lambda m: None)
        self.remote = None          # (ip, port) of the phone, learned from SDP and from packets
        self.dtmf_pt = None         # telephone-event payload type used by the phone
        self.on_dtmf = None         # called with a digit when the phone sends one
        self.active = False         # audio only flows once the call is answered
        self.rx_packets = 0
        self.tx_packets = 0
        self._running = False
        self._buf = bytearray()
        self._primed = False
        self._lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._seq = int.from_bytes(os.urandom(2), "big")
        self._ts = int.from_bytes(os.urandom(4), "big")
        self._ssrc = int.from_bytes(os.urandom(4), "big")
        self._marker = True
        self._dtmf_busy = False
        self._dtmf_lock = threading.Lock()
        self._last_event = None

    @classmethod
    def open(cls, ip, low, high, log=None, dbg=None):
        # Do not set SO_REUSEADDR here. On Linux it lets two UDP sockets share one
        # port, which made the phone leg and the PBX leg of a call collide.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for p in range(low, high, 2):
            try:
                s.bind((ip, p))
                return cls(s, p, log, dbg)
            except OSError:
                continue
        s.bind((ip, 0))
        return cls(s, s.getsockname()[1], log, dbg)

    def start(self, remote, dtmf_pt, on_dtmf):
        self.remote = remote
        self.dtmf_pt = dtmf_pt
        self.on_dtmf = on_dtmf
        self._running = True
        threading.Thread(target=self._recv_loop, name="phone-rtp", daemon=True).start()

    def activate(self):
        self.active = True

    def stop(self):
        self._running = False
        self.active = False
        try:
            self.sock.close()
        except OSError:
            pass

    # Audio from the phone toward pjsua2

    def _recv_loop(self):
        while self._running:
            try:
                ready, _, _ = select.select([self.sock], [], [], 0.5)
                if not ready:
                    continue
                data, addr = self.sock.recvfrom(2048)
            except (OSError, ValueError):
                if not self._running:
                    break
                continue
            try:
                self._handle_packet(data, addr)
            except Exception as e:
                self.log(f"Phone RTP packet error: {e!r}")

    def _handle_packet(self, data, addr):
        pkt = parse_rtp(data)
        if pkt is None or not self.active:
            return
        pt, _marker, _seq, ts, ssrc, payload = pkt
        self.remote = addr
        self.rx_packets += 1
        if self.rx_packets in (1, 250):
            self.dbg(f"Phone RTP: {self.rx_packets} packets received, {self.tx_packets} sent")
        if self.dtmf_pt is not None and pt == self.dtmf_pt:
            self._handle_event(ssrc, ts, payload)
            return
        if pt != PCMU_PT:
            return
        pcm = ulaw_decode(payload)
        with self._lock:
            self._buf += pcm
            if len(self._buf) > MAX_BUFFER_FRAMES * FRAME_BYTES:
                del self._buf[:len(self._buf) - TRIM_BUFFER_FRAMES * FRAME_BYTES]

    def _handle_event(self, ssrc, ts, payload):
        # Every packet of one key press carries the same timestamp, and the end
        # packet is repeated, so only the first packet of an event counts.
        if len(payload) < 4 or (ssrc, ts) == self._last_event:
            return
        self._last_event = (ssrc, ts)
        code = payload[0]
        if code < len(DTMF_DIGITS) and self.on_dtmf:
            self.on_dtmf(DTMF_DIGITS[code])

    def read_frame(self, size=FRAME_BYTES):
        """Return one frame of PCM from the phone, or silence if none is ready."""
        if not self.active:
            return bytes(size)
        with self._lock:
            if not self._primed and len(self._buf) >= PREBUFFER_FRAMES * FRAME_BYTES:
                self._primed = True
            if self._primed and len(self._buf) >= size:
                out = bytes(self._buf[:size])
                del self._buf[:size]
                return out
            # Ran dry, so wait for the buffer to refill before playing again.
            self._primed = False
        return bytes(size)

    # Audio from pjsua2 toward the phone

    def write_frame(self, pcm):
        """Encode one frame of PCM from the PBX and send it to the phone."""
        if not self.active or not pcm:
            return
        samples = len(pcm) // 2
        with self._send_lock:
            ts = self._ts
            self._ts = (self._ts + samples) & 0xFFFFFFFF
            if self._dtmf_busy or self.remote is None:
                return
            seq = self._seq
            self._seq = (self._seq + 1) & 0xFFFF
            marker = self._marker
            self._marker = False
            packet = build_rtp(PCMU_PT, marker, seq, ts, self._ssrc, ulaw_encode(pcm))
            self._send(packet)

    def _send(self, packet):
        try:
            self.sock.sendto(packet, self.remote)
            self.tx_packets += 1
        except OSError:
            pass

    def send_dtmf(self, digit, duration_ms=120):
        """Send a DTMF digit to the phone as RFC 4733 telephone-events."""
        code = DTMF_CODES.get(digit.upper())
        if code is None or self.dtmf_pt is None or not self.active:
            return
        threading.Thread(target=self._send_event, args=(code, duration_ms),
                         name="phone-dtmf", daemon=True).start()

    def _event_packet(self, code, end, duration, ts, marker):
        payload = bytes([code, (0x80 if end else 0) | 10]) + duration.to_bytes(2, "big")
        with self._send_lock:
            seq = self._seq
            self._seq = (self._seq + 1) & 0xFFFF
            if self.remote is not None:
                self._send(build_rtp(self.dtmf_pt, marker, seq, ts, self._ssrc, payload))

    def _send_event(self, code, duration_ms):
        # One digit at a time, so quick key presses do not interleave.
        with self._dtmf_lock:
            frames = max(2, duration_ms // 20)
            with self._send_lock:
                ts = self._ts
                self._dtmf_busy = True
            try:
                for i in range(frames):
                    self._event_packet(code, False, FRAME_SAMPLES * (i + 1), ts, i == 0)
                    time.sleep(0.02)
                for _ in range(3):
                    self._event_packet(code, True, FRAME_SAMPLES * frames, ts, False)
            finally:
                with self._send_lock:
                    self._dtmf_busy = False
