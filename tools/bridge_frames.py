#!/usr/bin/env python3
"""
Raw Ethernet frames for the YesOS Security bridge tests and lab: frame
builders (Ethernet, VLAN, PPPoE, IPv4, IPv6, TCP, UDP, ARP) and Side, one
side of the bridge as a UDP socket that QEMU's -netdev dgram talks to.
"""
import socket
import struct
import threading
import time

MODEM_MAC = bytes.fromhex("020000000001")
ROUTER_MAC = bytes.fromhex("020000000002")
MODEM_IP = "192.168.1.1"
ROUTER_IP = "192.168.1.2"
NAS_IP = "192.168.1.50"


def free_ports(n):
    socks = [socket.socket() for _ in range(n)]
    for k in socks:
        k.bind(("127.0.0.1", 0))
    ports = [k.getsockname()[1] for k in socks]
    for k in socks:
        k.close()
    return ports


# ---------------------------------------------------------------------------
# Frame builders
# ---------------------------------------------------------------------------

def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f">{len(b) // 2}H", b))
    while s > 0xFFFF:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def eth(dst, src, etype, payload):
    return dst + src + struct.pack(">H", etype) + payload


def ipv4(src, dst, proto, payload, ident=1):
    h = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    h = h[:10] + struct.pack(">H", csum(h)) + h[12:]
    return h + payload


def ipv6(src, dst, nh, payload, ext=b""):
    first_nh = 0 if ext else nh
    return struct.pack(">IHBB", 0x60000000, len(ext) + len(payload), first_nh, 64) + \
        socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + ext + payload


def hop_by_hop(nh):
    return bytes([nh, 0]) + b"\x01\x04\0\0\0\0"     # 8 bytes, PadN


def udp(sport, dport, data):
    return struct.pack(">HHHH", sport, dport, 8 + len(data), 0) + data


def tcp(sport, dport, flags=0x02):
    return struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 0x50, flags, 64240, 0, 0)


def vlan(vid, etype, payload, outer=0x8100):
    return struct.pack(">HH", vid, etype) + payload, outer


def v4_frame(dst_mac, src_mac, src, dst, proto, l4):
    return eth(dst_mac, src_mac, 0x0800, ipv4(src, dst, proto, l4))


def out_tcp(dport, sport=40000, dst="93.184.216.34"):
    return v4_frame(MODEM_MAC, ROUTER_MAC, ROUTER_IP, dst, 6, tcp(sport, dport))


def in_tcp(dport, sport=443, src="93.184.216.34"):
    return v4_frame(ROUTER_MAC, MODEM_MAC, src, ROUTER_IP, 6, tcp(sport, dport))


def pppoe(session, ip_pkt, v6=False):
    ppp = struct.pack(">H", 0x0057 if v6 else 0x0021) + ip_pkt
    return struct.pack(">BBHH", 0x11, 0, session, len(ppp)) + ppp


def arp(op, smac, sip, tmac, tip):
    return struct.pack(">HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op, smac, socket.inet_aton(sip), tmac, socket.inet_aton(tip))


# ---------------------------------------------------------------------------
# One side of the bridge (a UDP socket that QEMU's dgram netdev talks to)
# ---------------------------------------------------------------------------

class Side:
    def __init__(self, name):
        self.name = name
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.qemu_port = free_ports(1)[0]
        self.frames = []
        self.lock = threading.Lock()
        self.responder = None          # fn(frame) -> reply frames (the emulated modem)
        self.running = True
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while self.running:
            try:
                data, _ = self.sock.recvfrom(4096)
            except OSError:
                return
            with self.lock:
                self.frames.append(data)
            if self.responder:
                for r in self.responder(data) or []:
                    self.send(r)

    def netdev(self, nid, mac):
        return ["-netdev", f"dgram,id={nid},local.type=inet,local.host=127.0.0.1,local.port={self.qemu_port},"
                           f"remote.type=inet,remote.host=127.0.0.1,remote.port={self.port}",
                "-device", f"virtio-net-pci,netdev={nid},mac={mac}"]

    def send(self, frame):
        self.sock.sendto(frame, ("127.0.0.1", self.qemu_port))

    def clear(self):
        with self.lock:
            self.frames = []

    def wait(self, pred, timeout=3.0):
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                for f in self.frames:
                    if pred(f):
                        return f
            time.sleep(0.02)
        return None

    def got(self, frame, timeout=3.0):
        return self.wait(lambda f: f == frame, timeout) is not None

    def close(self):
        self.running = False
        self.sock.close()


def passes(src_side, dst_side, frame, timeout=3.0):
    dst_side.clear()
    src_side.send(frame)
    return dst_side.got(frame, timeout)


def blocked(src_side, dst_side, frame, settle=0.6):
    dst_side.clear()
    src_side.send(frame)
    time.sleep(settle)
    return dst_side.wait(lambda f: f == frame, 0.01) is None
