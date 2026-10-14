#!/usr/bin/env python3
"""
Gateway lab for `make run-gateway`: the modem (with "the Internet" behind it)
on one side of the YesOS bridge and the router (with the house behind it) on
the other, over the UDP sockets QEMU's -netdev dgram uses.

Every couple of seconds the "house" browses (HTTPS to a few sites, answered by
"the Internet"), resolves names (some of them ad and tracker domains), and now
and then something tries what the gateway should stop: an Intel AMT probe from
the Internet, an AMT CIRA call home, DASH / WS-Management, RMCP. Each event is
written to the log with what happened to it: crossed, blocked by YesOS, or DNS
answered by the NAS (interception on) or by "the Internet".

  python3 tools/gateway_lab.py [--log FILE] [--interval SECONDS]

Ports (must match the Makefile): WAN QEMU 40101 <-> lab 40102,
LAN QEMU 40103 <-> lab 40104.
"""
import argparse
import hashlib
import os
import random
import socket
import struct
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(1, os.path.join(os.path.dirname(HERE), "core", "tools"))  # YesOS core tools
from bridge_frames import (MODEM_MAC, ROUTER_MAC, MODEM_IP, ROUTER_IP, arp, eth, ipv4, tcp, udp, v4_frame)  # noqa: E402
import dns_wire as td  # noqa: E402

WAN_QEMU, WAN_LAB, LAN_QEMU, LAN_LAB = 40101, 40102, 40103, 40104
SITES = [("93.184.216.34", "example.org"), ("185.15.59.224", "wikipedia.org"), ("140.82.112.3", "github.com"),
         ("151.101.1.140", "reddit.com"), ("104.16.132.229", "cloudflare.com")]
NAMES = ["example.org", "wikipedia.org", "github.com", "doubleclick.net", "googleadservices.com",
         "google-analytics.com", "ads.yahoo.com", "use-application-dns.net", "debian.org", "telemetry.microsoft.com"]


class Port:
    def __init__(self, lab_port, qemu_port, answer):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", lab_port))
        self.qemu = qemu_port
        self.seen = []
        self.lock = threading.Lock()
        self.answer = answer
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                f, _ = self.sock.recvfrom(4096)
            except OSError:
                return
            with self.lock:
                self.seen.append((time.time(), f))
                self.seen = self.seen[-2000:]
            for r in self.answer(f) or []:
                self.send(r)

    def send(self, f):
        self.sock.sendto(f, ("127.0.0.1", self.qemu))

    def saw(self, pred, since):
        with self.lock:
            return next((f for t, f in self.seen if t >= since and pred(f)), None)


def fake_ip(name):
    h = hashlib.sha256(name.encode()).digest()
    return f"{h[0] % 200 + 20}.{h[1]}.{h[2]}.{h[3] % 250 + 1}"


def internet(f):
    """Behind the modem: ARP for the modem, DNS servers anywhere, web servers anywhere."""
    if f[12:14] == b"\x08\x06" and f[20:22] == b"\x00\x01" and f[38:42] == socket.inet_aton(MODEM_IP):
        return [eth(f[6:12], MODEM_MAC, 0x0806, arp(2, MODEM_MAC, MODEM_IP, f[22:28], socket.inet_ntoa(f[28:32])))]
    if f[12:14] != b"\x08\x00" or len(f) < 42:
        return []
    src, dst = socket.inet_ntoa(f[26:30]), socket.inet_ntoa(f[30:34])
    sport, dport = struct.unpack(">HH", f[34:38])
    if f[23] == 17 and dport == 53:
        q = f[42:]
        try:
            labels, o = [], 12
            while q[o]:
                labels.append(q[o + 1:o + 1 + q[o]].decode())
                o += 1 + q[o]
            name = ".".join(labels)
            qend = o + 5
        except (IndexError, UnicodeDecodeError):
            return []
        ans = q[:2] + b"\x81\x80\0\x01\0\x01\0\0\0\0" + q[12:qend] + b"\xc0\x0c\0\x01\0\x01\0\0\x01\x2c\0\x04" + socket.inet_aton(fake_ip(name))
        return [eth(f[6:12], MODEM_MAC, 0x0800, ipv4(dst, src, 17, udp(53, sport, ans)))]
    if f[23] == 6 and f[47] == 0x02 and dport in (443, 80):
        return [v4_frame(f[6:12], MODEM_MAC, dst, src, 6, tcp(dport, sport, 0x12))]
    return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="-")
    ap.add_argument("--interval", type=float, default=2.0)
    a = ap.parse_args()
    out = sys.stdout if a.log == "-" else open(a.log, "a", buffering=1)
    log = lambda s: out.write(time.strftime("%H:%M:%S ") + s + "\n")
    try:
        wan = Port(WAN_LAB, WAN_QEMU, internet)
        lan = Port(LAN_LAB, LAN_QEMU, lambda f: [])
    except OSError as e:
        print(f"gateway lab: cannot open its UDP ports ({e}); is another lab running?", file=sys.stderr)
        return 1
    log("lab started: modem + Internet on the WAN side, router + house on the LAN side")
    rnd = random.Random()
    tick = 0
    bridge_up = False   # nothing has crossed yet: YesOS may still be booting
    while True:
        tick += 1
        events = []
        ip, site = rnd.choice(SITES)
        sport = rnd.randint(40000, 60000)
        events.append((f"house -> {site} ({ip}) HTTPS", lan, v4_frame(MODEM_MAC, ROUTER_MAC, ROUTER_IP, ip, 6, tcp(sport, 443)), wan, "web"))
        name = rnd.choice(NAMES)
        qid, q = td.query(name)
        server = rnd.choice(["8.8.8.8", "1.1.1.1", MODEM_IP])
        events.append((f"house asks {server} for {name}", lan,
                       v4_frame(MODEM_MAC, ROUTER_MAC, ROUTER_IP, server, 17, udp(rnd.randint(40000, 60000), 53, q)), wan, ("dns", qid)))
        if tick % 5 == 0:
            events.append(("the Internet (203.0.113.66) probes Intel AMT on port 16992", wan,
                           v4_frame(ROUTER_MAC, MODEM_MAC, "203.0.113.66", ROUTER_IP, 6, tcp(rnd.randint(40000, 60000), 16992)), lan, "attack"))
        if tick % 7 == 0:
            events.append(("a PC tries AMT CIRA (calling home, 198.51.100.20:4433)", lan,
                           v4_frame(MODEM_MAC, ROUTER_MAC, ROUTER_IP, "198.51.100.20", 6, tcp(rnd.randint(40000, 60000), 4433)), wan, "attack"))
        if tick % 11 == 0:
            events.append(("a PC tries DASH / WS-Management (5986)", lan,
                           v4_frame(MODEM_MAC, ROUTER_MAC, ROUTER_IP, "198.51.100.21", 6, tcp(rnd.randint(40000, 60000), 5986)), wan, "attack"))
        if tick % 13 == 0:
            events.append(("the Internet sends RMCP/ASF (UDP 623)", wan,
                           v4_frame(ROUTER_MAC, MODEM_MAC, "203.0.113.67", ROUTER_IP, 17, udp(rnd.randint(40000, 60000), 623, b"\x06\0\xff\x06" + b"\0" * 8)), lan, "attack"))
        for text, src, frame, dst, kind in events:
            t0 = time.time()
            src.send(frame)
            time.sleep(0.4)
            crossed = dst.saw(lambda f: f == frame, t0) is not None
            if crossed:
                bridge_up = True
            elif not bridge_up and kind in ("web", "attack"):
                log(f"{text}: no answer (YesOS is not forwarding yet: still booting?)")
                continue
            if kind == "attack" or kind == "web":
                answered = kind == "web" and lan.saw(lambda f: f[12:14] == b"\x08\x00" and len(f) > 47 and f[23] == 6 and f[47] == 0x12
                                                    and struct.unpack(">H", f[36:38])[0] == struct.unpack(">H", frame[34:36])[0], t0)
                log(f"{text}: {'crossed' + (' and was answered' if answered else '') if crossed else 'BLOCKED by YesOS'}")
            else:
                qid = kind[1]
                ans = lan.saw(lambda f: f[12:14] == b"\x08\x00" and len(f) > 44 and f[23] == 17
                              and f[34:36] == b"\x00\x35" and f[42:44] == struct.pack(">H", qid), t0)
                if ans is None:
                    log(f"{text}: no answer")
                else:
                    r = td.parse(ans[42:])
                    who = "Internet" if crossed else "the NAS DNS filter (intercepted)"
                    res = "NXDOMAIN" if r["rcode"] == 3 else (", ".join(td.addr(r)) or "no data")
                    log(f"{text}: {res} — answered by {who}" + (" — BLOCKED" if res in ("0.0.0.0", "NXDOMAIN") else ""))
        time.sleep(max(0.0, a.interval - 0.4 * len(events)))


if __name__ == "__main__":
    sys.exit(main())
