#!/usr/bin/env python3
"""
YesOS Security image test (yesos.elf).

YesOS Security is the bridge between the modem (ONT) and the router: the
firewall, optional DNS interception and console administration, on its own
freshly formatted disk. The test is the modem on one side and the router on
the other, sending and seeing raw Ethernet frames (QEMU -netdev dgram).

Three-port layout (port 0 = management network, 1 = WAN, 2 = LAN):
  no NAS inside (no NAS commands, no vault, nothing on UDP 31415);
  forwarding of ARP, LLDP, PPPoE discovery and TCP both ways;
  Intel AMT / CIRA / DASH / RMCP / provisioning blocked, also inside VLAN,
  QinQ, PPPoE, IPv6 with extension headers and IPv6 over PPPoE;
  malformed frames dropped and 400 random frames survived;
  console rules (ports, ranges, IPv4 / IPv6 networks), invalid rules
  refused, `fw rules` with hit counters, `fw log` with repeats aggregated,
  groups off/on, the encrypted-DNS-by-IP group;
  DNS interception (plain and inside PPPoE, the answer spoofed from the
  server the router asked, IPv6 DNS dropped); throughput; persistence;
  swapping the WAN and LAN ports.
Two-port layout (the board between the ONT and the router): invisible - no
ARP answers, nothing of its own sent - and still forwarding and blocking.

Usage: python3 tools/test_security.py      (after `make`; non-zero exit on failure)
"""
import os
import random
import shutil
import socket
import struct
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(1, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core", "tools"))  # YesOS core tools
import yesos_harness as harness  # noqa: E402
import dns_wire as td  # noqa: E402
import bridge_frames as g  # noqa: E402
from bridge_frames import (MODEM_MAC, ROUTER_MAC, ROUTER_IP, eth, ipv4, ipv6, tcp, udp, pppoe, arp,  # noqa: E402
                           v4_frame, out_tcp, in_tcp, hop_by_hop, passes, blocked)
import redsea_fsck  # noqa: E402
import redsea_injector  # noqa: E402

failures = []
KERNEL = harness.KERNEL
OWN_MACS = (bytes.fromhex("525400aa0001"), bytes.fromhex("525400aa0002"))


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label, flush=True)
    if not cond:
        failures.append(label)
    return cond


def boot(disk, wan, lan, mgmt):
    """Security image; with mgmt, port 0 is QEMU's user network (UDP 31415 forwarded)."""
    orig_popen = harness.subprocess.Popen
    udp_port = g.free_ports(1)[0]

    def popen(cmd, *a, **kw):
        cmd = list(cmd)
        if not mgmt:
            i = cmd.index("-netdev")
            del cmd[i:i + 4]
        cmd += wan.netdev("wan", "52:54:00:00:aa:01") + lan.netdev("lan", "52:54:00:00:aa:02")
        return orig_popen(cmd, *a, **kw)

    harness.subprocess.Popen = popen
    try:
        vm = harness.YesOS(disk, udp_port, kernel=KERNEL)
    finally:
        harness.subprocess.Popen = orig_popen
    return vm, udp_port, vm.wait_for("YesOS [", 240)


def console(vm, line, wait=2):
    m = vm.send(line, wait)
    return vm.since(m)


def is_dns_answer(f):
    return f[:12] == ROUTER_MAC + MODEM_MAC and f[12:14] == b"\x08\x00" and len(f) > 42 and f[23] == 17 and f[34:36] == b"\x00\x35"


def three_port(disk, wan, lan, up):
    vm, udp_port, ok = boot(disk, wan, lan, mgmt=True)
    try:
        out = vm.output()
        check(ok and "[BOOT] Entering YesOS Security" in out and "YesOS Security - BOOT SUMMARY" in out,
              "boots as YesOS Security from its own empty disk")
        check("[BRIDGE] 3 ports: WAN (modem) = port 1, LAN (router) = port 2, NAS on port 0" in out,
              "three NICs: bridge between ports 1 and 2")
        check("NAS SERVICE" not in out and "WEBADMIN" not in out and "[TLS]" not in out, "no NAS, panel or TLS at boot")
        h = console(vm, "help")
        check("Gateway" in h and "DNS filter" in h and "snapshot" not in h and "smb" not in h and "user [" not in h
              and "vault [" not in h and "pkg [" not in h, "help: gateway and DNS commands only (no NAS, vault or packages)")
        check("Unknown command: 'nas status'" in console(vm, "nas status", 1), "the NAS command does not exist")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(struct.pack("<I", 0x59455343) + b"\0" * 300, ("127.0.0.1", udp_port))
        try:
            s.recvfrom(2048)
            answered = True
        except socket.timeout:
            answered = False
        s.close()
        check(not answered, "nothing answers on UDP 31415")
        r = console(vm, "write /vault/secreto.txt texto-que-no-debe-quedar-en-claro")
        check("no vault" in r and "Unknown command: 'vault status'" in console(vm, "vault status", 1),
              "no vault module: writing to /vault is refused and the vault command does not exist")

        # --- forwarding ------------------------------------------------------
        who = eth(b"\xff" * 6, ROUTER_MAC, 0x0806, arp(1, ROUTER_MAC, ROUTER_IP, b"\0" * 6, g.MODEM_IP))
        check(passes(lan, wan, who), "ARP broadcast from the router reaches the modem unchanged")
        rep = eth(ROUTER_MAC, MODEM_MAC, 0x0806, arp(2, MODEM_MAC, g.MODEM_IP, ROUTER_MAC, ROUTER_IP))
        check(passes(wan, lan, rep), "ARP reply from the modem reaches the router")
        check(passes(lan, wan, out_tcp(443)) and passes(wan, lan, in_tcp(40000, 443)), "HTTPS out and its answer forwarded byte for byte")
        check(passes(lan, wan, eth(MODEM_MAC, ROUTER_MAC, 0x88CC, b"\x02\x07\x04" + b"x" * 40)), "non-IP frames (LLDP) pass")
        disc = eth(b"\xff" * 6, ROUTER_MAC, 0x8863, struct.pack(">BBHH", 0x11, 0x09, 0, 4) + b"\x01\x01\0\0")
        check(passes(lan, wan, disc), "PPPoE discovery (PADI) passes")

        # --- built-in groups -------------------------------------------------
        check(blocked(wan, lan, in_tcp(16992)), "Intel AMT 16992 from the Internet blocked")
        check(blocked(lan, wan, v4_frame(MODEM_MAC, ROUTER_MAC, ROUTER_IP, "198.51.100.7", 6, tcp(16993, 51000, 0x12))),
              "AMT answering from port 16993 blocked")
        check(blocked(lan, wan, out_tcp(4433)), "AMT CIRA call home (4433 out) blocked")
        check(passes(wan, lan, in_tcp(4433, 50000)), "4433 from the Internet is not CIRA: passes")
        check(blocked(wan, lan, v4_frame(ROUTER_MAC, MODEM_MAC, "198.51.100.7", ROUTER_IP, 17, udp(40000, 623, b"\x06\0\xff\x06" + b"\0" * 8))),
              "RMCP / ASF (UDP 623) blocked")
        check(blocked(lan, wan, out_tcp(5986)), "DASH / WS-Management 5986 blocked")
        check(blocked(lan, wan, out_tcp(9971)), "AMT remote provisioning 9971 blocked")
        src = "93.184.216.34"
        cases = [
            ("VLAN", lambda p: eth(ROUTER_MAC, MODEM_MAC, 0x8100, struct.pack(">HH", 7, 0x0800) + ipv4(src, ROUTER_IP, 6, p))),
            ("QinQ", lambda p: eth(ROUTER_MAC, MODEM_MAC, 0x88A8, struct.pack(">HHHH", 100, 0x8100, 7, 0x0800) + ipv4(src, ROUTER_IP, 6, p))),
            ("PPPoE", lambda p: eth(ROUTER_MAC, MODEM_MAC, 0x8864, pppoe(0x1234, ipv4(src, ROUTER_IP, 6, p)))),
            ("IPv6", lambda p: eth(ROUTER_MAC, MODEM_MAC, 0x86DD, ipv6("2001:db8::1", "2001:db8:1::2", 6, p))),
            ("IPv6 + extension header", lambda p: eth(ROUTER_MAC, MODEM_MAC, 0x86DD, ipv6("2001:db8::1", "2001:db8:1::2", 6, p, hop_by_hop(6)))),
            ("PPPoE + IPv6", lambda p: eth(ROUTER_MAC, MODEM_MAC, 0x8864, pppoe(9, ipv6("2001:db8::1", "2001:db8:1::2", 6, p), True))),
        ]
        for name, wrap in cases:
            check(passes(wan, lan, wrap(tcp(443, 40000))) and blocked(wan, lan, wrap(tcp(40000, 16992))),
                  f"{name}: normal traffic passes, AMT inside it blocked")

        # --- malformed ------------------------------------------------------
        trunc = eth(ROUTER_MAC, MODEM_MAC, 0x0800, ipv4(src, ROUTER_IP, 6, tcp(443, 40000))[:30])
        check(blocked(wan, lan, trunc), "truncated IPv4 packet dropped")
        bad_ppp = eth(ROUTER_MAC, MODEM_MAC, 0x8864, struct.pack(">BBHH", 0x11, 0, 1, 900) + b"\0\x21" + b"\0" * 20)
        check(blocked(wan, lan, bad_ppp), "PPPoE length beyond the frame dropped")
        rnd = random.Random(11)
        for _ in range(400):
            et = rnd.choice([0x0800, 0x86DD, 0x8864, 0x8100, 0x88A8, 0x0806, rnd.getrandbits(16)])
            f = rnd.choice([MODEM_MAC, ROUTER_MAC, b"\xff" * 6]) + MODEM_MAC + struct.pack(">H", et) + \
                bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 120)))
            rnd.choice([wan, lan]).send(f)
            time.sleep(0.001)
        time.sleep(1)
        check(passes(lan, wan, out_tcp(443, 40001)), "400 random frames later the bridge still forwards")

        # --- console: rules, log, groups ------------------------------------
        console(vm, "fw log clear")
        for _ in range(5):
            blocked(wan, lan, in_tcp(16994, 443, "203.0.113.66"), settle=0.05)
        time.sleep(0.5)
        log = console(vm, "fw log")
        amt = [ln for ln in log.splitlines() if ":16994" in ln]
        check(len(amt) == 1 and "x5" in amt[0] and "203.0.113.66:443" in amt[0] and " in " in amt[0] and "AMT" in amt[0],
              f"fw log: 5 identical attempts in one line ({amt[:1]})")
        r = console(vm, "fw add tcp 25 out any correo saliente")
        check("Regla 1000" in r and blocked(lan, wan, out_tcp(25)) and passes(wan, lan, in_tcp(25, 40000)),
              "rule tcp 25 out: out blocked, in passes")
        console(vm, "fw add udp 1000-2000 both 203.0.113.0/24 red sospechosa")
        f1 = v4_frame(MODEM_MAC, ROUTER_MAC, ROUTER_IP, "203.0.113.9", 17, udp(40000, 1500, b"x"))
        f2 = v4_frame(MODEM_MAC, ROUTER_MAC, ROUTER_IP, "198.51.100.1", 17, udp(40000, 1500, b"x"))
        check(blocked(lan, wan, f1) and passes(lan, wan, f2), "port range + network rule matches only that network")
        console(vm, "fw add tcp 22 in 2001:db8::/32 ssh v6")
        f6 = eth(ROUTER_MAC, MODEM_MAC, 0x86DD, ipv6("2001:db8::99", "2001:db8:1::2", 6, tcp(50000, 22)))
        check(blocked(wan, lan, f6), "IPv6 network rule")
        for bad in ["tcp 0 out any", "icmp 25 out any", "tcp 25 sideways any", "tcp 25 out 300.1.1.1", "tcp 30-20 out any"]:
            check("error" in console(vm, f"fw add {bad}", 1), f"invalid rule refused: '{bad}'")
        rules = console(vm, "fw rules")
        line = next((ln for ln in rules.splitlines() if "correo saliente" in ln), "")
        fields = line.split()
        check(fields[:1] == ["1000"] and len(fields) > 6 and fields[6].isdigit() and int(fields[6]) >= 1,
              f"fw rules lists ids and hit counters ({line.strip()})")
        check("group amt    ON" in rules and "group dohip  off" in rules, "fw rules shows the groups")
        r = console(vm, "fw del 1000")
        check("eliminada" in r and passes(lan, wan, out_tcp(25)), "rule deleted: tcp 25 passes again")
        console(vm, "fw group amt off")
        ok_off = passes(wan, lan, in_tcp(16992))
        console(vm, "fw group amt on")
        check(ok_off and blocked(wan, lan, in_tcp(16992)), "AMT group off and on")
        check(passes(lan, wan, out_tcp(443, 40002, "1.1.1.1")), "encrypted-DNS-by-IP group off by default")
        console(vm, "fw group dohip on")
        check(blocked(lan, wan, out_tcp(443, 40003, "1.1.1.1")) and blocked(lan, wan, out_tcp(853, 40004, src))
              and passes(lan, wan, out_tcp(443, 40005, src)), "dohip on: 443 to 1.1.1.1 and DoT 853 blocked, other HTTPS passes")
        f6 = eth(MODEM_MAC, ROUTER_MAC, 0x86DD, ipv6("2001:db8:1::2", "2606:4700:4700::1111", 6, tcp(40006, 443)))
        check(blocked(lan, wan, f6), "DoH to Cloudflare over IPv6 blocked")

        # --- DNS interception ---------------------------------------------
        console(vm, f"dns upstream 10.0.2.2:{up.port}")
        console(vm, "dns block mine.example")
        qid, q = td.query("example.org")
        check(passes(lan, wan, v4_frame(MODEM_MAC, ROUTER_MAC, ROUTER_IP, "8.8.8.8", 17, udp(53000, 53, q))),
              "interception off: DNS to 8.8.8.8 goes to the modem")
        check("contestará" in console(vm, "fw intercept on"), "DNS interception switched on")
        for name, server, want in (("example.org", "8.8.8.8", ["93.184.216.34"]), ("ads.mine.example", "1.1.1.1", ["0.0.0.0"])):
            qid, q = td.query(name)
            lan.clear()
            wan.clear()
            lan.send(v4_frame(MODEM_MAC, ROUTER_MAC, ROUTER_IP, server, 17, udp(53010, 53, q)))
            ans = lan.wait(is_dns_answer, 6)
            leaked = wan.wait(lambda f: len(f) > 37 and f[36:38] == b"\x00\x35", 0.2)
            d = td.parse(ans[42:]) if ans else None
            ip_ok = ans is not None and socket.inet_ntoa(ans[26:30]) == server and socket.inet_ntoa(ans[30:34]) == ROUTER_IP \
                and struct.unpack(">H", ans[36:38])[0] == 53010 and g.csum(ans[14:34]) == 0
            check(d is not None and d["id"] == qid and td.addr(d) == want and ip_ok and leaked is None,
                  f"{name}: answered {want} as {server} (MACs, IPs, port, IP checksum); the modem never saw it")
        qid, q = td.query("example.org")
        lan.clear()
        lan.send(eth(MODEM_MAC, ROUTER_MAC, 0x8864, pppoe(0x0042, ipv4(ROUTER_IP, "9.9.9.9", 17, udp(53003, 53, q)))))
        ans = lan.wait(lambda f: f[12:14] == b"\x88\x64" and f[:6] == ROUTER_MAC, 6)
        if ans:
            sess, plen = struct.unpack(">HH", ans[16:20])
            d = td.parse(ans[50:])
            check(sess == 0x42 and plen == len(ans) - 20 and ans[20:22] == b"\x00\x21"
                  and socket.inet_ntoa(ans[34:38]) == "9.9.9.9" and td.addr(d) == ["93.184.216.34"],
                  "PPPoE: answer in the same session, correct PPPoE length, from 9.9.9.9")
        else:
            check(False, "PPPoE DNS query answered")
        q6 = eth(MODEM_MAC, ROUTER_MAC, 0x86DD, ipv6("2001:db8:1::2", "2001:4860:4860::8888", 17, udp(53004, 53, td.query("x.org")[1])))
        check(blocked(lan, wan, q6), "IPv6 DNS dropped while interception is on")
        check("DNS intercepted 3" in console(vm, "fw"), "fw status counts the intercepted queries")

        # --- throughput ---------------------------------------------------
        frames = [v4_frame(MODEM_MAC, ROUTER_MAC, ROUTER_IP, src, 17, udp(41000, 9000, struct.pack(">I", i) + b"p" * 200))
                  for i in range(1000)]
        wan.clear()
        t0 = time.time()
        for i, f in enumerate(frames):
            lan.send(f)
            if i % 32 == 31:
                time.sleep(0.004)
        end = time.time() + 10
        n = 0
        while time.time() < end:
            with wan.lock:
                n = sum(1 for f in wan.frames if f[34:36] == struct.pack(">H", 41000))
            if n >= len(frames):
                break
            time.sleep(0.05)
        el = time.time() - t0
        check(n >= 990, f"throughput: {n}/1000 frames forwarded in {el:.1f} s ({n / el:.0f} frames/s)")
        check("Puertos intercambiados" in console(vm, "fw swap on"), "fw swap on (applies after a reboot)")
    finally:
        vm.stop()

    vm, udp_port, ok = boot(disk, wan, lan, mgmt=True)
    try:
        out = vm.output()
        check(ok and "[BRIDGE] ports swapped by configuration: WAN = port 2, LAN = port 1" in out, "after reboot the ports are swapped")
        # the `lan` socket is now the Internet side (the modem's MAC lives there),
        # the `wan` socket the house side (the router's MAC lives there)
        check(passes(lan, wan, v4_frame(ROUTER_MAC, MODEM_MAC, "203.0.113.5", ROUTER_IP, 6, tcp(40000, 4433))),
              "4433 now arrives from the WAN side: not CIRA, passes")
        check(blocked(wan, lan, v4_frame(MODEM_MAC, ROUTER_MAC, ROUTER_IP, "203.0.113.5", 6, tcp(40000, 4433))),
              "and 4433 leaving through the new LAN side is blocked as CIRA")
        rules = console(vm, "fw rules")
        check("red sospechosa" in rules and "ssh v6" in rules and "correo saliente" not in rules and "group dohip  ON" in rules,
              "rules and groups kept across the reboot")
        qid, q = td.query("ads.mine.example")
        wan.clear()
        wan.send(v4_frame(MODEM_MAC, ROUTER_MAC, ROUTER_IP, "1.1.1.1", 17, udp(53011, 53, q)))
        ans = wan.wait(is_dns_answer, 6)
        check(ans is not None and td.addr(td.parse(ans[42:])) == ["0.0.0.0"], "interception and the DNS block list kept too")
        console(vm, "fw swap off")
        check("FATAL" not in vm.output() and "EXCEPTION" not in vm.output(), "no kernel faults")
    finally:
        vm.stop()


def two_port(disk, wan, lan):
    vm, udp_port, ok = boot(disk, wan, lan, mgmt=False)
    try:
        check(ok and "[BRIDGE] 2 ports: WAN (modem) = port 0, LAN (router) = port 1, invisible (no address)" in vm.output(),
              "two NICs: invisible bridge")
        time.sleep(1)
        wan.clear()
        lan.clear()
        for side, peer_mac, peer_ip in ((lan, ROUTER_MAC, ROUTER_IP), (wan, MODEM_MAC, g.MODEM_IP)):
            for target in ("10.0.2.15", "192.168.1.50", "192.168.100.2"):
                side.send(eth(b"\xff" * 6, peer_mac, 0x0806, arp(1, peer_mac, peer_ip, b"\0" * 6, target)))
        time.sleep(6)
        own = [f for s_ in (wan, lan) for f in s_.frames if f[6:12] in OWN_MACS]
        arp_replies = [f for s_ in (wan, lan) for f in s_.frames if f[12:14] == b"\x08\x06" and f[20:22] == b"\x00\x02"]
        check(not own and not arp_replies, f"in 6 s it sent nothing of its own and answered no ARP ({len(own)} frames)")
        check(passes(lan, wan, out_tcp(443)) and blocked(wan, lan, in_tcp(16992)), "invisible, but it forwards and blocks AMT")
    finally:
        vm.stop()


def main():
    if not os.path.exists(KERNEL):
        print(f"{KERNEL} not found: run `make` first")
        sys.exit(2)
    tmp = tempfile.mkdtemp(prefix="yesos_sec_")
    disk = os.path.join(tmp, "security.img")
    with open(os.devnull, "w") as null:
        old = sys.stdout
        sys.stdout = null
        try:
            redsea_injector.format_disk(disk, total_mb=64)
        finally:
            sys.stdout = old
    wan, lan = g.Side("modem"), g.Side("router")
    up = td.Upstream()
    try:
        three_port(disk, wan, lan, up)
        two_port(disk, wan, lan)
        r = redsea_fsck.fsck(disk)
        check(not r["errors"], f"its disk is clean ({r['files']} files)")
        with open(disk, "rb") as f:
            check(b"texto-que-no-debe-quedar-en-claro" not in f.read(), "nothing written to /vault reached the disk")
    finally:
        wan.close()
        lan.close()
        up.close()
        shutil.rmtree(tmp, ignore_errors=True)
    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        sys.exit(1)
    print("All checks passed")


if __name__ == "__main__":
    main()
