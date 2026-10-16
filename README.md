<div align="center">

# YesOS Security

**An invisible bridge firewall on bare-metal RISC-V, between the fibre<br>
modem and the router: with two NICs it has no address and sends nothing of its own.**

<img alt="RISC-V RV64GCV" src="https://img.shields.io/badge/RISC--V-RV64GCV-283272?logo=riscv&logoColor=white">
<img alt="Machine mode only" src="https://img.shields.io/badge/runs%20in-Machine%20mode-4a5568">
<img alt="PMP proven with Z3" src="https://img.shields.io/badge/PMP-proven%20with%20Z3-6b46c1">
<img alt="No floating point" src="https://img.shields.io/badge/floating%20point-none%2C%20checked-2f855a">
<img alt="License MIT" src="https://img.shields.io/badge/license-MIT-2b6cb0">

[Quick start](#quick-start) · [Layouts](#1-layouts) · [Firewall](#3-firewall--srcbridgec-rustsrcfwrs-corerustsrcframesrs) · [Tests](#7-tests) · [Limits](#8-honest-limits) · [YesOS core](https://github.com/yesos-project/yesos-core)

</div>

```text
 __   __          ___   ____
 \ \ / /___  ___ / _ \ / ___|
  \ V // _ \/ __| | | |\___ \
   | ||  __/\__ \ |_| | ___) |
   |_| \___||___/\___/ |____/
  ____                       _  _
 / ___|  ___   ___ _   _ _ __(_)| |_ _   _
 \___ \ / _ \ / __| | | | '__| || __| | | |
  ___) |  __/| (__| |_| | |  | || |_| |_| |
 |____/ \___| \___|\__,_|_|  |_| \__|\__, |
                                     |___/

  Invisible bridge firewall  -  RISC-V RV64GCV  -  Machine mode only
  PMP locked, proven with Z3  -  no address on the wire  -  357 KiB
```

<sub>The console's banner at boot, with two NICs. The size is measured by the running system;
with three NICs the second line says "an address on port 0 only", with one "no bridge: one NIC".</sub>

---

An invisible bridge firewall built on the YesOS core (the `core` git
submodule): Machine mode only, a locked Z3-proven PMP, an integer-only kernel
(no floating point, checked at every build), no Linux, libc or binary blobs.
It contains only the core, the core's DNS engine and the bridge
firewall: no web panel, no TCP, no file services, no vault, no packages
(357 KiB of code). It is administered from the serial console only, a plain
one (no line editor, no font, none of the Desktop's drivers: the build
refuses an image that contains them).

```text
fiber ─► [ONT] ─► [YesOS Security] ─► [router] ─► the house (Wi-Fi and cables)
```

Placed on the cable between the ONT and the router, everything the house sends
to or receives from the Internet crosses it, including the router's own Wi-Fi
clients and the Intel ME / AMD PSP of any PC. With two NICs it has no address:
it answers nothing and sends nothing of its own.

Design choices, a comparison with Linux, seL4, Zephyr and TempleOS, and what is
measured today: see the [yesos-core README](https://github.com/yesos-project/yesos-core#2-design-choices).

## Quick start

Requirements (clang, lld, llvm, QEMU, Rust, Python): see the
[yesos-core README](https://github.com/yesos-project/yesos-core#readme).

```bash
git clone --recurse-submodules https://github.com/yesos-project/yesos-security && cd yesos-security
make prover-setup        # once (Z3, in core/tools/.venv)
make                     # yesos.elf
make run                 # QEMU with the bridge wired to a simulated modem and router (see below)
make test                # tools/test_security.py
```

## 1. Layouts

Chosen by the number of NICs at boot:
- **2 NICs** (the board): port 0 = WAN (ONT side), port 1 = LAN (router side). **Invisible**: no IP, no ARP answers, nothing of its own on the wire.
- **3 NICs** (QEMU and tests): port 0 is a management network, used only by the DNS filter to reach its upstream; ports 1 and 2 are the bridge.
- `fw swap on|off` swaps WAN and LAN; it applies after a reboot.

## 2. Bridge

- It learns where each MAC is (128 entries, 5 min ageing), floods broadcasts and unknown destinations, and does not forward frames whose two ends are on the same side.
- It forwards everything that is not blocked, byte for byte: ARP, LLDP, PPPoE discovery and sessions, IPv4, IPv6.

## 3. Firewall — `src/bridge.c`, `rust/src/fw.rs`, `core/rust/src/frames.rs`

- It parses Ethernet, VLAN and QinQ, PPPoE session frames (the router may do PPPoE over this cable), IPv4, and IPv6 with extension headers, then reads the TCP or UDP ports. Truncated or inconsistent packets are dropped.
- Built-in groups, which can be switched on and off:

  | Group | Blocks | Default |
  |---|---|---|
  | `amt`: Intel AMT / ME | 16992-16995, RMCP 623 / 664, provisioning 9971, both ways | on |
  | `cira`: AMT CIRA | outgoing TCP 4433 (the ME calling a management server) | on |
  | `dash`: DASH / WS-Management | 5985 / 5986 (also WinRM) | on |
  | `dohip`: encrypted DNS by IP | 443 to well-known public resolvers (v4 and v6) and DoT 853 to anywhere | off |

- Owner rules: TCP, UDP or both; a port or range; direction out, in or both; optionally an IPv4 or IPv6 network. Up to 64 rules, with hit counters.
- Blocked flows go to a log in RAM (the last 200). Repeats within 10 s are aggregated.
- Rules and settings are kept in `SYS/FW.CFG` on its own disk.

## 4. DNS interception (off by default)

Outgoing UDP 53 is answered by the core's DNS filter, even when the router or a
device asks 8.8.8.8 or 1.1.1.1.
- The answer looks as if it came from the server that was asked: same MACs, IP and port, inside the same VLAN or PPPoE session.
- While it is on, IPv6 DNS is dropped so that clients fall back to IPv4.
- Its upstream must be reachable from the board. On the cable between the ONT and the router with PPPoE there is no local network to ask, so interception is useful only where one exists (or with a management port).

## 5. Console

```text
fw                     status: ports, forwarded, blocked, DNS intercepted
fw rules               rules with ids and hit counters, and the groups
fw log                 recent blocks (aggregated)       fw log clear
fw add <tcp|udp|any> <port[-port]> <out|in|both> <ip[/nn]|any> [label]
fw del <id>
fw group <amt|cira|dash|dohip> on|off
fw intercept on|off    fw swap on|off
dns                    DNS filter status        dns log   recent queries
dns list add <name>    load SYS/DNSLIST/<name>.txt (copied onto the disk with tools/redsea_injector.py)
dns block|allow <d>    dns upstream <ip>...|auto   (see the core's README)
```

The core's commands (`pmp`, `cell`, `integrity`, `fsck`, `sysinfo`, ...) are in its README.

## 6. Trying it: `make run`

`make run` boots the image with the two bridge ports connected to
`tools/gateway_lab.py`, which runs in the background as the modem (with "the
Internet" behind it) and the router (with the house behind it):
- every couple of seconds the house browses and resolves names, some of them ad domains;
- now and then an Intel AMT probe, an AMT CIRA call home, DASH or RMCP is attempted;
- each event and its outcome (crossed, blocked by YesOS, DNS answered by YesOS) goes to `build/gateway_lab.log`.

It uses its own `yesos_disk.img` (created on first run) and UDP ports
40101-40104 on 127.0.0.1. Try `fw log`, `fw rules`, or `fw intercept on` plus
`dns block doubleclick.net`.

## 7. Tests

`python3 tools/test_security.py` (64 checks) acts as both the modem and the
router, sending and receiving raw Ethernet frames:
- no NAS inside: no NAS commands, no vault (writing to `/vault` is refused and nothing reaches the disk), nothing on UDP 31415;
- forwarding and learning; every built-in group, also inside VLAN, QinQ, PPPoE, IPv6 with extension headers, and IPv6 over PPPoE;
- malformed frames and 400 random frames;
- console rules (ranges, IPv4 and IPv6 networks, invalid rules refused), `fw rules`, `fw log`, groups, the encrypted-DNS-by-IP group;
- DNS interception, plain and inside PPPoE; throughput (about 5,000 frames per second under QEMU);
- persistence and port swapping;
- the two-port layout is invisible and still forwards and blocks.

## 8. Honest limits

- It is tested only under QEMU. The board still needs drivers for its real network ports.
- It filters by port and address; it does not inspect content. An ME that disguised its traffic as normal HTTPS would pass.
- It cannot see traffic between devices inside the house, and behind the router every device has the router's address.
- It does not protect against the ME / PSP's local access (memory, firmware); it only controls what they can send out.
- It does not reassemble fragments; later IPv4 and IPv6 fragments carry no ports and pass.
- DNS over TCP is not intercepted.

## 9. Support YesOS

YesOS is developed in the open and funded by donations. They pay for
development time and for real RISC-V boards, so the missing storage and
network drivers can be written and tested outside the emulator.

[Donate on Liberapay](https://liberapay.com/yesos-project/donate)

## 10. License
MIT. In memory of Terry A. Davis (1969–2018).

YesOS is inspired by his TempleOS (its HolyC became HolyQ here, and the RedSea
filesystem) and is not affiliated with it.
