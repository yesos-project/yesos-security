//! YesOS gateway - firewall for frames crossing the transparent bridge.
//!
//! The NAS sits between the modem (WAN port) and the router (LAN port). Every
//! frame that crosses is parsed here (Ethernet, up to two VLAN tags, PPPoE
//! session, IPv4 / IPv6 with extension headers, TCP / UDP ports) and checked
//! against built-in groups (Intel AMT / ME, AMT CIRA, DASH / WS-Management,
//! encrypted DNS by IP) and the owner's rules. Truncated IP packets are
//! dropped. Blocked flows go to a log in RAM (repeats are aggregated).
//! Outgoing DNS (UDP 53) can be intercepted and answered by the DNS filter.

use alloc::string::String;
use alloc::vec::Vec;
use core::slice;

use yesos_core::crypto::Locked;
use yesos_core::frames::{parse, Addr, Parsed};

pub const DIR_OUT: u8 = 0; // LAN (router) -> WAN (modem)
pub const DIR_IN: u8 = 1;  // WAN -> LAN

const V_PASS: i32 = 0;
const V_DROP: i32 = 1;
const V_DNS: i32 = 2;

const MAX_RULES: usize = 64;
const LOG_MAX: usize = 200;
const AGGREGATE_MS: u64 = 10_000;

#[derive(Clone, Copy, PartialEq)]
enum Proto {
    Tcp,
    Udp,
    Any,
}

#[derive(Clone, Copy, PartialEq)]
enum Dir {
    Out,
    In,
    Both,
}

#[derive(Clone, Copy, PartialEq)]
enum Net {
    Any,
    V4(u32, u8),
    V6([u8; 16], u8),
}

struct Rule {
    id: u32,
    group: u8, // GROUP_* or USER
    proto: Proto,
    lo: u16,
    hi: u16,
    dir: Dir,
    net: Net,
    label: String,
    hits: u64,
}

const USER: u8 = 255;

struct Group {
    key: &'static str,
    title: &'static str,
    enabled: bool,
}

struct LogEntry {
    last: u64,
    count: u32,
    dir: u8,
    tcp: bool,
    src: Addr,
    dst: Addr,
    sport: u16,
    dport: u16,
    rule: u32,
}

#[derive(Default)]
struct Stats {
    passed_out: u64,
    passed_in: u64,
    dropped: u64,
    malformed: u64,
    intercepted: u64,
    non_ip: u64,
}

struct Fw {
    groups: Vec<Group>,
    rules: Vec<Rule>,
    next_id: u32,
    intercept: bool,
    swap: bool,
    log: Vec<LogEntry>,
    stats: Stats,
    ready: bool,
}

static FW: Locked<Fw> = Locked::new(Fw {
    groups: Vec::new(),
    rules: Vec::new(),
    next_id: 1000,
    intercept: false,
    swap: false,
    log: Vec::new(),
    stats: Stats { passed_out: 0, passed_in: 0, dropped: 0, malformed: 0, intercepted: 0, non_ip: 0 },
    ready: false,
});

const G_AMT: u8 = 0;
const G_CIRA: u8 = 1;
const G_DASH: u8 = 2;
const G_DOHIP: u8 = 3;

/// Well-known public DNS resolvers (DoH on 443 / DoT on 853 to these IPs
/// would bypass the DNS filter).
const DOH_V4: &[[u8; 4]] = &[
    [1, 1, 1, 1], [1, 0, 0, 1], [8, 8, 8, 8], [8, 8, 4, 4], [9, 9, 9, 9], [149, 112, 112, 112],
    [208, 67, 222, 222], [208, 67, 220, 220], [94, 140, 14, 14], [94, 140, 15, 15],
    [45, 90, 28, 0], [45, 90, 30, 0], [76, 76, 2, 0], [76, 76, 10, 0], [185, 228, 168, 9], [194, 242, 2, 2],
];
const DOH_V6: &[[u16; 8]] = &[
    [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111], [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001],
    [0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888], [0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844],
    [0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe], [0x2620, 0x0119, 0x0035, 0, 0, 0, 0, 0x0035],
    [0x2a10, 0x50c0, 0, 0, 0, 0, 0x0ad1, 0x00ff], [0x2a07, 0xa8c0, 0, 0, 0, 0, 0, 0],
];

impl Fw {
    fn setup(&mut self) {
        if self.ready {
            return;
        }
        self.ready = true;
        self.groups = alloc::vec![
            Group { key: "amt", title: "Intel AMT / ME (16992-16995, 623, 664, 9971)", enabled: true },
            Group { key: "cira", title: "Intel AMT CIRA: conexiones salientes a 4433", enabled: true },
            Group { key: "dash", title: "DASH / WS-Management (5985, 5986; también WinRM)", enabled: true },
            Group { key: "dohip", title: "DNS cifrado por IP (DoH/DoT a resolvers públicos, DoT 853)", enabled: false },
        ];
        let mut add = |g: u8, p: Proto, lo: u16, hi: u16, d: Dir, n: Net, l: &str, id: &mut u32| {
            self.rules.push(Rule { id: *id, group: g, proto: p, lo, hi, dir: d, net: n, label: String::from(l), hits: 0 });
            *id += 1;
        };
        let mut id = 1;
        add(G_AMT, Proto::Any, 16992, 16995, Dir::Both, Net::Any, "Intel AMT (web, SOL, IDE-R)", &mut id);
        add(G_AMT, Proto::Any, 623, 623, Dir::Both, Net::Any, "RMCP / ASF (AMT, DASH, IPMI)", &mut id);
        add(G_AMT, Proto::Any, 664, 664, Dir::Both, Net::Any, "RMCP seguro (ASF)", &mut id);
        add(G_AMT, Proto::Tcp, 9971, 9971, Dir::Both, Net::Any, "Aprovisionamiento remoto de AMT", &mut id);
        add(G_CIRA, Proto::Tcp, 4433, 4433, Dir::Out, Net::Any, "AMT CIRA (el ME llama a un servidor)", &mut id);
        add(G_DASH, Proto::Tcp, 5985, 5986, Dir::Both, Net::Any, "DASH / WS-Management", &mut id);
        add(G_DOHIP, Proto::Tcp, 853, 853, Dir::Out, Net::Any, "DNS sobre TLS (DoT)", &mut id);
        for ip in DOH_V4 {
            let prefix = if ip[3] == 0 { 24 } else { 32 };
            add(G_DOHIP, Proto::Any, 443, 443, Dir::Out, Net::V4(u32::from_be_bytes(*ip), prefix), "DoH a un resolver público", &mut id);
        }
        for w in DOH_V6 {
            let mut b = [0u8; 16];
            for (i, x) in w.iter().enumerate() {
                b[2 * i..2 * i + 2].copy_from_slice(&x.to_be_bytes());
            }
            add(G_DOHIP, Proto::Any, 443, 443, Dir::Out, Net::V6(b, 128), "DoH a un resolver público", &mut id);
        }
    }

    fn group_on(&self, g: u8) -> bool {
        g == USER || self.groups.get(g as usize).map(|x| x.enabled).unwrap_or(false)
    }

    fn matches(r: &Rule, tcp: bool, port: u16, dir: u8, remote: Addr) -> bool {
        let proto_ok = match r.proto { Proto::Any => true, Proto::Tcp => tcp, Proto::Udp => !tcp };
        let dir_ok = match r.dir { Dir::Both => true, Dir::Out => dir == DIR_OUT, Dir::In => dir == DIR_IN };
        proto_ok && dir_ok && port >= r.lo && port <= r.hi && net_contains(r.net, remote)
    }

    fn log(&mut self, now: u64, dir: u8, tcp: bool, src: Addr, dst: Addr, sport: u16, dport: u16, rule: u32) {
        if let Some(e) = self.log.iter_mut().rev().take(8).find(|e| {
            e.dir == dir && e.tcp == tcp && e.src == src && e.dst == dst && e.dport == dport && e.rule == rule
                && now.saturating_sub(e.last) < AGGREGATE_MS
        }) {
            e.count = e.count.saturating_add(1);
            e.last = now;
            e.sport = sport;
            return;
        }
        if self.log.len() >= LOG_MAX {
            self.log.remove(0);
        }
        self.log.push(LogEntry { last: now, count: 1, dir, tcp, src, dst, sport, dport, rule });
    }
}

fn net_contains(n: Net, a: Addr) -> bool {
    match (n, a) {
        (Net::Any, _) => true,
        (Net::V4(net, p), Addr::V4(ip)) => {
            let mask = if p == 0 { 0 } else { u32::MAX << (32 - p as u32) };
            (ip & mask) == (net & mask)
        }
        (Net::V6(net, p), Addr::V6(ip)) => {
            let full = (p / 8) as usize;
            if ip[..full] != net[..full] {
                return false;
            }
            let rem = p % 8;
            rem == 0 || (ip[full] >> (8 - rem)) == (net[full] >> (8 - rem))
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Inspection
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn yc_fw_inspect(frame: *const u8, len: usize, dir: u8, now_ms: u64) -> i32 {
    if frame.is_null() {
        return V_DROP;
    }
    let f = unsafe { slice::from_raw_parts(frame, len) };
    FW.with(|fw| {
        fw.setup();
        let (tcp, src, dst, sport, dport, ports, v6) = match parse(f) {
            Parsed::NotIp => {
                fw.stats.non_ip += 1;
                return V_PASS;
            }
            Parsed::Bad => {
                fw.stats.malformed += 1;
                fw.stats.dropped += 1;
                return V_DROP;
            }
            Parsed::OtherProto => {
                if dir == DIR_OUT { fw.stats.passed_out += 1 } else { fw.stats.passed_in += 1 }
                return V_PASS;
            }
            Parsed::Ip { tcp, src, dst, sport, dport, ports, l2, .. } => (tcp, src, dst, sport, dport, ports, l2.v6),
        };
        if ports {
            if fw.intercept && dir == DIR_OUT && !tcp && dport == 53 {
                if !v6 {
                    fw.stats.intercepted += 1;
                    return V_DNS;
                }
                // IPv6 DNS would bypass the filter: drop it, clients fall back to IPv4.
                fw.stats.dropped += 1;
                fw.log(now_ms, dir, tcp, src, dst, sport, dport, 0);
                return V_DROP;
            }
            let remote = if dir == DIR_OUT { dst } else { src };
            let mut hit: Option<usize> = None;
            for (i, r) in fw.rules.iter().enumerate() {
                if !fw.group_on(r.group) {
                    continue;
                }
                // a rule matches the service port on either side of the flow
                let port_hit = Fw::matches(r, tcp, dport, dir, remote)
                    || (r.dir == Dir::Both && Fw::matches(r, tcp, sport, dir, remote));
                if port_hit {
                    hit = Some(i);
                    break;
                }
            }
            if let Some(i) = hit {
                fw.rules[i].hits += 1;
                let id = fw.rules[i].id;
                fw.stats.dropped += 1;
                fw.log(now_ms, dir, tcp, src, dst, sport, dport, id);
                return V_DROP;
            }
        }
        if dir == DIR_OUT { fw.stats.passed_out += 1 } else { fw.stats.passed_in += 1 }
        V_PASS
    })
}

/// WAN and LAN ports swapped by the owner (applies at boot).
#[no_mangle]
pub extern "C" fn yc_fw_swapped() -> bool {
    FW.with(|fw| fw.swap)
}

/// DNS interception on/off (read by the bridge before calling the DNS filter).
#[no_mangle]
pub extern "C" fn yc_fw_intercept_enabled() -> bool {
    FW.with(|fw| fw.intercept)
}

// ---------------------------------------------------------------------------
// Configuration, actions, JSON
// ---------------------------------------------------------------------------

fn parse_ports(s: &str) -> Option<(u16, u16)> {
    let (a, b) = match s.split_once('-') {
        Some((a, b)) => (a, b),
        None => (s, s),
    };
    let lo: u16 = a.parse().ok()?;
    let hi: u16 = b.parse().ok()?;
    if lo == 0 || hi < lo { None } else { Some((lo, hi)) }
}

fn parse_net(s: &str) -> Option<Net> {
    if s == "any" || s == "*" {
        return Some(Net::Any);
    }
    let (ip, prefix) = match s.split_once('/') {
        Some((i, p)) => (i, Some(p.parse::<u8>().ok()?)),
        None => (s, None),
    };
    if ip.contains(':') {
        let a = parse_v6_addr(ip)?;
        let p = prefix.unwrap_or(128);
        if p > 128 { None } else { Some(Net::V6(a, p)) }
    } else {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        let mut v = 0u32;
        for x in parts {
            let n: u8 = x.parse().ok()?;
            v = (v << 8) | n as u32;
        }
        let p = prefix.unwrap_or(32);
        if p > 32 { None } else { Some(Net::V4(v, p)) }
    }
}

fn parse_v6_addr(s: &str) -> Option<[u8; 16]> {
    let (head, tail) = match s.split_once("::") {
        Some((h, t)) => (h, Some(t)),
        None => (s, None),
    };
    let words = |x: &str| -> Option<Vec<u16>> {
        if x.is_empty() { return Some(Vec::new()); }
        x.split(':').map(|w| if w.len() <= 4 { u16::from_str_radix(w, 16).ok() } else { None }).collect()
    };
    let h = words(head)?;
    let t = match tail { Some(t) => words(t)?, None => Vec::new() };
    if tail.is_none() && h.len() != 8 || h.len() + t.len() > 8 || (tail.is_some() && h.len() + t.len() == 8) {
        return None;
    }
    let mut w = [0u16; 8];
    w[..h.len()].copy_from_slice(&h);
    w[8 - t.len()..].copy_from_slice(&t);
    let mut b = [0u8; 16];
    for (i, x) in w.iter().enumerate() {
        b[2 * i..2 * i + 2].copy_from_slice(&x.to_be_bytes());
    }
    Some(b)
}

fn fmt_net(n: Net) -> String {
    match n {
        Net::Any => String::from("any"),
        Net::V4(ip, p) => {
            let mut s = fmt_addr(Addr::V4(ip));
            if p != 32 { s.push_str(&alloc::format!("/{}", p)); }
            s
        }
        Net::V6(ip, p) => {
            let mut s = fmt_addr(Addr::V6(ip));
            if p != 128 { s.push_str(&alloc::format!("/{}", p)); }
            s
        }
    }
}

pub fn fmt_addr(a: Addr) -> String {
    match a {
        Addr::V4(ip) => alloc::format!("{}.{}.{}.{}", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255),
        Addr::V6(b) => {
            let w: Vec<u16> = (0..8).map(|i| u16::from_be_bytes([b[2 * i], b[2 * i + 1]])).collect();
            // compress the longest run of zero words
            let (mut best, mut best_len, mut i) = (8, 0, 0);
            while i < 8 {
                if w[i] == 0 {
                    let s = i;
                    while i < 8 && w[i] == 0 { i += 1; }
                    if i - s > best_len && i - s > 1 { best = s; best_len = i - s; }
                } else {
                    i += 1;
                }
            }
            let part = |r: &[u16]| r.iter().map(|x| alloc::format!("{:x}", x)).collect::<Vec<_>>().join(":");
            if best_len == 0 {
                part(&w)
            } else {
                alloc::format!("{}::{}", part(&w[..best]), part(&w[best + best_len..]))
            }
        }
    }
}

fn proto_str(p: Proto) -> &'static str {
    match p { Proto::Tcp => "tcp", Proto::Udp => "udp", Proto::Any => "any" }
}

fn dir_str(d: Dir) -> &'static str {
    match d { Dir::Out => "out", Dir::In => "in", Dir::Both => "both" }
}

/// "proto ports dir net" (+ label) -> rule fields.
fn parse_rule(spec: &str, label: &str) -> Result<(Proto, u16, u16, Dir, Net, String), String> {
    let t: Vec<&str> = spec.split_whitespace().collect();
    if t.len() < 3 || t.len() > 4 {
        return Err(String::from("Formato: <tcp|udp|any> <puerto o inicio-fin> <out|in|both> [IP, red/prefijo o any]"));
    }
    let proto = match t[0] { "tcp" => Proto::Tcp, "udp" => Proto::Udp, "any" => Proto::Any,
                             _ => return Err(String::from("Protocolo: tcp, udp o any.")) };
    let (lo, hi) = parse_ports(t[1]).ok_or_else(|| String::from("Puertos: un número 1-65535 o un rango inicio-fin."))?;
    let dir = match t[2] { "out" => Dir::Out, "in" => Dir::In, "both" => Dir::Both,
                           _ => return Err(String::from("Dirección: out (hacia Internet), in (desde Internet) o both.")) };
    let net = parse_net(t.get(3).copied().unwrap_or("any")).ok_or_else(|| String::from("IP o red no válida (ejemplo: 203.0.113.0/24)."))?;
    let label: String = label.chars().filter(|c| !c.is_control()).take(48).collect();
    Ok((proto, lo, hi, dir, net, label))
}

impl Fw {
    fn config_text(&self) -> String {
        let mut o = String::from("# YesOS gateway firewall\n");
        o.push_str(if self.intercept { "intercept 1\n" } else { "intercept 0\n" });
        o.push_str(if self.swap { "swap 1\n" } else { "swap 0\n" });
        for g in &self.groups {
            o.push_str(&alloc::format!("group {} {}\n", g.key, if g.enabled { 1 } else { 0 }));
        }
        for r in self.rules.iter().filter(|r| r.group == USER) {
            o.push_str(&alloc::format!("rule {} {} {}-{} {} {} {}\n", r.id, proto_str(r.proto), r.lo, r.hi,
                                       dir_str(r.dir), fmt_net(r.net), r.label));
        }
        o
    }

    fn config_load(&mut self, text: &str) {
        self.setup();
        self.rules.retain(|r| r.group != USER);
        for line in text.lines() {
            let mut it = line.splitn(2, ' ');
            match (it.next(), it.next()) {
                (Some("intercept"), Some(v)) => self.intercept = v.trim() == "1",
                (Some("swap"), Some(v)) => self.swap = v.trim() == "1",
                (Some("group"), Some(v)) => {
                    let mut p = v.split_whitespace();
                    if let (Some(k), Some(on)) = (p.next(), p.next()) {
                        if let Some(g) = self.groups.iter_mut().find(|g| g.key == k) {
                            g.enabled = on == "1";
                        }
                    }
                }
                (Some("rule"), Some(v)) => {
                    let p: Vec<&str> = v.splitn(6, ' ').collect();
                    if p.len() >= 5 && self.rules.iter().filter(|r| r.group == USER).count() < MAX_RULES {
                        let id: u32 = p[0].parse().unwrap_or(0);
                        let spec = alloc::format!("{} {} {} {}", p[1], p[2], p[3], p[4]);
                        if let (true, Ok((proto, lo, hi, dir, net, label))) = (id >= 1000, parse_rule(&spec, p.get(5).copied().unwrap_or(""))) {
                            self.rules.push(Rule { id, group: USER, proto, lo, hi, dir, net, label, hits: 0 });
                            self.next_id = self.next_id.max(id + 1);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn action(&mut self, action: &str, name: &str, value: &str, label: &str) -> Result<String, (i32, String)> {
        self.setup();
        let on = matches!(value, "1" | "on" | "true");
        let off = matches!(value, "0" | "off" | "false");
        match action {
            "fw_intercept" if on || off => {
                self.intercept = on;
                Ok(String::from(if on { "Las consultas DNS que salen a Internet las contestará el filtro DNS del NAS." }
                                else { "Intercepción de DNS desactivada." }))
            }
            "bridge_swap" if on || off => {
                self.swap = on;
                Ok(String::from("Puertos intercambiados: el cambio se aplica al reiniciar."))
            }
            "fw_group" if on || off => match self.groups.iter_mut().find(|g| g.key == name) {
                Some(g) => {
                    g.enabled = on;
                    Ok(alloc::format!("{}: {}.", g.title, if on { "bloqueado" } else { "permitido" }))
                }
                None => Err((404, String::from("No existe ese grupo."))),
            },
            "fw_rule_add" => {
                if self.rules.iter().filter(|r| r.group == USER).count() >= MAX_RULES {
                    return Err((409, alloc::format!("Máximo {} reglas propias.", MAX_RULES)));
                }
                let (proto, lo, hi, dir, net, label) = parse_rule(value, label).map_err(|e| (400, e))?;
                let id = self.next_id;
                self.next_id += 1;
                self.rules.push(Rule { id, group: USER, proto, lo, hi, dir, net, label, hits: 0 });
                Ok(alloc::format!("Regla {} añadida: bloquear {} {} {} {}.", id, proto_str(proto),
                                  if lo == hi { alloc::format!("{}", lo) } else { alloc::format!("{}-{}", lo, hi) },
                                  match dir { Dir::Out => "hacia Internet", Dir::In => "desde Internet", Dir::Both => "en ambos sentidos" },
                                  if net == Net::Any { String::from("a cualquier dirección") } else { alloc::format!("para {}", fmt_net(net)) }))
            }
            "fw_rule_del" => {
                let id: u32 = name.parse().unwrap_or(0);
                match self.rules.iter().position(|r| r.id == id && r.group == USER) {
                    Some(i) => {
                        self.rules.remove(i);
                        Ok(alloc::format!("Regla {} eliminada.", id))
                    }
                    None => Err((404, String::from("No existe esa regla propia."))),
                }
            }
            "fw_log" if value == "clear" => {
                self.log.clear();
                Ok(String::from("Registro del cortafuegos borrado."))
            }
            _ => Err((400, String::from("Acción o valor no válido."))),
        }
    }
}

// ---------------------------------------------------------------------------
// C interface (kernel/bridge.c)
// ---------------------------------------------------------------------------

unsafe fn cstr<'a>(p: *const u8) -> &'a str {
    if p.is_null() {
        return "";
    }
    let mut n = 0;
    while *p.add(n) != 0 && n < 4096 {
        n += 1;
    }
    core::str::from_utf8(slice::from_raw_parts(p, n)).unwrap_or("")
}

fn copy_out(src: &[u8], out: *mut u8, max: usize) -> i32 {
    if out.is_null() || src.len() + 1 > max {
        return -2;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), out, src.len());
        *out.add(src.len()) = 0;
    }
    src.len() as i32
}

#[no_mangle]
pub extern "C" fn yc_fw_config_load(text: *const u8, len: usize) {
    let t = if text.is_null() { "" } else { core::str::from_utf8(unsafe { slice::from_raw_parts(text, len) }).unwrap_or("") };
    FW.with(|fw| fw.config_load(t));
}

#[no_mangle]
pub extern "C" fn yc_fw_config_text(out: *mut u8, max: usize) -> i32 {
    let t = FW.with(|fw| { fw.setup(); fw.config_text() });
    copy_out(t.as_bytes(), out, max)
}

#[no_mangle]
pub extern "C" fn yc_fw_action(action: *const u8, name: *const u8, value: *const u8, label: *const u8,
                               msg: *mut u8, max: usize) -> i32 {
    let (a, n, v, l) = unsafe { (cstr(action), cstr(name), cstr(value), cstr(label)) };
    let (code, text) = match FW.with(|fw| fw.action(a, n.trim(), v.trim(), l.trim())) {
        Ok(t) => (200, t),
        Err((c, t)) => (c, t),
    };
    let mut cut = text.len().min(max.saturating_sub(1));
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    copy_out(&text.as_bytes()[..cut], msg, max);
    code
}

/// Console listings: what 0 = rules (with hit counters), 1 = recent blocks.
#[no_mangle]
pub extern "C" fn yc_fw_text(what: u32, out: *mut u8, max: usize, now_ms: u64) -> i32 {
    let t = FW.with(|fw| {
        fw.setup();
        let mut o = String::new();
        if what == 0 {
            o.push_str("  id    group  proto  ports        dir   remote                 hits  label\n");
            for r in &fw.rules {
                if r.group != USER && r.group != G_AMT && r.group != G_CIRA && r.group != G_DASH {
                    continue;
                }
                let g = if r.group == USER { "user" } else { fw.groups[r.group as usize].key };
                let on = fw.group_on(r.group);
                let ports = if r.lo == r.hi { alloc::format!("{}", r.lo) } else { alloc::format!("{}-{}", r.lo, r.hi) };
                o.push_str(&alloc::format!("  {:<5} {:<6} {:<6} {:<12} {:<5} {:<22} {:>5}  {}{}\n", r.id, g, proto_str(r.proto), ports,
                                           dir_str(r.dir), fmt_net(r.net), r.hits, r.label, if on { "" } else { " (group off)" }));
            }
            for g in &fw.groups {
                o.push_str(&alloc::format!("  group {:<6} {}  {}\n", g.key, if g.enabled { "ON " } else { "off" }, g.title));
            }
        } else {
            if fw.log.is_empty() {
                o.push_str("  nothing blocked yet\n");
            }
            for e in fw.log.iter().rev() {
                let label = if e.rule == 0 { String::from("DNS over IPv6 (interception on)") }
                            else { fw.rules.iter().find(|r| r.id == e.rule).map(|r| r.label.clone()).unwrap_or_default() };
                o.push_str(&alloc::format!("  {:>5}s ago  {:<3} {} {}:{} -> {}:{}  x{}  {}\n",
                    now_ms.saturating_sub(e.last) / 1000, if e.dir == DIR_OUT { "out" } else { "in" },
                    if e.tcp { "tcp" } else { "udp" }, fmt_addr(e.src), e.sport, fmt_addr(e.dst), e.dport, e.count, label));
            }
        }
        o
    });
    copy_out(t.as_bytes(), out, max)
}
