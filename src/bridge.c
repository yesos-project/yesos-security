// ============================================================================
// YesOS NAS - transparent bridge for the gateway position (see bridge.h)
// ============================================================================

#include "bridge.h"
#include "shell.h"
#include "kprintf.h"
#include "memory.h"
#include "redsea_eml.h"
#include "timer.h"
#include "virtio_net.h"

I32  yc_fw_inspect(const U8* frame, size_t len, U8 dir, U64 now_ms);
Bool yc_fw_intercept_enabled(U0);
Bool yc_fw_swapped(U0);
U0   yc_fw_config_load(const U8* text, size_t len);
I32  yc_fw_config_text(char* out, size_t max);
I32  yc_fw_action(const char* action, const char* name, const char* value, const char* label, char* msg, size_t max);
I32  yc_fw_text(U32 what, char* out, size_t max, U64 now_ms);
I32  yc_dns_intercept(U32 port, const U8* frame, size_t len, U64 now_ms);

#define FW_CFG       "SYS/FW.CFG"
#define FDB_MAX      128
#define FDB_AGE_MS   (5 * 60 * 1000)
#define DIR_OUT      0
#define DIR_IN       1

typedef struct {
    U8  mac[6];
    U8  port;
    U64 seen;
} FdbEntry;

typedef struct {
    Bool active;
    Bool stack_attached;
    U32  wan, lan;
    U64  fwd_out, fwd_in, flooded, local_rx, local_tx, same_segment, fw_dropped, dns_intercepted;
} BridgeState;

static BridgeState g_br;
static FdbEntry    g_fdb[FDB_MAX];

static Bool mac_eq(const U8* a, const U8* b) {
    return MemCmp(a, b, 6) == 0;
}

static U0 fdb_learn(const U8* mac, U32 port, U64 now) {
    if (mac[0] & 1) return;                       // never learn group addresses
    U32 slot = 0;
    for (U32 i = 0; i < FDB_MAX; i++) {
        if (g_fdb[i].seen && mac_eq(g_fdb[i].mac, mac)) { slot = i; break; }
        if (g_fdb[i].seen < g_fdb[slot].seen) slot = i;   // oldest or empty
    }
    MemCpy(g_fdb[slot].mac, mac, 6);
    g_fdb[slot].port = (U8)port;
    g_fdb[slot].seen = now + 1;
}

// Port where `mac` was last seen, or -1 (unknown, aged out, or group address).
static I32 fdb_lookup(const U8* mac, U64 now) {
    if (mac[0] & 1) return -1;
    for (U32 i = 0; i < FDB_MAX; i++) {
        if (g_fdb[i].seen && mac_eq(g_fdb[i].mac, mac)) {
            return now - g_fdb[i].seen < FDB_AGE_MS ? (I32)g_fdb[i].port : -1;
        }
    }
    return -1;
}

static Bool bridge_shell_run(const char* cmd);
static U0 bridge_shell_help(U0);

U0 bridge_setup(Bool attach_stack) {
    MemSet(&g_br, 0, sizeof(g_br));
    MemSet(g_fdb, 0, sizeof(g_fdb));
    U32 n = net_port_count();
    if (n >= 3) {
        g_br.active = TRUE;
        g_br.wan = 1;
        g_br.lan = 2;
    } else if (n == 2) {
        g_br.active = TRUE;
        g_br.stack_attached = attach_stack;
        g_br.wan = 0;
        g_br.lan = 1;
    }
    if (g_br.active) {
        kprintf("[BRIDGE] %u ports: WAN (modem) = port %u, LAN (router) = port %u%s\n", n, g_br.wan, g_br.lan,
                g_br.stack_attached ? ", NAS attached to the bridge" : (n == 2 ? ", invisible (no address)" : ", NAS on port 0"));
        static const NetBridgeOps ops = { bridge_is_port, bridge_owns_stack, bridge_input, bridge_output_local };
        net_set_bridge(&ops);
    }
    static const ShellExtension ext = { bridge_shell_run, bridge_shell_help, NULL, NULL };
    shell_register(&ext);
}

static Bool save_fw(U0) {
    static char buf[16 * 1024];
    I32 n = yc_fw_config_text(buf, sizeof(buf));
    return n >= 0 && redsea_eml_write_file(FW_CFG, buf, (size_t)n, 0);
}

U0 bridge_load_config(U0) {
    size_t size = 0;
    U8* cfg = redsea_eml_read_file(FW_CFG, &size);
    if (cfg) {
        yc_fw_config_load(cfg, size);
        Free(cfg);
    }
    if (g_br.active && yc_fw_swapped()) {
        U32 t = g_br.wan; g_br.wan = g_br.lan; g_br.lan = t;
        kprintf("[BRIDGE] ports swapped by configuration: WAN = port %u, LAN = port %u\n", g_br.wan, g_br.lan);
    }
    if (g_br.active) {
        kprintf("[BRIDGE] firewall ready (Intel AMT, CIRA, DASH blocked by default)%s\n",
                yc_fw_intercept_enabled() ? "; DNS interception ON" : "");
    }
}

Bool bridge_is_port(U32 port) {
    return g_br.active && (port == g_br.wan || port == g_br.lan);
}

Bool bridge_owns_stack(U0) {
    return g_br.active && g_br.stack_attached;
}

U0 bridge_input(U32 port, const U8* frame, size_t len) {
    if (len < 14) return;
    U64 now = timer_get_uptime_ms();
    const U8* dst = frame;
    const U8* src = frame + 6;
    const U8* mine = net_port_mac(0);
    if (g_br.stack_attached && mac_eq(src, mine)) return;   // our own frame looped back
    fdb_learn(src, port, now);

    Bool group = (dst[0] & 1) != 0;
    Bool for_me = g_br.stack_attached && mac_eq(dst, mine);
    if (g_br.stack_attached && (for_me || group)) {
        g_br.local_rx++;
        net_stack_input(frame, len);
        if (for_me) return;
    }

    U32 out = port == g_br.wan ? g_br.lan : g_br.wan;
    I32 known = fdb_lookup(dst, now);
    if (known == (I32)port) {        // both ends on the same side: not ours to forward
        g_br.same_segment++;
        return;
    }
    U8 dir = port == g_br.lan ? DIR_OUT : DIR_IN;
    I32 v = yc_fw_inspect(frame, len, dir, now);
    if (v == 1) {
        g_br.fw_dropped++;
        return;
    }
    if (v == 2) {
        if (yc_dns_intercept(port, frame, len, now)) {
            g_br.dns_intercepted++;
            return;
        }
    }
    if (known < 0) g_br.flooded++;
    if (dir == DIR_OUT) g_br.fwd_out++; else g_br.fwd_in++;
    net_port_send(out, frame, len);
}

// Frames from the NAS's own stack when it is attached to the bridge.
Bool bridge_output_local(const U8* frame, size_t len) {
    if (len < 14) return FALSE;
    g_br.local_tx++;
    I32 p = fdb_lookup(frame, timer_get_uptime_ms());
    if (p >= 0) return net_port_send((U32)p, frame, len);
    Bool a = net_port_send(g_br.wan, frame, len);
    Bool b = net_port_send(g_br.lan, frame, len);
    return a || b;
}

I32 bridge_action(const char* action, const char* name, const char* value, const char* label,
                  char* msg, size_t msg_max) {
    I32 st = yc_fw_action(action, name, value, label, msg, msg_max);
    if (st == 200 && !save_fw()) {
        ksnprintf(msg, msg_max, "Cambio aplicado, pero no se pudo guardar en el disco.");
        return 507;
    }
    return st;
}

static Bool starts(const char* p, const char* s) {
    while (*p) if (*p++ != *s++) return FALSE;
    return TRUE;
}

U0 bridge_shell(const char* args) {
    while (*args == ' ') args++;
    char msg[256];
    msg[0] = '\0';
    I32 st;
    if (*args == '\0' || StrCmp(args, "status") == 0) {
        if (!g_br.active) {
            kprintf("[BRIDGE] inactive: %u network port(s); the gateway needs 2 (or 3 with a management port).\n", net_port_count());
            return;
        }
        kprintf("[BRIDGE] WAN port %u, LAN port %u%s | out %u in %u flooded %u | fw dropped %u | DNS intercepted %u | local rx %u tx %u\n",
                g_br.wan, g_br.lan, g_br.stack_attached ? " (NAS attached)" : "", g_br.fwd_out, g_br.fwd_in, g_br.flooded,
                g_br.fw_dropped, g_br.dns_intercepted, g_br.local_rx, g_br.local_tx);
        return;
    }
    if (StrCmp(args, "rules") == 0 || StrCmp(args, "log") == 0) {
        static char text[32 * 1024];
        if (yc_fw_text(args[0] == 'r' ? 0 : 1, text, sizeof(text), timer_get_uptime_ms()) >= 0) kprintf("%s", text);
        return;
    }
    if (starts("log clear", args)) st = bridge_action("fw_log", "", "clear", "", msg, sizeof(msg));
    else if (starts("intercept ", args)) st = bridge_action("fw_intercept", "", args + 10, "", msg, sizeof(msg));
    else if (starts("swap ", args)) st = bridge_action("bridge_swap", "", args + 5, "", msg, sizeof(msg));
    else if (starts("group ", args)) {
        char name[16] = {0};
        const char* p = args + 6;
        U32 i = 0;
        while (*p && *p != ' ' && i < sizeof(name) - 1) name[i++] = *p++;
        while (*p == ' ') p++;
        st = bridge_action("fw_group", name, p, "", msg, sizeof(msg));
    } else if (starts("del ", args)) {
        st = bridge_action("fw_rule_del", args + 4, "", "", msg, sizeof(msg));
    } else if (starts("add ", args)) {
        // fw add <proto> <ports> <dir> <net> [label...]
        char spec[96] = {0};
        const char* p = args + 4;
        U32 words = 0, i = 0;
        while (*p && words < 4 && i < sizeof(spec) - 1) {
            if (*p == ' ') { while (*p == ' ') p++; words++; if (words < 4) spec[i++] = ' '; continue; }
            spec[i++] = *p++;
        }
        while (*p == ' ') p++;
        st = bridge_action("fw_rule_add", "", spec, p, msg, sizeof(msg));
    } else {
        kprintf("usage: fw [status | rules | log | add <tcp|udp|any> <port[-port]> <out|in|both> <ip[/nn]|any> [label] | del <id> |\n"
                "           group <amt|cira|dash|dohip> on|off | intercept on|off | swap on|off | log clear]\n");
        return;
    }
    kprintf("[FW] %s%s\n", st == 200 ? "" : "error: ", msg);
}

static Bool bridge_shell_run(const char* cmd) {
    if (StrCmp(cmd, "bridge") == 0 || StrCmp(cmd, "fw") == 0) bridge_shell("");
    else if (shell_is_prefix("fw ", cmd)) bridge_shell(cmd + 3);
    else return FALSE;
    return TRUE;
}

static U0 bridge_shell_help(U0) {
    kprintf("  Gateway (bridge between the modem and the router)\n");
    kprintf("    fw  fw rules  fw log  fw add <tcp|udp|any> <port[-port]> <out|in|both> <ip[/nn]|any> [label]  fw del <id>\n");
    kprintf("    fw group <amt|cira|dash|dohip> on|off  fw intercept on|off  fw swap on|off  fw log clear\n");
}
