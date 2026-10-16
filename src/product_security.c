// ============================================================================
// YesOS Security - product glue: a transparent bridge between the modem (ONT)
// and the router, with the firewall and optional DNS interception. No web
// panel, no TCP, no file services, no telemetry: administration is on the
// serial console only. With two NICs the bridge is invisible (no address);
// with three, port 0 is a management network used only by the DNS filter to
// reach its upstream (and by the tests).
// ============================================================================

#include "product.h"
#include "kprintf.h"
#include "virtio_net.h"
#include "netcfg.h"
#include "dnsblock.h"
#include "bridge.h"

const char* const PRODUCT_NAME = "YesOS Security";

// Boot banner. Pure ASCII, at most 68 columns. The size is measured here,
// from the linker's symbols (the image's code and read-only data), and the
// wire line says what the bridge found: two NICs, invisible; three, an
// address on the management port 0 only; one, no bridge.
extern U8 _kernel_start[], _text_end[], _rodata_start[], _rodata_sec_end[];

static const char* const s_banner[] = {
    " __   __          ___   ____",
    " \\ \\ / /___  ___ / _ \\ / ___|",
    "  \\ V // _ \\/ __| | | |\\___ \\",
    "   | ||  __/\\__ \\ |_| | ___) |",
    "   |_| \\___||___/\\___/ |____/",
    "  ____                       _  _",
    " / ___|  ___   ___ _   _ _ __(_)| |_ _   _",
    " \\___ \\ / _ \\ / __| | | | '__| || __| | | |",
    "  ___) |  __/| (__| |_| | |  | || |_| |_| |",
    " |____/ \\___| \\___|\\__,_|_|  |_| \\__|\\__, |",
    "                                     |___/",
};

static U0 banner(U0) {
    kprintf("\n");
    for (U32 i = 0; i < sizeof(s_banner) / sizeof(s_banner[0]); i++) kprintf("%s\n", s_banner[i]);
    U64 kib = ((U64)(_text_end - _kernel_start) + (U64)(_rodata_sec_end - _rodata_start) + 512) / 1024;
    kprintf("\n  Invisible bridge firewall  -  RISC-V RV64GCV  -  Machine mode only\n");
    // What the bridge found (bridge_setup ran in product_early_init).
    const char* wire = bridge_is_port(0) && !bridge_owns_stack() ? "no address on the wire"
                     : bridge_is_port(1) ? "an address on port 0 only"
                     : "no bridge: one NIC";
    kprintf("  PMP locked, proven with Z3  -  %s  -  %u KiB\n\n", wire, kib);
}

static Bool dns_udp(const NetUdpDatagram* d) {
    return dnsblock_udp(d->src_ip, d->src_mac, d->src_port, d->dst_port, d->data, d->len);
}

U0 product_early_init(U0) {
    bridge_setup(FALSE);
}

U0 product_init(U0) {
    bridge_load_config();
    dnsblock_init();
    net_register_udp(0, dns_udp);   // upstream answers for intercepted queries
    netcfg_on_change(dnsblock_refresh_upstream);
    banner();
}

U0 product_boot_summary(U0) {
    kprintf(" [ OK ] SECURITY         : bridge modem <-> router, firewall, console administration only\n");
}

U0 product_poll(U0) {
    dnsblock_poll();
}
