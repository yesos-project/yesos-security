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
}

U0 product_boot_summary(U0) {
    kprintf(" [ OK ] SECURITY         : bridge modem <-> router, firewall, console administration only\n");
}

U0 product_poll(U0) {
    dnsblock_poll();
}
