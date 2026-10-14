#ifndef BRIDGE_H
#define BRIDGE_H

#include "types.h"

// Transparent bridge for the gateway position (modem <-> YesOS <-> router).
//   3 NICs: port 0 keeps the NAS's own stack (management); ports 1 (WAN,
//           modem side) and 2 (LAN, router side) are bridged.
//   2 NICs: ports 0 (WAN) and 1 (LAN) are bridged and the NAS's stack is
//           attached to the bridge (the Orange Pi layout).
//   1 NIC : no bridge.
// Frames crossing are checked by the firewall (rust_core/src/fw.rs);
// outgoing DNS can be intercepted and answered by the DNS filter.

// attach_stack: with 2 NICs, put the system's own IP stack on the bridge
// (NAS on the Orange Pi); FALSE keeps the bridge invisible (Security).
U0   bridge_setup(Bool attach_stack);   // after virtio_net_init: decides the roles
U0   bridge_load_config(U0);    // after the disk is mounted: SYS/FW.CFG
Bool bridge_is_port(U32 port);
Bool bridge_owns_stack(U0);
U0   bridge_input(U32 port, const U8* frame, size_t len);
Bool bridge_output_local(const U8* frame, size_t len);
I32  bridge_action(const char* action, const char* name, const char* value, const char* label,
                   char* msg, size_t msg_max);   // fw_*, bridge_swap
U0   bridge_shell(const char* args);              // "bridge", "fw ..."

#endif // BRIDGE_H
