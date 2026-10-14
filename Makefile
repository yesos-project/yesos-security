# =============================================================================
# YesOS Security - invisible bridge firewall between the ONT and the router
# (the YesOS core is the `core` submodule). Console administration only.
#   make            build yesos.elf (core + DNS filter + bridge firewall)
#   make run        boot it in QEMU with two bridge ports wired to the lab
#                   (tools/gateway_lab.py: a simulated modem and router; what
#                   crosses goes to build/gateway_lab.log)
#   make test       run tools/test_security.py
# Console: fw  fw rules  fw log  fw add ...  dns ...   Exit QEMU: Ctrl-A X
# =============================================================================
PRODUCT = security
CORE_MODULES = dns
PRODUCT_C_SRCS = $(wildcard src/*.c)
DISK_MB = 64

include core/core.mk

# Port 0: management network (only the DNS filter's upstream uses it).
# Ports 1 (WAN) and 2 (LAN): the bridge, wired to the lab over UDP.
QEMU_NET = -netdev user,id=net0 -device virtio-net-pci,netdev=net0,id=nic0
GW_NET = -netdev dgram,id=wan,local.type=inet,local.host=127.0.0.1,local.port=40101,remote.type=inet,remote.host=127.0.0.1,remote.port=40102 -device virtio-net-pci,netdev=wan,mac=52:54:00:00:aa:01 \
         -netdev dgram,id=lan,local.type=inet,local.host=127.0.0.1,local.port=40103,remote.type=inet,remote.host=127.0.0.1,remote.port=40104 -device virtio-net-pci,netdev=lan,mac=52:54:00:00:aa:02

run: $(ELF) yesos_disk.img
	@mkdir -p $(OBJ_DIR)
	@python3 tools/gateway_lab.py --log $(OBJ_DIR)/gateway_lab.log & echo $$! > $(OBJ_DIR)/gateway_lab.pid
	@echo "Lab: modem and router simulated; what crosses the bridge -> $(OBJ_DIR)/gateway_lab.log"
	-qemu-system-riscv64 $(QEMU_CPU) $(QEMU_DISK) $(QEMU_NET) $(GW_NET) -kernel $(ELF) -nographic
	@kill `cat $(OBJ_DIR)/gateway_lab.pid` 2>/dev/null; rm -f $(OBJ_DIR)/gateway_lab.pid

test: $(ELF)
	python3 tools/test_security.py

.PHONY: run test
