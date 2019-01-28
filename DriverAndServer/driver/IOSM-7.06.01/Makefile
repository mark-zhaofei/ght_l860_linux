#
# Copyright (C) 2018 Intel Corporation
#
# SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
#

obj-m := imc_ipc.o

# compilation flags
ccflags-y += -O2 -Wno-pointer-to-int-cast
ccflags-y += -DIPC_NETIF_RX_NI

ccflags-y += -I$(PWD)
ccflags-y += $(CCFLAGS_ADD)

# Compiler defense flags
ccflags-y += -fstack-protector -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security
ldflags-y += -z noexecstack -z relro -z now

# Fixes the error message seen "module verification failed: signature and/or
# required key missing - tainting kernel"
CONFIG_MODULE_SIG=n
CONFIG_MODULE_SIG_FORCE=n
KERNEL_VERSION=$(shell uname -r)
KDIR := /lib/modules/$(KERNEL_VERSION)/build

# Objects for module source
imc_ipc-objs = $(addsuffix .o,$(basename $(imc_ipc-src)))

all:
	@echo ">>> start building release IMC IPC driver <<<"
	@echo $(VERSION)
	@$(MAKE) -C $(KDIR) M=$$PWD CCFLAGS_ADD="-DIPC_EXTERNAL_BUILD"
	@echo ">>> end building release IMC IPC driver <<<\n"

clean:
	@rm -fr .built-in.o.cmd *.o .imc_ipc* modules.order *~
	@rm -fr Module.symvers imc_ipc.mod.c modules.order .tmp_versions .coverity
	@rm -fr imc_ipc.ko



# IOSM IPC Source files
imc_ipc-src =  \
	 imc_ipc_completion.c \
	 imc_ipc_tasklet.c \
	 imc_ipc_imem.c \
	 imc_ipc_mmio.c \
	 imc_ipc_hrtimer.c \
	 imc_ipc_sio.c \
	 imc_ipc_wwan.c \
	 imc_ipc_netlink.c \
	 imc_ipc_uevent.c \
	 imc_ipc_parc.c \
	 imc_ipc_pm.c \
	 imc_ipc_util.c \
	 imc_ipc_pcie.c \
	 imc_ipc_rtpm.c \
	 imc_ipc_params.c \
	 imc_ipc_chnl_cfg.c \
	 imc_ipc_rtpm.c \
	 imc_ipc_protocol.c \
	 imc_ipc_protocol_legacy.c \
	 imc_ipc_ras_des.c \
	 imc_ipc_protocol_converged.c \
	 imc_ipc_dbg.c

# IOSM IPC Header files
imc_ipc-headers =  \
	 imc_ipc_completion.h \
	 imc_ipc_imem.h \
	 imc_ipc_mmio.h \
	 imc_ipc_hrtimer.h \
	 imc_ipc_sio.h \
	 imc_ipc_mux.h \
	 imc_ipc_tasklet.h \
	 imc_ipc_netlink.h \
	 imc_ipc_util.h \
	 imc_ipc_export.h \
	 imc_ipc_debugfs.h \
	 imc_ipc_uevent.h \
	 imc_ipc_parc.h \
	 imc_ipc_pm.h \
	 imc_ipc_pcie.h \
	 imc_ipc_rtpm.h \
	 imc_ipc_params.h \
	 imc_ipc_chnl_cfg.h \
	 imc_ipc_protocol.h \
	 imc_ipc_protocol_priv.h \
	 imc_ipc_protocol_legacy.h \
	 imc_ipc_protocol_converged.h \
	 imc_ipc_dbg.h \
	 imc_ipc_version.h \
	 imc_ipc_ras_des.h \
	 imc_ipc_wwan.h \
	 imc_ipc_trace.h \
	 imc_ipc_gpio_handler.h

include $(dir $(lastword $(MAKEFILE_LIST)))/Makefile.debug
