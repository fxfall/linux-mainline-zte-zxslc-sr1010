# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the ZTE device drivers
#

obj-$(CONFIG_DINGHAI) += dinghai/

# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_ZTE_ZX279133_ETH) += npu.o
npu-y := zx279133-main.o zx279133-tm.o zx279133-np.o zx279133-idm.o \
	       zx279133-mac.o zx279133-netdev.o zx279133-offload-api.o \
	       zx279133-ptp.o

npu-y += zx279133-host.o zx279133-native.o zx279133-meter.o
npu-$(CONFIG_ZTE_ZX279133_NATIVE_DEBUG) += zx279133-native-debug.o

obj-$(CONFIG_ZTE_ZX279133_LAN_CONDUIT) += zx279133-lan-conduit.o
obj-$(CONFIG_ZTE_ZX279133_RTL8372N) += zx279133-rtl8372n.o

obj-$(CONFIG_ZTE_ZX279133_FNOFFLOAD) += fnoffload.o
fnoffload-y := zx279133-offload.o
