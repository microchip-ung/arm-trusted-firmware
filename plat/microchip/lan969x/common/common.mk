#
# Copyright (c) 2021, Microchip Technology Inc. and its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause
#

include lib/xlat_tables_v2/xlat_tables.mk
include drivers/arm/gic/v2/gicv2.mk
include drivers/microchip/crypto/lan966x_crypto.mk

# MCHP SOC family
$(eval $(call add_define,MCHP_SOC_LAN969X))

LAN969X_PLAT		:=	plat/microchip/lan969x
LAN969X_PLAT_BOARD	:=	${LAN969X_PLAT}/${PLAT}
LAN969X_PLAT_COMMON	:=	${LAN969X_PLAT}/common

PLAT_INCLUDES		:=	-Iinclude/plat/microchip/common			\
				-Iinclude/drivers/microchip/			\
				-I${LAN969X_PLAT}/include

LAN969X_STORAGE_SOURCES	:=	drivers/io/io_block.c					\
				drivers/io/io_encrypted.c				\
				drivers/io/io_fip.c					\
				drivers/io/io_memmap.c					\
				drivers/io/io_storage.c					\
				drivers/microchip/emmc/emmc.c				\
				drivers/microchip/qspi/qspi.c				\
				drivers/mmc/mmc.c					\
				drivers/partition/gpt.c					\
				drivers/partition/partition.c				\
				plat/microchip/lan969x/common/lan969x_io_storage.c	\
				plat/microchip/lan969x/common/lan969x_mmc.c
# Disabled
#				drivers/microchip/gpio/vcore_gpio.s

PLAT_BL_COMMON_SOURCES	:=	${XLAT_TABLES_LIB_SRCS}			\
				${LAN969X_PLAT_COMMON}/aarch64/plat_helpers.S \
				${LAN969X_PLAT_COMMON}/lan969x_common.c \
				${LAN969X_PLAT_COMMON}/lan969x_tbbr.c	\
				${LAN969X_STORAGE_SOURCES}		\
				drivers/delay_timer/delay_timer.c	\
				drivers/delay_timer/generic_delay_timer.c \
				drivers/microchip/clock/lan966x_clock.c \
				drivers/microchip/flexcom_uart/aarch64/flexcom_console.S \
				drivers/microchip/otp/otp.c		\
				drivers/microchip/trng/lan966x_trng.c	\
				drivers/microchip/tz_matrix/tz_matrix.c	\
				plat/microchip/common/fw_config.c	\
				plat/microchip/common/plat_crypto.c	\
				plat/microchip/common/plat_tbbr.c

BL1_SOURCES		+=	lib/cpus/aarch64/cortex_a53.S			\
				${LAN969X_PLAT_COMMON}/lan969x_bl1_setup.c	\
				plat/common/aarch64/platform_up_stack.S		\
				plat/microchip/common/lan966x_sjtag.c

BL2_SOURCES		+=	common/desc_image_load.c			\
				drivers/arm/tzc/tzc400.c			\
				${LAN969X_PLAT_COMMON}/lan969x_bl2_mem_params_desc.c \
				${LAN969X_PLAT_COMMON}/lan969x_bl2_setup.c	\
				${LAN969X_PLAT_COMMON}/lan969x_image_load.c	\
				plat/microchip/common/lan966x_sjtag.c

BL31_SOURCES		+=	${GICV2_SOURCES}				\
				${LAN969X_PLAT_COMMON}/lan969x_bl31_setup.c	\
				${LAN969X_PLAT_COMMON}/lan969x_pm.c		\
				${LAN969X_PLAT_COMMON}/lan969x_topology.c	\
				lib/cpus/aarch64/cortex_a53.S			\
				plat/common/plat_gicv2.c			\
				plat/common/plat_psci_common.c			\
				plat/microchip/lan966x/common/lan966x_gicv2.c

# We have/require TBB
TRUSTED_BOARD_BOOT		:= 1

COLD_BOOT_SINGLE_CPU		:= 1

CRASH_REPORTING			:= 1

TRNG_SUPPORT			:= 1

# Enable stack protection
ENABLE_STACK_PROTECTOR	 	:= strong

ifneq (${ENABLE_STACK_PROTECTOR},0)
PLAT_BL_COMMON_SOURCES  +=      plat/microchip/common/lan966x_stack_protector.c
endif

# Tune compiler for Cortex-A53
ifeq ($(notdir $(CC)),armclang)
    TF_CFLAGS_aarch64	+=	-mcpu=cortex-a53
else ifneq ($(findstring clang,$(notdir $(CC))),)
    TF_CFLAGS_aarch64	+=	-mcpu=cortex-a53
else
    TF_CFLAGS_aarch64	+=	-mtune=cortex-a53
endif

# Build config flags
# ------------------

# Enable all errata workarounds for Cortex-A53
ERRATA_A53_819472		:= 1
ERRATA_A53_824069		:= 1
ERRATA_A53_827319		:= 1
ERRATA_A53_835769		:= 1
ERRATA_A53_836870		:= 1
ERRATA_A53_843419		:= 1
ERRATA_A53_855873		:= 1
ERRATA_A53_1530924		:= 1

WORKAROUND_CVE_2017_5715	:= 0
