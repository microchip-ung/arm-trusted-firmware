#
# Copyright (c) 2021, Microchip Technology Inc. and its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause
#

include lib/xlat_tables_v2/xlat_tables.mk
include drivers/arm/gic/v2/gicv2.mk
include lib/zlib/zlib.mk
include lib/libfit/libfit.mk
include lib/libfdt/libfdt.mk
include common/fdt_wrappers.mk

$(info Including platform TBBR)
include drivers/microchip/crypto/lan969x_crypto.mk

# MCHP SOC family
$(eval $(call add_define,MCHP_SOC_LAN969X))

# Use QSPI pipelined XDMA
$(eval $(call add_define,XDMAC_PIPELINE_SUPPPORT))

LAN969X_PLAT		:=	plat/microchip/lan969x
LAN969X_PLAT_BOARD	:=	${LAN969X_PLAT}/${PLAT}
LAN969X_PLAT_COMMON	:=	${LAN969X_PLAT}/common

PLAT_INCLUDES		:=	-Iinclude/plat/microchip/common			\
				-Iinclude/drivers/microchip/			\
				-I${LAN969X_PLAT}/include

LAN969X_CONSOLE_SOURCES	:=	drivers/gpio/gpio.c					\
				drivers/microchip/flexcom_uart/aarch64/flexcom_console.S \
				drivers/microchip/gpio/vcore_gpio.c

LAN969X_STORAGE_SOURCES	:=	drivers/io/io_block.c					\
				drivers/io/io_encrypted.c				\
				drivers/io/io_fip.c					\
				drivers/io/io_memmap.c					\
				drivers/io/io_mtd.c					\
				drivers/io/io_storage.c					\
				drivers/microchip/emmc/emmc.c				\
				drivers/microchip/qspi/qspi_mtd.c			\
				drivers/mmc/mmc.c					\
				drivers/mtd/nor/spi_nor.c				\
				drivers/mtd/spi-mem/spi_mem.c				\
				drivers/partition/gpt.c					\
				drivers/partition/partition.c				\
				plat/microchip/common/lan96xx_mmc.c			\
				plat/microchip/lan969x/common/lan969x_mmc.c

PLAT_BL_COMMON_SOURCES	:=	${FDT_WRAPPERS_SOURCES}			\
				${XLAT_TABLES_LIB_SRCS}			\
				${LAN969X_PLAT_COMMON}/aarch64/plat_helpers.S \
				${LAN969X_PLAT_COMMON}/lan969x_common.c \
				${LAN969X_PLAT_COMMON}/lan969x_strapping.c \
				${LAN969X_PLAT_COMMON}/lan969x_tbbr.c	\
				${LAN969X_CONSOLE_SOURCES}		\
				${LAN969X_STORAGE_SOURCES}		\
				$(ZLIB_SOURCES)				\
				drivers/delay_timer/delay_timer.c	\
				drivers/delay_timer/generic_delay_timer.c \
				drivers/microchip/clock/lan966x_clock.c \
				drivers/microchip/crypto/lan966x_sha.c	\
				drivers/microchip/dma/xdmac.c		\
				drivers/microchip/otp/otp.c		\
				drivers/microchip/trng/lan966x_trng.c	\
				drivers/microchip/tz_matrix/tz_matrix.c	\
				plat/microchip/common/duff_memcpy.c	\
				plat/microchip/common/fw_config_dt.c	\
				plat/microchip/common/lan966x_crc32.c	\
				plat/microchip/common/lan96xx_common.c	\
				plat/microchip/common/plat_crypto.c	\
				plat/microchip/common/plat_tbbr.c

BL1_SOURCES		+=	lib/cpus/aarch64/cortex_a53.S			\
				${LAN969X_PLAT_COMMON}/lan969x_bl1_setup.c	\
				plat/common/aarch64/platform_up_stack.S		\
				plat/microchip/common/lan966x_bl1_pcie.c	\
				plat/microchip/common/lan966x_bootstrap.c	\
				plat/microchip/common/lan966x_sjtag.c		\
				plat/microchip/common/plat_bl1_bootstrap.c	\
				plat/microchip/lan969x/common/lan969x_io_storage.c

BL2_SOURCES		+=	common/desc_image_load.c			\
				drivers/arm/tzc/tzc400.c			\
				drivers/microchip/pcie/lan969x_pcie_ep.c	\
				${LAN969X_PLAT_COMMON}/lan969x_bl2_mem_params_desc.c \
				${LAN969X_PLAT_COMMON}/lan969x_bl2_setup.c	\
				${LAN969X_PLAT_COMMON}/lan969x_tz.c		\
				${LAN969X_PLAT_COMMON}/lan969x_image_load.c	\
				plat/microchip/common/lan966x_sjtag.c		\
				plat/microchip/lan969x/common/lan969x_io_storage.c

BL2U_SOURCES		+=	drivers/arm/tzc/tzc400.c			\
				${LAN969X_PLAT_COMMON}/lan969x_bl2u_setup.c	\
				${LAN969X_PLAT_COMMON}/lan969x_tz.c		\
				plat/microchip/common/lan966x_bootstrap.c	\
				plat/microchip/common/lan966x_fw_bind.c		\
				plat/microchip/common/plat_bl2u_bootstrap.c	\
				plat/microchip/lan969x/common/lan969x_bl2u_io.c

# Only BL2U needs this
BL2U_CPPFLAGS := -DPLAT_XLAT_TABLES_DYNAMIC

ifneq (${PLAT},lan969x_sr)
DDR_SOURCES	:=					\
	plat/microchip/common/ddr_test.c		\
	${LAN969X_PLAT_COMMON}/ddr_umctl.c		\
	${LAN969X_PLAT_COMMON}/lan969x_ddr_config.c	\
	${LAN969X_PLAT_COMMON}/lan969x_ddr_clock.c
else
DDR_SOURCES	:=					\
	${LAN969X_PLAT_COMMON}/lan969x_ddr.c		\
	${LAN969X_PLAT_COMMON}/lan969x_ddr_config.c
endif

BL2_SOURCES	+=  ${DDR_SOURCES}
BL2U_SOURCES	+=  ${DDR_SOURCES}

ifneq ($(filter ${BL2_VARIANT},NOOP NOOP_OTP),)
$(info Generating a BL2 NOOP)
override BL2_SOURCES		:=	\
				bl2/${ARCH}/bl2_entrypoint.S				\
				common/aarch64/early_exceptions.S			\
				plat/microchip/lan969x/common/${ARCH}/plat_bl2_noop.S
endif

BL31_SOURCES		+=	$(LIBFIT_SRCS)					\
				${GICV2_SOURCES}				\
				${LAN969X_PLAT_COMMON}/lan969x_bl31_setup.c	\
				${LAN969X_PLAT_COMMON}/lan969x_pm.c		\
				${LAN969X_PLAT_COMMON}/lan969x_topology.c	\
				drivers/microchip/crypto/aes.c			\
				drivers/microchip/otp/otp_tags.c		\
				lib/cpus/aarch64/cortex_a53.S			\
				plat/common/plat_gicv2.c			\
				plat/common/plat_psci_common.c			\
				plat/microchip/common/lan966x_fw_bind.c		\
				plat/microchip/common/lan966x_ns_enc.c		\
				plat/microchip/common/lan966x_sip_svc.c		\
				plat/microchip/common/lan966x_sjtag.c		\
				plat/microchip/lan966x/common/lan966x_gicv2.c

# libfit must support unzip
$(eval $(call add_define,MCHP_LIBFIT_GZIP))

# We have/require TBB
TRUSTED_BOARD_BOOT		:= 1

COLD_BOOT_SINGLE_CPU		:= 1

CRASH_REPORTING			:= 1

TRNG_SUPPORT			:= 1

# Non-volatile counter values
TFW_NVCTR_VAL			?=	2
NTFW_NVCTR_VAL			?=	3

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

# ASM impl of various (memset)
OVERRIDE_LIBC			:= 1
ifeq (${OVERRIDE_LIBC},1)
    include lib/libc/libc_asm.mk
endif

# DT related compile flags
$(eval $(call add_define,FW_CONFIG_DT))
DTC_CPPFLAGS		+=	-I ${LAN969X_PLAT}/fdts

# Set FIP alignment to acheive good performance
FIP_ALIGN		:= 512

# io_block layer optimization
$(eval $(call add_define_val,IO_BLOCK_DIRECT_COPY_BLOCK_ALIGN,512))

# Generate the FIPs FW_CONFIG
LAN969X_FW_CONFIG	:=	${BUILD_PLAT}/fdts/${PLAT}_tb_fw_config.dtb

DTC_FLAGS		+=	-Wno-unit_address_vs_reg -Wno-simple_bus_reg

FDT_SOURCES		+=	${LAN969X_PLAT_BOARD}/fdts/${PLAT}_tb_fw_config.dts

# FW config
$(eval $(call TOOL_ADD_PAYLOAD,${LAN969X_FW_CONFIG},--fw-config,${LAN969X_FW_CONFIG}))

FWU_HTML := ${BUILD_PLAT}/fwu.html
FWU_JS   := ${BUILD_PLAT}/fwu_app.js

${FWU_JS}: ${BUILD_PLAT}/${FWU_FIP_NAME}
	./plat/microchip/scripts/mkjs.rb -p ${PLAT} -o ${FWU_JS} $<

${FWU_HTML}: ${FWU_JS}
	./plat/microchip/scripts/html_inline.rb -i ${BUILD_PLAT} ./scripts/fwu/serial.html > ${FWU_HTML}

all: ${FWU_HTML}
