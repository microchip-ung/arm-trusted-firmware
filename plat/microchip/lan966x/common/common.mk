#
# Copyright (c) 2021, Microchip Technology Inc. and its subsidiaries.
#
# SPDX-License-Identifier: BSD-3-Clause
#

ifeq (${ARCH},aarch64)
  $(error Error: AArch64 not supported on ${PLAT})
endif

ARM_CORTEX_A7                   := yes
ARM_ARCH_MAJOR			:= 7

COLD_BOOT_SINGLE_CPU		:= 1

# We have/require TBB
TRUSTED_BOARD_BOOT		:= 1

# Default number of CPUs per cluster on FVP
LAN966x_MAX_CPUS_PER_CLUSTER	:= 1

# Default number of threads per CPU on FVP
LAN966x_MAX_PE_PER_CPU	:= 1

# No coherent memory, we're single core
USE_COHERENT_MEM	:= 0

# To compile with highest log level (VERBOSE) set value to 50
LOG_LEVEL := 40

# Single-core system
WARMBOOT_ENABLE_DCACHE_EARLY	:=	1

# Set FIP alignment to acheive good performance
FIP_ALIGN		:= 512

# Must be zero on aarch32
ENABLE_SVE_FOR_NS		:=	0

# Save some memory for GUIDs not used
$(eval $(call add_define,GPT_NO_GUID))

# Pass LAN966x_MAX_CPUS_PER_CLUSTER to the build system.
$(eval $(call add_define,LAN966x_MAX_CPUS_PER_CLUSTER))

# Pass LAN966x_MAX_PE_PER_CPU to the build system.
$(eval $(call add_define,LAN966x_MAX_PE_PER_CPU))

include lib/xlat_tables_v2/xlat_tables.mk
include lib/zlib/zlib.mk

$(info Including platform TBBR)
# Mbed TLS heap size is smal as we only use the asn1 parsing functions
# digest, signature and crypto algorithm are done by other library.
# NB: Only affects BL1 due to heap sharing
$(eval $(call add_define_val,TF_MBEDTLS_HEAP_SIZE,5120U))
include drivers/microchip/crypto/lan966x_crypto.mk

# MCHP SOC family
$(eval $(call add_define,MCHP_SOC_LAN966X))

# We have OTP emulation enabled
$(eval $(call add_define,MCHP_OTP_EMULATION))

# Default chip variant = platform
ifeq (${PLAT_VARIANT},)
PLAT_VARIANT			:=	${PLAT}
endif

PLAT_INCLUDES	:=	-Iinclude/plat/microchip/common				\
			-Iplat/microchip/lan966x/${PLAT_VARIANT}/include	\
			-Iplat/microchip/lan966x/common/include			\
			-Idrivers/microchip/crypto/inc/				\
			-Iinclude/drivers/microchip

LAN966X_CONSOLE_SOURCES	:=	\
				drivers/microchip/gpio/vcore_gpio.c			\
				drivers/microchip/qspi/qspi.c				\
				drivers/microchip/flexcom_uart/aarch32/flexcom_console.S \
				drivers/gpio/gpio.c					\

LAN966X_STORAGE_SOURCES	:=	\
				drivers/io/io_block.c					\
				drivers/io/io_encrypted.c				\
				drivers/io/io_fip.c					\
				drivers/io/io_memmap.c					\
				drivers/io/io_storage.c					\
				drivers/microchip/emmc/emmc.c				\
				drivers/mmc/mmc.c					\
				drivers/partition/gpt.c					\
				drivers/partition/partition.c				\
				plat/microchip/common/lan96xx_mmc.c			\
				plat/microchip/lan966x/common/lan966x_mmc.c

PLAT_BL_COMMON_SOURCES	+=	\
				${LAN966X_CONSOLE_SOURCES}				\
				${LAN966X_STORAGE_SOURCES}				\
				${XLAT_TABLES_LIB_SRCS}					\
				$(ZLIB_SOURCES)						\
				common/desc_image_load.c				\
				drivers/delay_timer/delay_timer.c			\
				drivers/delay_timer/generic_delay_timer.c		\
				drivers/microchip/clock/lan966x_clock.c			\
				drivers/microchip/crypto/lan966x_sha.c			\
				drivers/microchip/dma/xdmac.c				\
				drivers/microchip/otp/otp.c				\
				drivers/microchip/tz_matrix/tz_matrix.c			\
				lib/cpus/aarch32/cortex_a7.S				\
				plat/microchip/common/fw_config.c			\
				plat/microchip/common/lan966x_crc32.c			\
				plat/microchip/common/lan96xx_common.c			\
				plat/microchip/common/plat_crypto.c			\
				plat/microchip/common/plat_tbbr.c			\
				plat/microchip/lan966x/common/${ARCH}/plat_helpers.S	\
				plat/microchip/lan966x/common/lan966x_common.c		\
				plat/microchip/lan966x/common/lan966x_strapping.c	\
				drivers/microchip/trng/lan966x_trng.c

BL1_SOURCES		+=	\
				plat/microchip/common/lan966x_bootstrap.c		\
				plat/microchip/common/lan966x_sjtag.c			\
				plat/microchip/common/plat_bl1_bootstrap.c		\
				plat/microchip/common/lan966x_bl1_pcie.c		\
				plat/microchip/lan966x/common/lan966x_io_storage.c	\
				plat/microchip/lan966x/common/lan966x_bl1_setup.c	\
				plat/microchip/lan966x/common/lan966x_tbbr.c

BL2_SOURCES		+=	\
				plat/microchip/common/ddr_test.c			\
				plat/microchip/common/lan966x_sjtag.c			\
				plat/microchip/lan966x/common/lan966x_io_storage.c	\
				plat/microchip/lan966x/common/lan966x_bl2_mem_params_desc.c \
				plat/microchip/lan966x/common/lan966x_bl2_setup.c	\
				plat/microchip/lan966x/common/ddr_umctl.c		\
				plat/microchip/lan966x/common/lan966x_ddr_config.c	\
				plat/microchip/lan966x/common/lan966x_image_load.c	\
				plat/microchip/lan966x/common/lan966x_tbbr.c		\
				plat/microchip/lan966x/common/lan966x_tz.c

BL2U_SOURCES		+=	plat/microchip/common/ddr_test.c			\
				plat/microchip/common/lan966x_bootstrap.c		\
				plat/microchip/common/lan966x_fw_bind.c			\
				plat/microchip/common/plat_bl2u_bootstrap.c		\
				plat/microchip/lan966x/common/lan966x_bl2u_io.c		\
				plat/microchip/lan966x/common/lan966x_bl2u_setup.c	\
				plat/microchip/lan966x/common/ddr_umctl.c		\
				plat/microchip/lan966x/common/lan966x_ddr_config.c

# Only BL2U needs this
BL2U_CPPFLAGS := -DPLAT_XLAT_TABLES_DYNAMIC

ifneq ($(filter ${BL2_VARIANT},NOOP NOOP_OTP),)
override BL2_SOURCES		:=	\
				bl2/${ARCH}/bl2_entrypoint.S				\
				plat/microchip/lan966x/common/${ARCH}/plat_bl2_noop.S
$(info Generating a BL2 NOOP)
endif

# Add the build options to pack Trusted OS Extra1 and Trusted OS Extra2 images
# in the FIP if the platform requires.
ifneq ($(BL32_EXTRA1),)
$(eval $(call TOOL_ADD_IMG,bl32_extra1,--tos-fw-extra1,,$(ENCRYPT_BL32)))
endif
ifneq ($(BL32_EXTRA2),)
$(eval $(call TOOL_ADD_IMG,bl32_extra2,--tos-fw-extra2,,$(ENCRYPT_BL32)))
endif

# Enable Activity Monitor Unit extensions by default
ENABLE_AMU			:=	1

# We have TRNG
TRNG_SUPPORT			:=	1

# Enable stack protection
ENABLE_STACK_PROTECTOR	 	:= strong

ifneq (${ENABLE_STACK_PROTECTOR},0)
PLAT_BL_COMMON_SOURCES  +=      plat/microchip/common/lan966x_stack_protector.c
endif

# Generate binary FW configuration data for inclusion in the FIPs FW_CONFIG
LAN966X_FW_PARAM	:=	${BUILD_PLAT}/fw_param.bin

${LAN966X_FW_PARAM}: plat/microchip/config/fw_data_lan966x.yaml
	$(info Generating binary FW configuration data)
	$(Q)ruby scripts/otp_fw_data.rb $< $@

# Generate the FIPs FW_CONFIG
LAN966X_FW_CONFIG	:=	${BUILD_PLAT}/fw_config.bin

${LAN966X_FW_CONFIG}: ${LAN966X_OTP_DATA} ${LAN966X_FW_PARAM}
	$(Q)ruby ./scripts/otpbin.rb $(if ${LAN966X_OTP_DATA},-y ${LAN966X_OTP_DATA}) -o $@
	$(Q)cat ${LAN966X_FW_PARAM} >> $@

# FW config
$(eval $(call TOOL_ADD_PAYLOAD,${LAN966X_FW_CONFIG},--fw-config,${LAN966X_FW_CONFIG}))

# Regenerate the header file from the YAML definition
LAN966X_OTP_H = include/plat/microchip/common/plat_otp.h

${LAN966X_OTP_H}: scripts/otp.yaml
	$(info Generating OTP headerfile)
	$(Q)scripts/otpgen.rb  -y $< -g $@

FWU_HTML := ${BUILD_PLAT}/fwu.html
FWU_JS   := ${BUILD_PLAT}/fwu_app.js

${FWU_JS}: ${BUILD_PLAT}/${FWU_FIP_NAME}
	./plat/microchip/scripts/mkjs.rb -p ${PLAT} -o ${FWU_JS} $<

${FWU_HTML}: ${FWU_JS}
	./plat/microchip/scripts/html_inline.rb -i ${BUILD_PLAT} ./scripts/fwu/serial.html > ${FWU_HTML}

all: ${FWU_HTML}
