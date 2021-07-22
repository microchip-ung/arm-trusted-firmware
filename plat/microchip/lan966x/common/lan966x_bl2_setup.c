/*
 * Copyright (C) 2021 Microchip Technology Inc. and its subsidiaries.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>

#include <common/bl_common.h>
#include <drivers/generic_delay_timer.h>
#include <drivers/microchip/otp.h>
#include <lib/mmio.h>
#include <lib/xlat_tables/xlat_tables_compat.h>
#include <plat/arm/common/plat_arm.h>
#include <plat/common/platform.h>

#include "lan966x_private.h"
#include "lan966x_regs.h"
#include "lan966x_memmap.h"

/* Data structure which holds the extents of the trusted SRAM for BL2 */
static meminfo_t bl2_tzram_layout __aligned(CACHE_WRITEBACK_GRANULE);

#define MAP_BL2_TOTAL		MAP_REGION_FLAT(			\
					bl2_tzram_layout.total_base,	\
					bl2_tzram_layout.total_size,	\
					MT_MEMORY | MT_RW | MT_SECURE)

#if SEPARATE_CODE_AND_RODATA
#define ARM_MAP_BL_RO			MAP_REGION_FLAT(			\
						BL_CODE_BASE,			\
						BL_CODE_END - BL_CODE_BASE,	\
						MT_CODE | MT_SECURE),		\
					MAP_REGION_FLAT(			\
						BL_RO_DATA_BASE,		\
						BL_RO_DATA_END			\
							- BL_RO_DATA_BASE,	\
						MT_RO_DATA | MT_SECURE)
#else
#define ARM_MAP_BL_RO			MAP_REGION_FLAT(			\
						BL_CODE_BASE,			\
						BL_CODE_END - BL_CODE_BASE,	\
						MT_CODE | MT_SECURE)
#endif

#if USE_COHERENT_MEM
#define ARM_MAP_BL_COHERENT_RAM		MAP_REGION_FLAT(			\
						BL_COHERENT_RAM_BASE,		\
						BL_COHERENT_RAM_END		\
							- BL_COHERENT_RAM_BASE, \
						MT_DEVICE | MT_RW | MT_SECURE)
#endif

/*******************************************************************************
 * Perform the very early platform specific architectural setup here. At the
 * moment this is only initializes the mmu in a quick and dirty way.
 ******************************************************************************/
void bl2_plat_arch_setup(void)
{
	const mmap_region_t bl_regions[] = {
		MAP_BL2_TOTAL,
		MAP_PKCL_CODE,
		MAP_PKCL_DATA,
		ARM_MAP_BL_RO,
#if USE_COHERENT_MEM
		ARM_MAP_BL_COHERENT_RAM,
#endif
		{0}
	};

	setup_page_tables(bl_regions, plat_arm_get_mmap());

#ifdef __aarch64__
	enable_mmu_el1(0);
#else
	enable_mmu_svc_mon(0);
#endif
}

static void bl2_early_platform_setup(void)
{
#if defined(DEBUG)
	/* Spin if in debugger */
	while (mmio_read_32(CPU_CPU_DBG(LAN966X_CPU_BASE)) &
	       CPU_CPU_DBG_CORE_IN_DBG(1))
		/* nop */;
#endif

#if BL2_AT_EL3
	/* BL1 was not there */
	lan966x_timer_init();
#endif

	/* Enable arch timer */
	generic_delay_timer_init();

	/* Console */
	lan966x_console_init();

	/* Announce HW */
	INFO("Running on platform build: 0x%08x\n",
	     mmio_read_32(CPU_BUILDID(LAN966X_CPU_BASE)));
}

void bl2_early_platform_setup2(u_register_t arg0, u_register_t arg1, u_register_t arg2, u_register_t arg3)
{
	/* Save memory layout */
	bl2_tzram_layout = *(struct meminfo *) arg1;

#if defined(BL1_RW_BASE) && defined(BL1_RW_LIMIT)
	/* Check if fw_config is forwarded */
	if (arg2 > BL1_RW_BASE && arg2 < BL1_RW_LIMIT)
		memcpy(&lan966x_fw_config, (void *) arg2, sizeof(lan966x_fw_config));
#endif

	/* Common setup */
	bl2_early_platform_setup();
}

void bl2_el3_early_platform_setup(u_register_t arg1, u_register_t arg2,
				  u_register_t arg3, u_register_t arg4)
{
	bl2_tzram_layout.total_base = BL2_BASE;
	bl2_tzram_layout.total_size = BL2_SIZE;

	/* Common setup */
	bl2_early_platform_setup();
}

void bl2_el3_plat_arch_setup(void)
{
	bl2_plat_arch_setup();
}

void bl2_platform_setup(void)
{
	/* IO */
	lan966x_io_setup();

#if BL2_AT_EL3
	/* No BL1 to forward fw_config, load it ourselves */
	lan966x_load_fw_config(FW_CONFIG_ID);
	/* Apply fw_config */
	lan966x_fwconfig_apply();
#endif

	/* OTP */
	otp_emu_init();

	/* SJTAG: Freeze mode and configuration */
	lan966x_sjtag_configure();

#if !defined(LAN966X_ASIC)
	/* On ASIC, we don't get fw_config forwarded, so read in
	 * ourselves.
	 */
	lan966x_load_fw_config(FW_CONFIG_ID);
#endif

	/* Initialize DDR for loading BL32/BL33 */
	lan966x_ddr_init();

#if defined(LAN966X_TZ)   /* N/A on LAN966X-A0 due to chip error */
	/* Initialize the secure environment */
	lan966x_tz_init();
#endif
#if defined(LAN966X_AES_TESTS)
	lan966x_crypto_tests();
#endif
}
