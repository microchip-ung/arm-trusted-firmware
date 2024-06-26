/*
 * Copyright (C) 2021 Microchip Technology Inc. and its subsidiaries.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>

#include <common/bl_common.h>
#include <drivers/generic_delay_timer.h>
#include <lib/mmio.h>
#include <lib/xlat_tables/xlat_tables_compat.h>
#include <lib/xlat_tables/xlat_tables_v2.h>
#include <plat/arm/common/plat_arm.h>
#include <plat/common/platform.h>
#include <plat/microchip/common/fw_config.h>
#include <plat_bl2u_bootstrap.h>
#include <lan96xx_common.h>

#include "lan966x_private.h"
#include "lan966x_regs.h"

#define MAP_BL2U_TOTAL		MAP_REGION_FLAT(			\
					BL2U_BASE,			\
					BL2U_LIMIT - BL2U_BASE,		\
					MT_MEMORY | MT_RW | MT_SECURE)

#define ARM_MAP_BL_RO			MAP_REGION_FLAT(			\
						BL_CODE_BASE,			\
						BL_CODE_END - BL_CODE_BASE,	\
						MT_CODE | MT_SECURE)

void bl2u_platform_setup(void)
{
	/* IO */
	lan966x_io_setup();

	/* Prepare fw_config from applicable boot source */
	if (lan966x_bootable_source()) {
		lan966x_load_fw_config(FW_CONFIG_ID);
		lan966x_fwconfig_apply();
	}

	/* Call BL2U UART monitor */
	lan966x_bl2u_bootstrap_monitor();

	/* Unprotect VCORE */
	mmio_clrbits_32(CPU_RESET_PROT_STAT(LAN966X_CPU_BASE),
			CPU_RESET_PROT_STAT_SYS_RST_PROT_VCORE(1));

	/* Issue GCB reset */
	mmio_write_32(GCB_SOFT_RST(LAN966X_GCB_BASE),
		      GCB_SOFT_RST_SOFT_SWC_RST(1));
}

void bl2u_early_platform_setup(struct meminfo *mem_layout, void *plat_info)
{
	/* Strapping */
	lan966x_init_strapping();

	/* Timer */
	lan966x_timer_init();

	/* Enable arch timer */
	generic_delay_timer_init();

	/* Limit trace level if needed */
	lan966x_set_max_trace_level();

	/* Console */
	lan966x_console_init();

	/* Check bootstrap mask: this may abort */
	lan966x_validate_strapping();

	/* Announce HW */
	INFO("Running on platform build: 0x%08x\n",
	     mmio_read_32(CPU_BUILDID(LAN966X_CPU_BASE)));
}

void bl2u_plat_arch_setup(void)
{

	const mmap_region_t bl_regions[] = {
		MAP_BL2U_TOTAL,
		ARM_MAP_BL_RO,
		{0}
	};

	setup_page_tables(bl_regions, plat_arm_get_mmap());

	/* Add region we'll be changing */
	mmap_add_dynamic_region(LAN966X_DDR_BASE, LAN966X_DDR_BASE, LAN966X_DDR_MAX_SIZE, MT_NON_CACHEABLE | MT_RW | MT_SECURE);

#ifdef __aarch64__
	enable_mmu_el1(0);
#else
	enable_mmu_svc_mon(0);
#endif
}
