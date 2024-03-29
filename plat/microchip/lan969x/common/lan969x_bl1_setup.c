/*
 * Copyright (C) 2021 Microchip Technology Inc. and its subsidiaries.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>

#include <arch.h>
#include <bl1/bl1.h>
#include <common/bl_common.h>
#include <drivers/generic_delay_timer.h>
#include <drivers/microchip/otp.h>
#include <fw_config.h>
#include <lib/fconf/fconf.h>
#include <lib/utils.h>
#include <lib/xlat_tables/xlat_tables_compat.h>
#include <plat/arm/common/plat_arm.h>
#include <plat/common/platform.h>
#include <plat/microchip/common/lan966x_sjtag.h>
#include <plat/microchip/common/plat_bootstrap.h>

#include "lan969x_private.h"
#include "lan969x_memmap.h"

#define MAP_BL1_TOTAL   MAP_REGION_FLAT(				\
		bl1_tzram_layout.total_base,				\
		bl1_tzram_layout.total_size,				\
		MT_MEMORY | MT_RW | MT_SECURE)
/*
 * If SEPARATE_CODE_AND_RODATA=1 we define a region for each section
 * otherwise one region is defined containing both
 */
#if SEPARATE_CODE_AND_RODATA
#define MAP_BL1_RO	MAP_REGION_FLAT(				\
		BL_CODE_BASE,						\
		BL1_CODE_END - BL_CODE_BASE,				\
		MT_CODE | MT_SECURE),					\
		MAP_REGION_FLAT(					\
			BL1_RO_DATA_BASE,				\
			BL1_RO_DATA_END					\
			- BL_RO_DATA_BASE,				\
			MT_RO_DATA | MT_SECURE)
#else
#define MAP_BL1_RO	MAP_REGION_FLAT(				\
		BL_CODE_BASE,						\
		BL1_CODE_END - BL_CODE_BASE,				\
		MT_CODE | MT_SECURE)
#endif

/* Data structure which holds the extents of the trusted SRAM for BL1*/
static meminfo_t bl1_tzram_layout;
static meminfo_t bl2_tzram_layout;

/* Boolean variable to hold condition whether firmware update needed or not */
static bool is_fwu_needed;

struct meminfo *bl1_plat_sec_mem_layout(void)
{
	return &bl1_tzram_layout;
}

void bl1_early_platform_setup(void)
{
	/* Timer */
	lan969x_timer_init();

	/* Enable arch timer */
	generic_delay_timer_init();

	/* Strapping */
	lan966x_init_strapping();

	/* Set logging level */
	lan969x_set_max_trace_level();

	/* Console */
	lan969x_console_init();

	/* Check bootstrap mask: this may abort */
	lan966x_validate_strapping();

	/* PCIe - may never return */
	lan966x_pcie_init();

	/* Allow BL1 to see the whole Trusted RAM */
	bl1_tzram_layout.total_base = LAN969X_SRAM_BASE;
	bl1_tzram_layout.total_size = LAN969X_SRAM_SIZE;
}

void bl1_plat_arch_setup(void)
{
	const mmap_region_t bl_regions[] = {
		MAP_BL1_TOTAL,
		MAP_SILEX_REGS,
		MAP_SILEX_RAM,
		MAP_BL1_RO,
		{0}
	};

	setup_page_tables(bl_regions, plat_arm_get_mmap());
#ifdef __aarch64__
	enable_mmu_el3(0);
#else
	enable_mmu_svc_mon(0);
#endif /* __aarch64__ */
}

void bl1_platform_setup(void)
{
	/* IO */
	lan966x_io_setup();

	/* Prepare fw_config from applicable boot source */
	if (lan966x_bootable_source()) {
		/* Prepare fw_config from applicable boot source */
		bl1_plat_handle_pre_image_load(FW_CONFIG_ID);
		lan966x_load_fw_config(FW_CONFIG_ID);
		bl1_plat_handle_post_image_load(FW_CONFIG_ID);
	}

	/* SJTAG: Configure challenge, no freeze */
	lan966x_sjtag_configure();

	/* Strapped for boot monitor? */
	if (lan966x_monitor_enabled()) {
		plat_bl1_bootstrap_monitor();
	}
}

void bl1_plat_prepare_exit(entry_point_info_t *ep_info)
{
}

void plat_bootstrap_trigger_fwu(void)
{
	is_fwu_needed = true;
}

/*******************************************************************************
 * The following function checks if Firmware update is needed,
 * by checking if TOC in FIP image is valid or not.
 ******************************************************************************/
unsigned int bl1_plat_get_next_image_id(void)
{
	return is_fwu_needed ? NS_BL1U_IMAGE_ID : BL2_IMAGE_ID;
}

/*
 * Cannot use default weak implementation in bl1_main.c because the
 * location of the 'bl2_secram_layout' structure at start of
 * memory. We place BL2 itself here, so we must explicitly allocate
 * the bl2 meminfo_t structure.
 */
int bl1_plat_handle_post_image_load(unsigned int image_id)
{
	image_desc_t *image_desc;
	entry_point_info_t *ep_info;

	if (image_id != BL2_IMAGE_ID)
		return 0;

	/* Get the image descriptor */
	image_desc = bl1_plat_get_image_desc(BL2_IMAGE_ID);
	assert(image_desc != NULL);

	/* Get the entry point info */
	ep_info = &image_desc->ep_info;

	bl2_tzram_layout.total_base = BL2_BASE;
	bl2_tzram_layout.total_size = BL2_SIZE;

	flush_dcache_range((uintptr_t)&bl2_tzram_layout, sizeof(meminfo_t));

	ep_info->args.arg1 = (uintptr_t)&bl2_tzram_layout;

	/* Fwconfig memory info in arg2 */
	ep_info->args.arg2 = (uintptr_t) &lan966x_fw_config;
	flush_dcache_range(ep_info->args.arg2, sizeof(lan966x_fw_config));

	return 0;
}
