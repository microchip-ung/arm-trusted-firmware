/*
 * Copyright (C) 2022 Microchip Technology Inc. and its subsidiaries.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <common/debug.h>
#include <drivers/arm/tzc400.h>
#include <drivers/microchip/lan966x_trng.h>
#include <drivers/microchip/tz_matrix.h>
#include <lib/mmio.h>

#include "lan966x_regs.h"
#include "lan969x_private.h"
#include "plat_otp.h"

#define TZC_NSAID_DEFAULT		0
#define PLAT_ARM_TZC_NS_DEV_ACCESS	TZC_REGION_ACCESS_RDWR(TZC_NSAID_DEFAULT)
#define PLAT_ARM_TZC_FILTERS		TZC_400_REGION_ATTR_FILTER_BIT(0)

typedef struct {
	unsigned int region;
	unsigned int sec_attr;
	unsigned int nsaid_permissions;
	unsigned long long region_base; /* Not for region 0 */
	unsigned long long region_top;  /* Not for region 0 */
} lan969x_tcreg_t;

/* Only NS access by default */
static const lan969x_tcreg_t css_rules[] = {
	{ 0, TZC_REGION_S_RDWR, PLAT_ARM_TZC_NS_DEV_ACCESS, }
};

/* Only NS access by default */
static const lan969x_tcreg_t hss_rules[] = {
	{ 0, TZC_REGION_S_RDWR, PLAT_ARM_TZC_NS_DEV_ACCESS, }
};

static void setup_ns_access(uintptr_t gpv, uintptr_t tzpm)
{
	/* Allow S+NS access to these devices */
	mmio_write_32(GPV_SECURITY_CPU_REGS(gpv), BIT(0));
	mmio_write_32(GPV_SECURITY_CSR_REGS(gpv), BIT(0));
	mmio_write_32(GPV_SECURITY_DDR_CSS(gpv), BIT(0));
	mmio_write_32(GPV_SECURITY_DDR_MAIN(gpv), BIT(0));
	mmio_write_32(GPV_SECURITY_APB_CSS2(gpv), BIT(0)); /* OTP */
	mmio_write_32(GPV_SECURITY_APB_MAIN3(gpv), BIT(2)|BIT(3)); /* TIMERS, WDT */
}

void lan969x_tzc_configure(uintptr_t tzc_base, const lan969x_tcreg_t *regions, size_t nregs)
{
	const lan969x_tcreg_t *reg;
	int i;

	VERBOSE("Configuring TZC@%08lx\n", tzc_base);
	tzc400_init(tzc_base);
	tzc400_disable_filters();

	for (i = 0, reg = regions; i < nregs; i++, reg++) {
		VERBOSE("Region(%d) = %08x %08x\n", reg->region, reg->sec_attr, reg->nsaid_permissions);
		if (reg->region == 0)
			tzc400_configure_region0(reg->sec_attr, reg->nsaid_permissions);
		else
			tzc400_configure_region(
				TZC_400_REGION_ATTR_FILTER_BIT_ALL,
				reg->region,
				reg->sec_attr, reg->nsaid_permissions,
				reg->region_base, reg->region_top);
	}

	/* Raise an exception+irq if a NS device tries to access secure memory */
	tzc400_set_action(TZC_ACTION_ERR_INT);

	/* Shields UP */
	tzc400_enable_filters();

	/* Done */
	VERBOSE("TZC Active\n");
}

void lan969x_tz_init(void)
{
	INFO("Configuring TrustZone\n");

	/*
	 * Enable TZPM for NS transactions, Otherwise all are treated
	 * as Secure transactions in CPU subsystem
	 */
	mmio_write_32(TZPM_TZPM_EN(LAN969X_TZPM_BASE),
		      TZPM_TZPM_EN_TZPM_EN(1));

	/* NS periph access */
	setup_ns_access(LAN969X_GPV_BASE, LAN969X_TZPM_BASE);

	/* Enable QSPI0 for NS access */
	matrix_configure_slave_security(MATRIX_SLAVE_QSPI0,
					MATRIX_SRTOP(0, MATRIX_SRTOP_VALUE_128M) |
					MATRIX_SRTOP(1, MATRIX_SRTOP_VALUE_128M),
					MATRIX_SASPLIT(0, MATRIX_SRTOP_VALUE_128M),
					MATRIX_LANSECH_NS(0));

	/* Enable USB for NS access */
	matrix_configure_slave_security(MATRIX_SLAVE_USB,
					MATRIX_SRTOP(0, MATRIX_SRTOP_VALUE_1M) |
					MATRIX_SRTOP(1, MATRIX_SRTOP_VALUE_1M),
					MATRIX_SASPLIT(0, MATRIX_SRTOP_VALUE_1M),
					MATRIX_LANSECH_NS(0));

	/* TZC: DDR accesess through CSS (128bit) */
	lan969x_tzc_configure(LAN969X_TZC_CSS_BASE, css_rules, ARRAY_SIZE(css_rules));

	/* TZC: DDR access through HSS/HMATRIX (64bit) */
	lan969x_tzc_configure(LAN969X_TZC_MAIN_HSS_BASE, hss_rules, ARRAY_SIZE(hss_rules));
}

void lan969x_tz_finish(void)
{
	uintptr_t tzpm = LAN969X_TZPM_BASE;

	/* Reset Silex SRAM */
	memset((void*) LAN969X_SILEX_RAM_BASE, 0, LAN969X_SILEX_RAM_SIZE);

	/* Magic key to unlock protection */
	mmio_write_32(TZPM_TZPM_KEY(tzpm), 0x12AC4B5D);
	mmio_setbits_32(TZPM_TZPCTL0(tzpm),
			TZPM_TZPCTL0_QSPI0(1) |
			TZPM_TZPCTL0_QSPI2(1) |
			TZPM_TZPCTL0_MCAN0(1) |
			TZPM_TZPCTL0_MCAN1(1) |
			TZPM_TZPCTL0_SDMMC0(1) |
			TZPM_TZPCTL0_SDMMC1(1));
	mmio_setbits_32(TZPM_TZPCTL1(tzpm),
			TZPM_TZPCTL1_XDMA(1) |
			TZPM_TZPCTL1_FLEXCOM0(1) |
			TZPM_TZPCTL1_FLEXCOM1(1) |
			TZPM_TZPCTL1_FLEXCOM2(1) |
			TZPM_TZPCTL1_FLEXCOM3(1));
	mmio_setbits_32(TZPM_TZPCTL2(tzpm),
			TZPM_TZPCTL2_PKE(1));
	mmio_setbits_32(TZPM_TZPCTL3(tzpm),
			TZPM_TZPCTL3_FDMA(1));
	/* Reset key to reestablish protection */
	mmio_write_32(TZPM_TZPM_KEY(tzpm), 0);
}
