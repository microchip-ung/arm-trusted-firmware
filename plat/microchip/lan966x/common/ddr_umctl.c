/*
 * Copyright (C) 2022 Microchip Technology Inc. and its subsidiaries.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <errno.h>

#include <ddr_init.h>
#include <ddr_reg.h>
#include <ddr_test.h>
#include <ddr_xlist.h>
#include <platform_def.h>

#define PGSR_ERR_MASK		GENMASK_32(27, 20)
#define PGSR_ALL_DONE		GENMASK_32(11, 0)

#define TIME_MS_TO_US(ms)	(ms * 1000U)
#define PHY_TIMEOUT_US_1S	TIME_MS_TO_US(1000U)

#define DDR_FAILURE(...) do { \
	snprintf(ddr_failure_details, sizeof(ddr_failure_details), __VA_ARGS__); \
	ERROR("%s\n", ddr_failure_details);				\
	} while (0)
char ddr_failure_details[132];

static uint32_t ddr_size;

static const struct {
	uint32_t mask;
	const char *desc;
} phyerr[] = {
	{ PGSR0_ZCERR, "Impedance Calibration" },
	{ PGSR0_WLERR, "Write Leveling" },
	{ PGSR0_QSGERR, "DQS Gate Training" },
	{ PGSR0_WLAERR, "Write Leveling Adjustment" },
	{ PGSR0_RDERR, "Read Bit Deskew" },
	{ PGSR0_WDERR, "Write Bit Deskew" },
	{ PGSR0_REERR, "Read Eye Training" },
	{ PGSR0_WEERR, "Write Eye Training" },
};

struct reg_desc {
	uintptr_t reg_addr;
	uint8_t par_offset;	/* Offset for parameter array */
};

#define X(x, y, z)							\
	{								\
		.reg_addr  = y,						\
		.par_offset = offsetof(struct config_ddr_##z, x),	\
	},

static const struct reg_desc ddr_main_reg[] = {
	XLIST_DDR_MAIN
};

static const struct reg_desc ddr_timing_reg[] = {
	XLIST_DDR_TIMING
};

static const struct reg_desc ddr_mapping_reg[] = {
	XLIST_DDR_MAPPING
};

static const struct reg_desc ddr_phy_reg[] = {
	XLIST_DDR_PHY
};

static const struct reg_desc ddr_phy_timing_reg[] = {
	XLIST_DDR_PHY_TIMING
};

static bool wait_reg_set(uintptr_t reg, uint32_t mask, int usec)
{
	uint64_t t = timeout_init_us(usec);
	while ((mmio_read_32(reg) & mask) == 0) {
		if (timeout_elapsed(t)) {
			NOTICE("Timeout waiting for %p mask %08x set\n", (void*)reg, mask);
			return true;
		}
	}
	return false;
}

static bool wait_reg_clr(uintptr_t reg, uint32_t mask, int usec)
{
	uint64_t t = timeout_init_us(usec);
	while ((mmio_read_32(reg) & mask) != 0) {
		if (timeout_elapsed(t)) {
			NOTICE("Timeout waiting for %p mask %08x clr\n", (void*)reg, mask);
			return true;
		}
	}
	return false;
}

static void wait_operating_mode(uint32_t mode, int usec)
{
	uint64_t t = timeout_init_us(usec);
	while ((FIELD_GET(STAT_OPERATING_MODE,
			  mmio_read_32(DDR_UMCTL2_STAT))) != mode) {
		if (timeout_elapsed(t)) {
			PANIC("Timeout waiting for mode %d\n", mode);
		}
	}
}

static void set_regs(const struct ddr_config *ddr_cfg,
		     const void *cfg,
		     const struct reg_desc *reg,
		     size_t ct)
{
	int i;

	for (i = 0; i < ct; i++) {
		uint32_t val = ((const uint32_t *)cfg)[reg[i].par_offset >> 2];
		mmio_write_32(reg[i].reg_addr, val);
	}
}

static void set_static_ctl(void)
{
	/* Disabling update request initiated by DDR controller during
	 * DDR initialization */
	mmio_setbits_32(DDR_UMCTL2_DFIUPD0,
			DFIUPD0_DIS_AUTO_CTRLUPD_SRX | DFIUPD0_DIS_AUTO_CTRLUPD);
}

/*
 * This mirrors the PHY mrX fields from the controller initX registers
 * to avoid having both in the configuration strcuture.
 */
static void set_mrx_phy(const struct ddr_config *cfg)
{
	mmio_write_32(DDR_PHY_MR0,
		      FIELD_GET(INIT3_MR, cfg->main.init3));
	mmio_write_32(DDR_PHY_MR1,
		      FIELD_GET(INIT3_EMR, cfg->main.init3));
	mmio_write_32(DDR_PHY_MR2,
		      FIELD_GET(INIT4_EMR2, cfg->main.init4));
	mmio_write_32(DDR_PHY_MR3,
		      FIELD_GET(INIT4_EMR3, cfg->main.init4));
}

static void set_static_phy(const struct ddr_config *cfg)
{
	/* Disabling PHY initiated update request during DDR
	 * initialization */
	mmio_clrbits_32(DDR_PHY_DSGCR, DSGCR_PUREN);
	/* Enable data lanes according to configured bus width */
	switch (cfg->info.bus_width) {
	case 16:
		/* Enable two first lanes */
		mmio_setbits_32(DDR_PHY_DX0GCR, DX0GCR_DX0_DXEN);
		mmio_setbits_32(DDR_PHY_DX1GCR, DX1GCR_DX1_DXEN);
		break;
	case 8:
		/* Enable first lane */
		mmio_setbits_32(DDR_PHY_DX0GCR, DX0GCR_DX0_DXEN);
		/* Disable un-used upper byte lanes */
		mmio_clrbits_32(DDR_PHY_DX1GCR, DX1GCR_DX1_DXEN);
		break;
	default:
		PANIC("Unsupported bus width: %d\n", cfg->info.bus_width);
		break;
	}
}

static void axi_enable_ports(bool enable)
{
	if (enable) {
		/* Enable controller port(s) */
		mmio_setbits_32(DDR_UMCTL2_PCTRL_0, PCTRL_0_PORT_EN);
		mmio_setbits_32(DDR_UMCTL2_PCTRL_1, PCTRL_1_PORT_EN);
		mmio_setbits_32(DDR_UMCTL2_PCTRL_2, PCTRL_2_PORT_EN);
	} else {
		/* Disable controller port(s) */
		mmio_clrbits_32(DDR_UMCTL2_PCTRL_0, PCTRL_0_PORT_EN);
		mmio_clrbits_32(DDR_UMCTL2_PCTRL_1, PCTRL_1_PORT_EN);
		mmio_clrbits_32(DDR_UMCTL2_PCTRL_2, PCTRL_2_PORT_EN);
	}
}

static int ecc_enable_scrubbing(const struct ddr_config *cfg)
{
	uint32_t size = (cfg->info.size - 1) >> 1;

	VERBOSE("Enable ECC scrubbing\n");

	/* 1.  Disable AXI port. port_en = 0 */
	axi_enable_ports(false);

	/* 2. scrub_mode = 1 */
	mmio_setbits_32(DDR_UMCTL2_SBRCTL, SBRCTL_SCRUB_MODE);

	/* 3. scrub_interval = 0 */
	mmio_clrbits_32(DDR_UMCTL2_SBRCTL, SBRCTL_SCRUB_INTERVAL);

	/* 4. Data pattern = 0 */
	mmio_write_32(DDR_UMCTL2_SBRWDATA0, 0);

	/* 5. Address range */
	mmio_write_32(DDR_UMCTL2_SBRSTART0, 0);
	mmio_write_32(DDR_UMCTL2_SBRRANGE0, size); /* 16bit words */
	mmio_write_32(DDR_UMCTL2_SBRSTART1, 0);
	mmio_write_32(DDR_UMCTL2_SBRRANGE1, 0);

	/* 6. Enable SBR programming */
	mmio_setbits_32(DDR_UMCTL2_SBRCTL, SBRCTL_SCRUB_EN);

	/* 7. Poll SBRSTAT.scrub_done */
	if (wait_reg_set(DDR_UMCTL2_SBRSTAT, SBRSTAT_SCRUB_DONE, 10000000)) {
		DDR_FAILURE("Timeout: SBRSTAT.done not set: 0x%0x\n",
			    mmio_read_32(DDR_UMCTL2_SBRSTAT));
		return -ETIMEDOUT;
	}

	/* 8. Poll SBRSTAT.scrub_busy */
	if (wait_reg_clr(DDR_UMCTL2_SBRSTAT, SBRSTAT_SCRUB_BUSY, 50)) {
		DDR_FAILURE("Timeout: SBRSTAT.busy not clear: 0x%0x\n",
			    mmio_read_32(DDR_UMCTL2_SBRSTAT));
		return -ETIMEDOUT;
	}

	/* 9. Disable SBR programming */
	mmio_clrbits_32(DDR_UMCTL2_SBRCTL, SBRCTL_SCRUB_EN);

	VERBOSE("Initial ECC scrubbing done\n");

#if 0
	/* 10+11: Enable SBR programming again if enabled and interval != 0 */
	if (cfg->main.sbrctl & SBRCTL_SCRUB_EN &&
	    FIELD_GET(SBRCTL_SCRUB_INTERVAL, cfg->main.sbrctl) != 0) {
		mmio_write_32(DDR_UMCTL2_SBRCTL, cfg->main.sbrctl);
		VERBOSE("Enabled ECC scrubbing\n");
	}
#endif

	/* 12. Enable AXI port */
	axi_enable_ports(true);

	return 0;
}

static int wait_phy_idone(int tmo)
{
	uint32_t pgsr;
	uint64_t t;
	int i;

	t = timeout_init_us(tmo);

	do {
		pgsr = mmio_read_32(DDR_PHY_PGSR0);

		if (pgsr & PGSR_ERR_MASK) {
			for (i = 0; i < ARRAY_SIZE(phyerr); i++) {
				if (pgsr & phyerr[i].mask) {
					DDR_FAILURE("PHYERR: %s Error", phyerr[i].desc);
					return -EIO;
				}
			}
		}

		if (pgsr & PGSR0_IDONE)
			return 0;

	} while(!timeout_elapsed(t));

	DDR_FAILURE("PHY IDONE timeout");
	return -ETIMEDOUT;
}

static int ddr_phy_init(uint32_t mode, int usec_timout)
{
	int rc;

	mode |= PIR_INIT;

	VERBOSE("ddr_phy_init:start\n");

	/* Now, kick PHY */
	mmio_write_32(DDR_PHY_PIR, mode);

	VERBOSE("pir = 0x%x -> 0x%x\n", mode, mmio_read_32(DDR_PHY_PIR));

	/* Need to wait 10 configuration clock before start polling */
	ddr_nsleep(10);

	rc = wait_phy_idone(usec_timout);

	VERBOSE("ddr_phy_init:exit = %d\n", rc);

	return rc;
}

static int PHY_initialization(void)
{
	/* PHY initialization: PLL initialization, Delay line
	 * calibration, PHY reset and Impedance Calibration
	 */
	return ddr_phy_init(PIR_ZCAL | PIR_PLLINIT | PIR_DCAL | PIR_PHYRST, PHY_TIMEOUT_US_1S);
}

static int DRAM_initialization(bool init_by_pub)
{
	uint32_t init_flags = init_by_pub ? PIR_DRAMRST | PIR_DRAMINIT : PIR_CTLDINIT;

	/* write PHY initialization register for PUB/UMCTL SDRAM initialization */
	return ddr_phy_init(init_flags, PHY_TIMEOUT_US_1S);
}

static void sw_done_start(void)
{
	/* Enter quasi-dynamic mode */
	mmio_write_32(DDR_UMCTL2_SWCTL, 0);
}

static void sw_done_ack(void)
{
	VERBOSE("sw_done_ack:enter\n");

	/* Signal we're done */
	mmio_write_32(DDR_UMCTL2_SWCTL, SWCTL_SW_DONE);

	/* wait for SWSTAT.sw_done_ack to become set */
	if (wait_reg_set(DDR_UMCTL2_SWSTAT, SWSTAT_SW_DONE_ACK, 50))
		PANIC("Timout SWSTAT.sw_done_ack set\n");

	VERBOSE("sw_done_ack:exit\n");
}

static void ddr_disable_refresh(void)
{
	sw_done_start();
	mmio_setbits_32(DDR_UMCTL2_RFSHCTL3, RFSHCTL3_DIS_AUTO_REFRESH);
	mmio_clrbits_32(DDR_UMCTL2_PWRCTL, PWRCTL_POWERDOWN_EN);
	mmio_clrbits_32(DDR_UMCTL2_DFIMISC, DFIMISC_DFI_INIT_COMPLETE_EN);
	sw_done_ack();
}

static void ddr_restore_refresh(uint32_t rfshctl3, uint32_t pwrctl)
{
	sw_done_start();
	if ((rfshctl3 & RFSHCTL3_DIS_AUTO_REFRESH) == 0)
		mmio_clrbits_32(DDR_UMCTL2_RFSHCTL3, RFSHCTL3_DIS_AUTO_REFRESH);
	if (pwrctl & PWRCTL_POWERDOWN_EN)
		mmio_setbits_32(DDR_UMCTL2_PWRCTL, PWRCTL_POWERDOWN_EN);
	mmio_setbits_32(DDR_UMCTL2_DFIMISC, DFIMISC_DFI_INIT_COMPLETE_EN);
	sw_done_ack();
}

static int do_data_training(const struct ddr_config *cfg)
{
	int rc;
	uint32_t w;

	VERBOSE("do_data_training:enter\n");

	/* Disable Auto refresh and power down before training */
	ddr_disable_refresh();

	/* Write leveling, DQS gate training, Write_latency adjustment must be executed in
	 * asynchronous read mode. After these training are finished, then static read mode
	 * can be set and rest of the training can be executed with a second PIR register.
	 */

	/* write PHY initialization register for Write leveling, DQS
	 * gate training, Write_latency adjustment
	 */
	rc = ddr_phy_init(PIR_WL | PIR_QSGATE | PIR_WLADJ, PHY_TIMEOUT_US_1S);
	if (rc)
		return rc;

	/* Now, actual data training */
	w = PIR_WREYE | PIR_RDEYE | PIR_WRDSKW | PIR_RDDSKW;
	rc = ddr_phy_init(w, PHY_TIMEOUT_US_1S);
	if (rc)
		return rc;

	w = mmio_read_32(DDR_PHY_PGSR0);
	if ((w & PGSR_ALL_DONE) != PGSR_ALL_DONE) {
		DDR_FAILURE("data training error: pgsr0: got %08x, want %08x\n", w, PGSR_ALL_DONE);
		return -EIO;
	}

	ddr_restore_refresh(cfg->main.rfshctl3, cfg->main.pwrctl);

	/* Reenabling uMCTL2 initiated update request after executing
	 * DDR initization. Reference: DDR4 MultiPHY PUB databook
	 * (3.11a) PIR.INIT description (pg no. 114)
	 */
	sw_done_start();
	mmio_clrbits_32(DDR_UMCTL2_DFIUPD0, DFIUPD0_DIS_AUTO_CTRLUPD);
	sw_done_ack();

	/* Reenabling PHY update Request after executing DDR
	 * initization. Reference: DDR4 MultiPHY PUB databook (3.11a)
	 * PIR.INIT description (pg no. 114)
	 */
	mmio_setbits_32(DDR_PHY_DSGCR, DSGCR_PUREN);

	/* Enable AXI port(s) */
	axi_enable_ports(true);

	/* Settle */
	ddr_usleep(1);

	VERBOSE("do_data_training:exit\n");

	return 0;
}

int ddr_init(const struct ddr_config *cfg)
{
	int ret;

	strlcpy(ddr_failure_details, "No error", sizeof(ddr_failure_details));

	VERBOSE("ddr_init:start\n");

	NOTICE("DDR: %s, %d MHz, %dMiB, ECC %s\n", cfg->info.name,
	       cfg->info.speed,
	       cfg->info.size / 1024 / 1024,
	       cfg->main.ecccfg0 & ECCCFG0_ECC_MODE ? "enabled" : "disabled");

	/* Reset, start clocks at desired speed */
	ret = ddr_reset(cfg, true);
	if (ret)
		return ret;

	/* Set up platform specific registers */
	mmio_write_32(DDR_UMCTL2_SARBASE0, LAN966X_DDR_BASE >> 29);
	mmio_write_32(DDR_UMCTL2_SARSIZE0, 3); /* n+1 512M blocks = 2G (max) */

	/* Set up controller registers */
	set_regs(cfg, &cfg->main, ddr_main_reg, ARRAY_SIZE(ddr_main_reg));
	set_regs(cfg, &cfg->timing, ddr_timing_reg, ARRAY_SIZE(ddr_timing_reg));
	set_regs(cfg, &cfg->mapping, ddr_mapping_reg, ARRAY_SIZE(ddr_mapping_reg));

	/* Static controller settings */
	set_static_ctl();

	/* Release reset */
	ret = ddr_reset(cfg, false);
	if (ret)
		return ret;

	/* Set PHY registers */
	set_regs(cfg, &cfg->phy, ddr_phy_reg, ARRAY_SIZE(ddr_phy_reg));
	set_regs(cfg, &cfg->phy_timing, ddr_phy_timing_reg, ARRAY_SIZE(ddr_phy_timing_reg));

	/* Mirror PHY MRx registers */
	set_mrx_phy(cfg);

	/* Static PHY settings */
	set_static_phy(cfg);

	if (PHY_initialization()) {
		ERROR("PHY initization failed\n");
		return -EIO;
	}

	if (DRAM_initialization(true)) {
		ERROR("DDR initization failed\n");
		return -EIO;
	}

	/* Start quasi-dynamic programming */
	sw_done_start();

	/* PHY initialization complete enable: trigger SDRAM initialisation */
	mmio_setbits_32(DDR_UMCTL2_DFIMISC, DFIMISC_DFI_INIT_COMPLETE_EN);

	/* Signal quasi-dynamic phase end, await ack */
	sw_done_ack();

	/* wait 2ms for STAT.operating_mode to become "normal" */
	wait_operating_mode(1, TIME_MS_TO_US(2U));

	if (do_data_training(cfg)) {
		ERROR("Data training failed\n");
		return -EIO;
	}

	if (cfg->main.ecccfg0 & ECCCFG0_ECC_MODE) {
		if (ecc_enable_scrubbing(cfg)) {
			ERROR("ECC scrubbing init failed\n");
			return -EIO;
		}
	}

	VERBOSE("ddr_init:done\n");

	return 0;
}

int ddr_reset(const struct ddr_config *cfg , bool assert)
{
	VERBOSE("Reset: %sassert\n", assert ? "" : "de-");
	if (assert) {
		/* Assert resets */
		mmio_setbits_32(CPU_DDRCTRL_RST,
				DDRCTRL_RST_DDRC_RST |
				DDRCTRL_RST_DDR_AXI0_RST |
				DDRCTRL_RST_DDR_AXI1_RST |
				DDRCTRL_RST_DDR_AXI2_RST |
				DDRCTRL_RST_DDR_APB_RST |
				DDRCTRL_RST_DDRPHY_CTL_RST |
				DDRCTRL_RST_DDRPHY_APB_RST);

		/* Start the clocks */
		mmio_setbits_32(CPU_DDRCTRL_CLK,
				DDRCTRL_CLK_DDR_CLK_ENA |
				DDRCTRL_CLK_DDR_AXI0_CLK_ENA |
				DDRCTRL_CLK_DDR_AXI1_CLK_ENA |
				DDRCTRL_CLK_DDR_AXI2_CLK_ENA |
				DDRCTRL_CLK_DDR_APB_CLK_ENA |
				DDRCTRL_CLK_DDRPHY_CTL_CLK_ENA |
				DDRCTRL_CLK_DDRPHY_APB_CLK_ENA);

		/* Allow clocks to settle */
		ddr_nsleep(100);

		/* Deassert presetn once the clocks are active and stable */
		mmio_clrbits_32(CPU_DDRCTRL_RST, DDRCTRL_RST_DDR_APB_RST);

		ddr_nsleep(50);
	} else {
		ddr_nsleep(200);

		/* Deassert the core_ddrc_rstn reset */
		mmio_clrbits_32(CPU_RESET, RESET_MEM_RST);

		/* Deassert DDRC and AXI RST */
		mmio_clrbits_32(CPU_DDRCTRL_RST,
				DDRCTRL_RST_DDRC_RST |
				DDRCTRL_RST_DDR_AXI0_RST |
				DDRCTRL_RST_DDR_AXI1_RST |
				DDRCTRL_RST_DDR_AXI2_RST);

		/* Settle */
		ddr_nsleep(100);

		/* Deassert DDRPHY_APB_RST and DRPHY_CTL_RST */
		mmio_clrbits_32(CPU_DDRCTRL_RST,
				DDRCTRL_RST_DDRPHY_APB_RST | DDRCTRL_RST_DDRPHY_CTL_RST);

		ddr_nsleep(100);
	}
	VERBOSE("Reset: %sasserted\n", assert ? "" : "de-");

	return 0;
}

void lan966x_ddr_init(void)
{
	extern const struct ddr_config lan966x_ddr_config;
	const struct ddr_config *cfg =	&lan966x_ddr_config;
	uintptr_t err_off;

	if (ddr_init(cfg))
		PANIC("DDR initialization failed\n");

	err_off = ddr_test_data_bus(PLAT_LAN966X_NS_IMAGE_BASE, true);
	if (err_off != 0)
		PANIC("DDR data bus test @ 0x%08lx\n", err_off);

	err_off = ddr_test_addr_bus(PLAT_LAN966X_NS_IMAGE_BASE, PLAT_LAN966X_NS_IMAGE_SIZE, true);
	if (err_off != 0)
		PANIC("DDR address bus test @ 0x%08lx\n", err_off);

	ddr_size = cfg->info.size;
}

uint32_t lan966x_ddr_size(void)
{
	return ddr_size;
}
