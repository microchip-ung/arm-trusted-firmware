/*
 * Copyright (C) 2021 Microchip Technology Inc. and its subsidiaries.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stddef.h>
#include <assert.h>

#include <drivers/delay_timer.h>
#include <drivers/microchip/emmc.h>
#include <drivers/mmc.h>
#include <lib/mmio.h>

/* -------- SDMMC_BSR : (SDMMC Offset: 0x04) Block Size Register ---------- */
#define SDMMC_BSR	0x04	/* uint16_t */
#define   SDMMC_BSR_BLKSIZE_Pos 0
#define   SDMMC_BSR_BLKSIZE_Msk (0x3ffu << SDMMC_BSR_BLKSIZE_Pos)	/* Transfer Block Size */
#define   SDMMC_BSR_BLKSIZE(value) ((SDMMC_BSR_BLKSIZE_Msk & ((value) << SDMMC_BSR_BLKSIZE_Pos)))
/* -------- SDMMC_BCR : (SDMMC Offset: 0x06) Block Count Register --------- */
#define  SDMMC_BCR	0x06	/* uint16_t */
/* -------- SDMMC_ARG1R : (SDMMC Offset: 0x08) Argument 1 Register -------- */
#define  SDMMC_ARG1R	0x08	/* uint32_t */
/* -------- SDMMC_TMR : (SDMMC Offset: 0x0C) Transfer Mode Register ------- */
#define SDMMC_TMR	0x0C	/* uint16_t */
#define   SDMMC_TMR_DTDSEL_READ (0x1u << 4)	/* Reads data from the device to the SDMMC */
/* -------- SDMMC_CR : (SDMMC Offset: 0x0E) Command Register -------- */
#define SDMMC_CR	0x0E	/* uint16_t */
#define   SDMMC_CR_RESPTYP_Pos 0
#define   SDMMC_CR_RESPTYP_Msk (0x3u << SDMMC_CR_RESPTYP_Pos)	/* Response Type */
#define   SDMMC_CR_RESPTYP_NORESP (0x0u << 0)	/* No Response */
#define   SDMMC_CR_RESPTYP_RL136 (0x1u << 0)	/* Response Length 136 */
#define   SDMMC_CR_RESPTYP_RL48 (0x2u << 0)	/* Response Length 48 */
#define   SDMMC_CR_RESPTYP_RL48BUSY (0x3u << 0)	/* Response Length 48 with Busy */
#define   SDMMC_CR_CMDCCEN (0x1u << 3)	/* Command CRC Check Enable */
#define   SDMMC_CR_CMDICEN (0x1u << 4)	/* Command Index Check Enable */
#define   SDMMC_CR_DPSEL (0x1u << 5)	/* Data Present Select */
#define   SDMMC_CR_CMDTYP_NORMAL (0x0u << 6)	/* Other commands */
#define   SDMMC_CR_CMDTYP_ABORT (0x3u << 6)	/* CMD12, CMD52 to write "I/O Abort" in the Card Common Control Registers (CCCR) (for SDIO only) */
#define   SDMMC_CR_CMDIDX_Pos 8
#define   SDMMC_CR_CMDIDX_Msk (0x3fu << SDMMC_CR_CMDIDX_Pos)	/* Command Index */
#define   SDMMC_CR_CMDIDX(value) ((SDMMC_CR_CMDIDX_Msk & ((value) << SDMMC_CR_CMDIDX_Pos)))
/* -------- SDMMC_RR[4] : (SDMMC Offset: 0x10) Response Register ----------- */
#define SDMMC_RR0	0x10	/* uint32_t / Response Reg[0] */
#define SDMMC_RR1	0x14	/* uint32_t / Response Reg[1] */
#define SDMMC_RR2	0x18	/* uint32_t / Response Reg[2] */
#define SDMMC_RR3	0x1C	/* uint32_t / Response Reg[3] */
/* -------- SDMMC_BDPR : (SDMMC Offset: 0x20) Buffer Data Port Register ---- */
#define SDMMC_BDPR	0x20	/* uint32_t */
/* -------- SDMMC_PSR : (SDMMC Offset: 0x24) Present State Register -------- */
#define SDMMC_PSR	0x24	/* uint32_t */
#define   SDMMC_PSR_CMDINHC (0x1u << 0)	/* Command Inhibit (CMD) */
#define   SDMMC_PSR_CMDINHD (0x1u << 1)	/* Command Inhibit (DAT) */
#define   SDMMC_PSR_DATLL_Pos 20
#define   SDMMC_PSR_DATLL_Msk (0xfu << SDMMC_PSR_DATLL_Pos)	/* DAT[3:0] Line Level */
/* -------- SDMMC_HC1R : (SDMMC Offset: 0x28) Host Control 1 Register ------ */
#define SDMMC_HC1R	0x28	/* uint8_t */
#define   SDMMC_HC1R_DW (0x1u << 1)	/* Data Width */
#define   SDMMC_HC1R_DW_1_BIT (0x0u << 1) /* 1-bit mode. */
#define   SDMMC_HC1R_DW_4_BIT (0x1u << 1) /* 4-bit mode. */
/* -------- SDMMC_PCR : (SDMMC Offset: 0x29) Power Control Register -------- */
#define SDMMC_PCR	0x29	/* uint8_t */
#define   SDMMC_PCR_SDBPWR (0x1u << 0)	/* SD Bus Power */
/* -------- SDMMC_CCR : (SDMMC Offset: 0x2C) Clock Control Register -------- */
#define SDMMC_CCR	0x2C	/* uint16_t */
#define   SDMMC_CCR_INTCLKEN (0x1u << 0)	/* (SDMMC_CCR) Internal Clock Enable */
#define   SDMMC_CCR_INTCLKS (0x1u << 1)	/* Internal Clock Stable */
#define   SDMMC_CCR_SDCLKEN (0x1u << 2)	/* SD Clock Enable */
#define   SDMMC_CCR_CLKGSEL (0x1u << 5)	/* Clock Generator Select */
#define   SDMMC_CCR_USDCLKFSEL_Pos 6
#define   SDMMC_CCR_USDCLKFSEL_Msk (0x3u << SDMMC_CCR_USDCLKFSEL_Pos)	/* Upper Bits of SDCLK Frequency Select */
#define   SDMMC_CCR_USDCLKFSEL(value) ((SDMMC_CCR_USDCLKFSEL_Msk & ((value) << SDMMC_CCR_USDCLKFSEL_Pos)))
#define   SDMMC_CCR_SDCLKFSEL_Pos 8
#define   SDMMC_CCR_SDCLKFSEL_Msk (0xffu << SDMMC_CCR_SDCLKFSEL_Pos)	/* SDCLK Frequency Select */
#define   SDMMC_CCR_SDCLKFSEL(value) ((SDMMC_CCR_SDCLKFSEL_Msk & ((value) << SDMMC_CCR_SDCLKFSEL_Pos)))
/* -------- SDMMC_TCR : (SDMMC Offset: 0x2E) Timeout Control Register -------- */
#define SDMMC_TCR	0x2E	/* uint8_t */
#define   SDMMC_TCR_DTCVAL_Pos 0
#define   SDMMC_TCR_DTCVAL_Msk (0xfu << SDMMC_TCR_DTCVAL_Pos)	/* (SDMMC_TCR) Data Timeout Counter Value */
#define   SDMMC_TCR_DTCVAL(value) ((SDMMC_TCR_DTCVAL_Msk & ((value) << SDMMC_TCR_DTCVAL_Pos)))
/* -------- SDMMC_SRR : (SDMMC Offset: 0x2F) Software Reset Register ------- */
#define SDMMC_SRR	0x2F	/* uint8_t */
#define   SDMMC_SRR_SWRSTALL (0x1u << 0)	/* Software reset for All */
#define   SDMMC_SRR_SWRSTCMD (0x1u << 1)	/* Software reset for CMD line */
#define   SDMMC_SRR_SWRSTDAT (0x1u << 2)	/* Software reset for DAT line */
/* -------- SDMMC_NISTR : (SDMMC Offset: 0x30) Normal Interrupt Status Register - */
#define SDMMC_NISTR	0x30	/* uint16_t  */
#define   SDMMC_NISTR_CMDC (0x1u << 0)	/* Command Complete */
#define   SDMMC_NISTR_TRFC (0x1u << 1)	/* Transfer Complete */
#define   SDMMC_NISTR_BRDRDY (0x1u << 5)	/* Buffer Read Ready */
#define   SDMMC_NISTR_ERRINT (0x1u << 15)	/* Error Interrupt */
/* -------- SDMMC_EISTR : (SDMMC Offset: 0x32) Error Interrupt Status Register -------- */
#define SDMMC_EISTR	0x32	/* uint16_t */
#define   SDMMC_EISTR_CMDTEO (0x1u << 0)	/* Command Timeout Error */
#define   SDMMC_EISTR_DATTEO (0x1u << 4)	/* Data Timeout Error */
/* -------- SDMMC_NISTER : (SDMMC Offset: 0x34) Normal Interrupt Status Enable Register -------- */
#define SDMMC_NISTER	0x34	/* uint16_t */
#define   SDMMC_NISTER_CMDC (0x1u << 0)	/* Command Complete Status Enable */
#define   SDMMC_NISTER_TRFC (0x1u << 1)	/* Transfer Complete Status Enable */
#define   SDMMC_NISTER_BRDRDY (0x1u << 5)	/* Buffer Read Ready Status Enable */
/* -------- SDMMC_EISTER : (SDMMC Offset: 0x36) Error Interrupt Status Enable Register -------- */
#define SDMMC_EISTER	0x36	/* uint16_t */
#define   SDMMC_EISTER_DATTEO (0x1u << 4)	/* Data Timeout Error Status Enable */
#define   SDMMC_EISTER_DATCRC (0x1u << 5)	/* Data CRC Error Status Enable */
#define   SDMMC_EISTER_DATEND (0x1u << 6)	/* Data End Bit Error Status Enable */
/* -------- SDMMC_NISIER : (SDMMC Offset: 0x38) Normal Interrupt Signal Enable Register -------- */
#define SDMMC_NISIER	0x38	/* uint16_t */
#define   SDMMC_NISIER_BRDRDY (0x1u << 5)	/* Buffer Read Ready Signal Enable */
/* -------- SDMMC_EISIER : (SDMMC Offset: 0x3A) Error Interrupt Signal Enable Register -------- */
#define SDMMC_EISIER	0x3A	/* uint16_t */
#define   SDMMC_EISIER_DATTEO (0x1u << 4)	/* Data Timeout Error Signal Enable */
#define   SDMMC_EISIER_DATCRC (0x1u << 5)	/* Data CRC Error Signal Enable */
#define   SDMMC_EISIER_DATEND (0x1u << 6)	/* Data End Bit Error Signal Enable */
/* -------- SDMMC_CA0R : (SDMMC Offset: 0x40) Capabilities 0 Register ------ */
#define SDMMC_CA0R	0x40	/* uint32_t */
#define   SDMMC_CA0R_TEOCLKF_Pos 0
#define   SDMMC_CA0R_TEOCLKF_Msk (0x3fu << SDMMC_CA0R_TEOCLKF_Pos)	/* Timeout Clock Frequency */
#define   SDMMC_CA0R_TEOCLKU (0x1u << 7)	/* (SDMMC_CA0R) Timeout Clock Unit */
#define   SDMMC_CA0R_BASECLKF_Pos 8
#define   SDMMC_CA0R_BASECLKF_Msk (0xffu << SDMMC_CA0R_BASECLKF_Pos)	/* Base Clock Frequency */
/* -------- SDMMC_MC1R : (SDMMC Offset: 0x204) e.MMC Control 1 Register ---- */
#define SDMMC_MC1R	0x204	/* uint8_t */
#define   SDMMC_MC1R_CMDTYP_Pos 0
#define   SDMMC_MC1R_CMDTYP_Msk (0x3u << SDMMC_MC1R_CMDTYP_Pos)	/* e.MMC Command Type */
#define   SDMMC_MC1R_CMDTYP_NORMAL (0x0u << 0)	/* The command is not an e.MMC specific command. */
#define   SDMMC_MC1R_OPD (0x1u << 4)	/* e.MMC Open Drain Mode */
#define   SDMMC_MC1R_FCD (0x1u << 7)	/* e.MMC Force Card Detect */

static card p_card;
static uintptr_t reg_base;
static uint16_t eistr = 0u;	/* Holds the error interrupt status */
static bool resetDone = false;
static lan966x_mmc_params_t lan966x_params;

static const unsigned int TAAC_TimeExp[8] =
    { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000 };
static const unsigned int TAAC_TimeMant[16] =
    { 0, 10, 12, 13, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 70, 80 };

static void lan966x_clock_delay(unsigned int sd_clock_cycles)
{
	unsigned int usec;
	usec = DIV_ROUND_UP_2EVAL(sd_clock_cycles * 1000000u,
				  lan966x_params.clk_rate);
	udelay(usec);
}

static unsigned char lan966x_set_clk_freq(unsigned int SD_clock_freq,
					  unsigned int sd_src_clk)
{
	unsigned int timeout;
	unsigned short new_ccr, old_ccr;
	unsigned int clk_div, base_clock, mult_clock;

	timeout = 0x1000;
	while ((mmio_read_32(reg_base + SDMMC_PSR) & (SDMMC_PSR_CMDINHD | SDMMC_PSR_CMDINHC)) && --timeout > 0) ;	//Wait for transaction stop
	if (!timeout) {
		return 1;
	}

	/* Save current value of clock control register */
	old_ccr = mmio_read_16(reg_base + SDMMC_CCR);

	/* Clear CLK div, SD Clock Enable and Internal Clock Stable */
	new_ccr = old_ccr & ~(SDMMC_CCR_SDCLKFSEL_Msk |
			      SDMMC_CCR_USDCLKFSEL_Msk |
			      SDMMC_CCR_SDCLKEN | SDMMC_CCR_INTCLKS);

	switch (sd_src_clk) {
	case SDMMC_CLK_CTRL_DIV_MODE:
		/* Switch to divided clock mode, only for SR FPGA */
		base_clock = FPGA_SDMMC0_SRC_CLOCK;
		new_ccr &= ~SDMMC_CCR_CLKGSEL;

		if (SD_clock_freq == base_clock) {
			clk_div = 0;
		} else {
			clk_div = (((base_clock / SD_clock_freq) % 2) ?
				   (((base_clock / SD_clock_freq) + 1) / 2) :
				   ((base_clock / SD_clock_freq) / 2));
		}
		break;

	case SDMMC_CLK_CTRL_PROG_MODE:
		/* Switch to programmable clock mode, only for SR FPGA */
		mult_clock = FPGA_SDMMC0_MULTI_SRC_CLOCK;
		new_ccr |= SDMMC_CCR_CLKGSEL;

		if (SD_clock_freq == mult_clock) {
			clk_div = 0;
		} else {
			clk_div = DIV_ROUND_UP_2EVAL(mult_clock, SD_clock_freq) - 1;
		}
		break;

	default:
		return 1;
	}

	/* Set new clock divisor and enable only the internal clock */
	new_ccr |= (SDMMC_CCR_INTCLKEN |
		    SDMMC_CCR_SDCLKFSEL(clk_div) |
		    SDMMC_CCR_USDCLKFSEL(clk_div >> 8));

	/* New value of clock control reg has been calculated for update */
	/* Disable SD clock before setting new divisor (but not the internal clock) */
	mmio_write_16(reg_base + SDMMC_CCR, (old_ccr & ~(SDMMC_CCR_SDCLKEN)));

	/* Set new clock configuration */
	mmio_write_16(reg_base + SDMMC_CCR, new_ccr);

	/* Wait for internal clock to be stable */
	timeout = 0x100000;
	while (((mmio_read_16(reg_base + SDMMC_CCR) & SDMMC_CCR_INTCLKS) == 0)
	       && --timeout > 0) ;
	if (!timeout) {
		return 1;
	}

	/* Enable SD clock */
	mmc_setbits_16(reg_base + SDMMC_CCR, SDMMC_CCR_SDCLKEN);
	lan966x_params.clk_rate = SD_clock_freq;

	/* Wait for 74 SD clock cycles (according SD Card specification) */
	lan966x_clock_delay(74u);

	return 0;
}

static int lan966x_host_init(void)
{
	unsigned int timeout;

	lan966x_params.clk_rate = 0u;

	/* Set default values */
	p_card.card_type = SD_CARD;
	p_card.card_capacity = SD_CARD_SDSC;

	/* Reset Data and CMD line */
	mmc_setbits_8(reg_base + SDMMC_SRR, SDMMC_SRR_SWRSTALL);

	timeout = 0xFFFF;
	while ((mmio_read_8(reg_base + SDMMC_SRR) & SDMMC_SRR_SWRSTALL)
	       && ((timeout--) != 1)) ;
	if (timeout == 0) {
		return -1;
	}

	/* "SD Bus Power" init. */
	mmc_setbits_8(reg_base + SDMMC_PCR, SDMMC_PCR_SDBPWR);

	/* Set host controller data bus width to 4 bit */
	mmc_setbits_8(reg_base + SDMMC_HC1R, SDMMC_HC1R_DW_4_BIT);

	if (lan966x_set_clk_freq(SDCLOCK_400KHZ, SDMMC_CLK_CTRL_PROG_MODE)) {
		return -1;
	}

	return 0;
}

static void lan996x_mmc_initialize(void)
{
	int retVal;

	VERBOSE("EMMC: ATF CB init() \n");

	retVal = lan966x_host_init();
	assert(retVal == 0);
	
	/* Prevent compiler warning in release build */
	(void)retVal;
}

static void lan966x_get_cid_register(void)
{
	p_card.card_type = (mmio_read_32(reg_base + SDMMC_RR3) >> 8) & 0x03;
	p_card.card_manufacturer_id =
	    (mmio_read_32(reg_base + SDMMC_RR3) >> 16) & 0xFF;
	p_card.card_application_id =
	    (mmio_read_32(reg_base + SDMMC_RR3) >> 0) & 0xFF;
	p_card.card_product_name[0] =
	    (mmio_read_32(reg_base + SDMMC_RR1) >> 16) & 0xFF;
	p_card.card_product_name[1] =
	    (mmio_read_32(reg_base + SDMMC_RR1) >> 24) & 0xFF;
	p_card.card_product_name[2] =
	    (mmio_read_32(reg_base + SDMMC_RR2) >> 0) & 0xFF;
	p_card.card_product_name[3] =
	    (mmio_read_32(reg_base + SDMMC_RR2) >> 8) & 0xFF;
	p_card.card_product_name[4] =
	    (mmio_read_32(reg_base + SDMMC_RR2) >> 16) & 0xFF;
	p_card.card_product_name[5] =
	    (mmio_read_32(reg_base + SDMMC_RR2) >> 24) & 0xFF;
	p_card.card_product_revision =
	    (mmio_read_32(reg_base + SDMMC_RR1) >> 8) & 0xFF;
	p_card.card_product_sn[0] =
	    (mmio_read_32(reg_base + SDMMC_RR0) >> 8) & 0xFF;
	p_card.card_product_sn[1] =
	    (mmio_read_32(reg_base + SDMMC_RR0) >> 16) & 0xFF;
	p_card.card_product_sn[2] =
	    (mmio_read_32(reg_base + SDMMC_RR0) >> 24) & 0xFF;
	p_card.card_product_sn[3] =
	    (mmio_read_32(reg_base + SDMMC_RR1) >> 0) & 0xFF;
}

static void lan966x_get_csd_register(void)
{
	unsigned int m, e;
	unsigned int csd_struct;
	volatile const unsigned int *p_resp;

	/* Initialize pointer to response register RR[0] */
	p_resp = (unsigned int *)(reg_base + SDMMC_RR0);

	/* Retrieve version of CSD structure information */
	csd_struct = get_CSD_field(p_resp, 126, 2);

	switch (csd_struct) {
	case 0:
	case 2:
	case 3:
		e = get_CSD_field(p_resp, 112, 3);
		m = get_CSD_field(p_resp, 115, 4);
		p_card.card_taac_ns = TAAC_TimeExp[e] * TAAC_TimeMant[m] / 10;

		p_card.card_nsac = get_CSD_field(p_resp, 104, 8);
		p_card.card_r2w_factor = get_CSD_field(p_resp, 26, 3);
		p_card.card_max_rd_blk_len = get_CSD_field(p_resp, 80, 4);

		if (p_card.card_type == MMC_CARD) {
			if (get_CSD_field(p_resp, 122, 4) == 4) {
				p_card.card_phy_spec_rev =
				    MMC_CARD_PHY_SPEC_4_X;
			} else {
				p_card.card_phy_spec_rev =
				    MMC_CARD_PHY_SPEC_OLD;
			}
		}

		break;
	case 1:
		/* Settings from Linux drivers */
		p_card.card_taac_ns = 0;
		p_card.card_nsac = 0;
		p_card.card_r2w_factor = 4;
		p_card.card_max_rd_blk_len = 9;

		break;
	default:
		break;
	}
}

static unsigned char lan966x_emmc_poll(unsigned int expected)
{
	unsigned int trials = DIV_ROUND_UP_2EVAL(EMMC_POLLING_TIMEOUT,
						 EMMC_POLL_LOOP_DELAY);
	uint16_t nistr = 0u;

	eistr = 0u;
	while (trials--) {
		nistr = mmio_read_16(reg_base + SDMMC_NISTR);

		/* Check errors */
		if (nistr & SDMMC_NISTR_ERRINT) {
			eistr = mmio_read_16(reg_base + SDMMC_EISTR);

			/* Dump interrupt status values and variables */
			ERROR(" NISTR: 0x%x \n", nistr);
			ERROR(" NISTR expected: 0x%x \n", expected);
			ERROR(" EISTR: 0x%x \n", eistr);

			/* Clear Normal/Error Interrupt Status Register flags */
			mmio_write_16(reg_base + SDMMC_EISTR, eistr);
			mmio_write_16(reg_base + SDMMC_NISTR, nistr);
			return 1;
		}

		/* Wait for any expected flags */
		if (nistr & expected) {
			/* Clear only expected flags */
			mmio_write_16(reg_base + SDMMC_NISTR, expected);
			return 0;
		}

		udelay(EMMC_POLL_LOOP_DELAY);
	}
	return 1;
}

static void lan966x_set_data_timeout(unsigned int trans_type)
{
	unsigned timeout_freq;
	unsigned timeout_freq_fact;
	unsigned int clock_frequency;
	unsigned int clock_div;
	unsigned int mult;
	unsigned int timeout_val;
	unsigned int limit_us;
	unsigned int timeout_cyc;

	timeout_val = 0;

	/* SD cards use a 100 multiplier rather than 10 */
	mult = (p_card.card_type == SD_CARD) ? 100 : 10;

	mmc_clrbits_16(reg_base + SDMMC_EISTER, SDMMC_EISTER_DATTEO);
	mmc_clrbits_16(reg_base + SDMMC_EISIER, SDMMC_EISIER_DATTEO);

	if (p_card.card_type == MMC_CARD
	    || (p_card.card_type == SD_CARD
		&& p_card.card_capacity == SD_CARD_SDSC)) {
		/* Set base clock frequency in Mhz */
		clock_frequency =
		    (mmio_read_32(reg_base + SDMMC_CA0R) &
		     SDMMC_CA0R_BASECLKF_Msk) >> SDMMC_CA0R_BASECLKF_Pos;

		clock_div =
		    ((mmio_read_16(reg_base + SDMMC_CCR) &
		      SDMMC_CCR_SDCLKFSEL_Msk) >> SDMMC_CCR_SDCLKFSEL_Pos) |
		    (((mmio_read_16(reg_base + SDMMC_CCR) &
		       SDMMC_CCR_USDCLKFSEL_Msk) >> SDMMC_CCR_USDCLKFSEL_Pos) <<
		     8);

		/* Convert base clock frequency into sd clock frequency in KHz */
		clock_frequency = (clock_frequency * 1000) / (2 * clock_div);

		if (trans_type == SD_DATA_WRITE) {
			mult <<= p_card.card_r2w_factor;
		}

		/* Set timeout_val in micro seconds */
		timeout_val =
		    mult * ((p_card.card_taac_ns / 1000) +
			    (p_card.card_nsac * 100 * 1000 / clock_frequency));
	}

	if (p_card.card_type == SD_CARD && p_card.card_capacity == SD_CARD_SDSC) {
		if (trans_type == SD_DATA_WRITE) {
			/* The limit is 250 ms, but that is sometimes insufficient */
			limit_us = TIME_MSEC(300);

		} else {
			limit_us = TIME_MSEC(100);
		}

		if (timeout_val > limit_us) {
			/* Max read timeout = 100ms and max write timeout = 300ms */
			timeout_val = limit_us;
		}
	}

	if (p_card.card_type == SD_CARD
	    && p_card.card_capacity == SD_CARD_SDHC_SDXC) {
		if (trans_type == SD_DATA_WRITE) {
			/* Write timeout is 500ms for SDHC and SDXC */
			timeout_val = TIME_MSEC(500);
		} else {
			/* Read timeout is 100ms for SDHC and SDXC */
			timeout_val = TIME_MSEC(100);
		}
	}

	/* Convert timeout_val from micro seconds into ms */
	timeout_val = timeout_val / 1000;

	if ((mmio_read_32(reg_base + SDMMC_CA0R) & SDMMC_CA0R_TEOCLKU) ==
	    SDMMC_CA0R_TEOCLKU) {
		/* Set value of 1000, because "timeout_val" is in ms */
		timeout_freq_fact = 1000u;
	} else {
		/* Set value of 1, because "timeout_val" is in ms */
		timeout_freq_fact = 1u;
	}

	timeout_freq =
	    (mmio_read_32(reg_base + SDMMC_CA0R) & SDMMC_CA0R_TEOCLKF_Msk) *
	    timeout_freq_fact;
	timeout_cyc = timeout_val * timeout_freq;

	/* timeout_val will be re-used for the data timeout counter */
	timeout_val = 0;
	while (timeout_cyc > 0) {
		timeout_val++;
		timeout_cyc >>= 1;
	}

	/* Clearing Data Time Out Error Status bit before. */
	mmc_setbits_16(reg_base + SDMMC_EISTR, SDMMC_EISTR_DATTEO);
	mmio_write_8(reg_base + SDMMC_TCR, SDMMC_TCR_DTCVAL(timeout_val - 13));
}

static void lan996x_mmc_prepare_data_read(unsigned int trans_type)
{
	VERBOSE("EMMC: lan996x_mmc_prepare_data_read() \n");

	lan966x_set_data_timeout(trans_type);

	mmio_write_16(reg_base + SDMMC_TMR, SDMMC_TMR_DTDSEL_READ);
	mmio_write_16(reg_base + SDMMC_BSR, SDMMC_BSR_BLKSIZE(MAX_BLOCK_SIZE));
	mmc_setbits_16(reg_base + SDMMC_NISTER, SDMMC_NISTER_BRDRDY);

	mmc_setbits_16(reg_base + SDMMC_EISTER, SDMMC_EISTER_DATTEO);
	mmc_setbits_16(reg_base + SDMMC_EISIER, SDMMC_EISIER_DATTEO);
}

static int lan996x_mmc_send_cmd(struct mmc_cmd *cmd)
{
	unsigned short emmcRegVal, cmdRegVal;
	unsigned int is_busy_resp, timeout, not_ready;
	unsigned int op;

	VERBOSE("EMMC: ATF CB send_cmd() %d \n", cmd->cmd_idx);

	/* The first received CMD will trigger the one time software reset stage */
	if (!resetDone) {
		VERBOSE("EMMC: Software reset \n");

		/* Reset CMD and DATA lines */
		timeout = 0x10000;
		mmio_write_8(reg_base + SDMMC_SRR,
			     (SDMMC_SRR_SWRSTCMD | SDMMC_SRR_SWRSTDAT));
		while (mmio_read_8(reg_base + SDMMC_SRR) && --timeout > 0) ;

		resetDone = true;
	}

	/* Parse CMD argument and set proper flags */
	switch (cmd->cmd_idx) {
	case 0:
		op = SDMMC_SD_CMD0;
		break;
	case 1:
		op = SDMMC_SD_CMD1;
		break;
	case 2:
		op = SDMMC_MMC_CMD2;
		break;
	case 3:
		op = SDMMC_MMC_CMD3;
		break;
	case 6:
		lan996x_mmc_prepare_data_read(SD_DATA_READ);
		op = SDMMC_MMC_CMD6;
		break;
	case 7:
		lan966x_set_data_timeout(SD_DATA_WRITE);
		op = SDMMC_MMC_CMD7;
		break;
	case 8:
		lan996x_mmc_prepare_data_read(SD_DATA_READ);
		op = SDMMC_MMC_CMD8;
		break;
	case 9:
		op = SDMMC_MMC_CMD9;
		break;
	case 12:
		op = SDMMC_MMC_CMD12;
		break;
	case 13:
		op = SDMMC_MMC_CMD13;
		break;
	case 16:
		op = SDMMC_MMC_CMD16;
		break;
	case 17:
		op = SDMMC_MMC_CMD17;
		break;
	case 18:
		op = SDMMC_MMC_CMD18;
		break;
	case 51:
		op = SDMMC_SD_ACMD51;
		break;
	case 55:
		op = SDMMC_SD_CMD55;
		break;
	default:
		op = 0u;
		ERROR("EMMC: Unsupported Command ID : %d \n", cmd->cmd_idx);
		break;
	}

	cmdRegVal = op & 0xFFFF;
	is_busy_resp =
	    ((cmdRegVal & SDMMC_CR_RESPTYP_Msk) == SDMMC_CR_RESPTYP_RL48BUSY);

	/* Configure Normal and Error Interrupt Status Enable Registers */
	mmc_setbits_16(reg_base + SDMMC_NISTER,
		       (SDMMC_NISTER_CMDC | SDMMC_NISTER_TRFC));
	mmio_write_16(reg_base + SDMMC_EISTER, ALL_FLAGS);

	/* Clear all the Normal/Error Interrupt Status Register flags */
	mmio_write_16(reg_base + SDMMC_NISTR, ALL_FLAGS);
	mmio_write_16(reg_base + SDMMC_EISTR, ALL_FLAGS);

	/* Prepare masks */
	not_ready = SDMMC_PSR_CMDINHC;
	if ((cmdRegVal & SDMMC_CR_DPSEL) || is_busy_resp) {
		not_ready |= SDMMC_PSR_CMDINHD;
	}

	/* Wait for CMD and DATn lines becomes ready */
	timeout = 0x1000;
	while ((mmio_read_32(reg_base + SDMMC_PSR) & not_ready)
	       && (--timeout > 0)) ;
	if (!timeout) {
		return 1;
	}

	/* Send command */
	emmcRegVal = mmio_read_8(reg_base + SDMMC_MC1R);
	emmcRegVal &= ~(SDMMC_MC1R_CMDTYP_Msk | SDMMC_MC1R_OPD);	//Clear MMC command type and Open Drain fields
	emmcRegVal |= ((op >> 16) & 0xFFFF);
	emmcRegVal |= SDMMC_MC1R_FCD;	// Set ForceCardDetect flag (eMMC mode)

#if 0
	VERBOSE("===> Process command ID: %d \n", cmd->cmd_idx);
	VERBOSE(" SDMMC_ARG1R: 0x%x \n", cmd->cmd_arg);
	VERBOSE(" SDMMC_CR: 0x%x \n", cmdRegVal);
	VERBOSE(" SDMMC_MC1R: 0x%x \n", emmcRegVal);
#endif

	mmio_write_8(reg_base + SDMMC_MC1R, emmcRegVal);
	mmio_write_32(reg_base + SDMMC_ARG1R, cmd->cmd_arg);
	mmio_write_16(reg_base + SDMMC_CR, cmdRegVal);

	/* Poll Interrupt Status Register, wait for command completion */
	if (lan966x_emmc_poll(SDMMC_NISTR_CMDC)) {
		ERROR("Command completion of CMD: %d failed !!! \n",
		      cmd->cmd_idx);
		return 1;
	}

	/* Trigger CMD specific actions after sent */
	switch (cmd->cmd_idx) {
	case 0:
		// No response handling needed
		break;
	case 1:
		cmd->resp_data[0] = mmio_read_32(reg_base + SDMMC_RR0);
		p_card.card_type = MMC_CARD;
		if ((cmd->resp_data[0] & MMC_CARD_ACCESS_MODE_msk) ==
		    MMC_CARD_ACCESS_MODE_SECTOR) {
			p_card.card_capacity = MMC_HIGH_DENSITY;
			// VERBOSE("HIGH DENSITY MMC \n");
		} else {
			p_card.card_capacity = MMC_NORM_DENSITY;
			// VERBOSE("NORMAL DENSITIY MMC \n");
		}
		break;
	case 2:
		lan966x_get_cid_register();
		break;
	case 3:
	case 6:
	case 7:
	case 8:
	case 12:
	case 13:
	case 17:
	case 18:
	case 55:
		cmd->resp_data[0] = mmio_read_32(reg_base + SDMMC_RR0);
		break;
	case 9:
		cmd->resp_data[3] =
		    (mmio_read_32(reg_base + SDMMC_RR3) << 8) |
		    (mmio_read_32(reg_base + SDMMC_RR2) >> 24);
		cmd->resp_data[2] =
		    (mmio_read_32(reg_base + SDMMC_RR2) << 8) |
		    (mmio_read_32(reg_base + SDMMC_RR1) >> 24);
		cmd->resp_data[1] =
		    (mmio_read_32(reg_base + SDMMC_RR1) << 8) |
		    (mmio_read_32(reg_base + SDMMC_RR0) >> 24);
		cmd->resp_data[0] = (mmio_read_32(reg_base + SDMMC_RR0) << 8);
		lan966x_get_csd_register();
		break;
	default:
		ERROR(" CMD Id %d not supported ! \n", cmd->cmd_idx);
		assert(false);
		break;
	}

	return 0;
}

static int lan966x_recover_error(unsigned int error_int_status)
{
	struct mmc_cmd cmd;
	unsigned int sd_status;

	VERBOSE("EMMC: recover from error() \n");

	/* Perform software reset CMD */
	mmc_setbits_8(reg_base + SDMMC_SRR, SDMMC_SRR_SWRSTCMD);
	/* Wait for command reset done */
	while (mmio_read_8(reg_base + SDMMC_SRR) & SDMMC_SRR_SWRSTCMD) ;

	/* Perform software reset DAT */
	mmc_setbits_8(reg_base + SDMMC_SRR, SDMMC_SRR_SWRSTDAT);
	/* Wait for data reset done */
	while (mmio_read_8(reg_base + SDMMC_SRR) & SDMMC_SRR_SWRSTDAT) ;

	/* Set data timeout */
	lan966x_set_data_timeout(SD_DATA_WRITE);

	// Send CMD12 : Abort transaction
	cmd.cmd_idx = 12u;
	cmd.cmd_arg = 0u;
	cmd.resp_type = 0u;

	if (lan996x_mmc_send_cmd(&cmd)) {
		/* No response from SD card to CMD12 */
		if (eistr & SDMMC_EISTR_CMDTEO) {
			/* Perform software reset */
			mmc_setbits_8(reg_base + SDMMC_SRR, SDMMC_SRR_SWRSTCMD);
			/* Wait till reset is done */
			while (mmio_read_8(reg_base + SDMMC_SRR) &
			       SDMMC_SRR_SWRSTCMD) ;

			sd_status = mmio_read_32(reg_base + SDMMC_RR0);

			if ((sd_status & SD_STATUS_CURRENT_STATE_msk) !=
			    STATUS_CURRENT_STATE(MMC_STATE_TRAN)) {
				//ERROR("Unrecoverable error : SDMMC_Error_Status = %d\n ",SDMMC_error);
				return 1;
			} else {
				//ERROR("Unrecoverable error : SDMMC_Error_Status = %d\n ",SDMMC_error);
				return 1;
			}
		}
	}

	if ((mmio_read_32(reg_base + SDMMC_PSR) & SDMMC_PSR_DATLL_Msk) !=
	    SDMMC_PSR_DATLL_Msk) {
		return 1;
	}

	return 0;
}

static int lan996x_mmc_set_ios(unsigned int clk, unsigned int width)
{
	VERBOSE("EMMC: ATF CB set_ios() \n");

	return 0;
}

static int lan996x_mmc_prepare(int lba, uintptr_t buf, size_t size)
{
	VERBOSE("EMMC: ATF CB prepare() \n");

	return 0;
}

static int lan996x_mmc_read(int lba, uintptr_t buf, size_t size)
{
	unsigned int i;
	unsigned int *pExtBuffer = (unsigned int *)buf;

	VERBOSE("EMMC: ATF CB read() \n");

	if (!SD_CARD_STATUS_SUCCESS(mmio_read_32(reg_base + SDMMC_RR0))) {
		ERROR("Error on CMD8 command : SD Card Status = 0x%x\n",
		      mmio_read_32(reg_base + SDMMC_RR0));
		return 1;
	}

	if (lan966x_emmc_poll(SDMMC_NISTR_BRDRDY)) {
		ERROR("Error on CMD8, BRDRDY is not read \n");
		return 1;
	}

	for (i = 0; i < (size / 4); i++) {
		*pExtBuffer = mmio_read_32(reg_base + SDMMC_BDPR);
		pExtBuffer++;
	}

	if (lan966x_emmc_poll(SDMMC_NISTR_TRFC)) {
		lan966x_recover_error(eistr);
		return 1;
	}

	return 0;
}

static int lan996x_mmc_write(int lba, uintptr_t buf, size_t size)
{
	VERBOSE("EMMC: ATF CB write() not implemented \n");

	return 0;
}

size_t lan966x_read_single_block(int block_number,
				 uintptr_t dest_buffer, size_t block_size)
{
	size_t retSize;

	/* Enable read buffer ready status */
	mmc_setbits_16(reg_base + SDMMC_NISTER, SDMMC_NISTER_BRDRDY);

	if (p_card.card_capacity == SD_CARD_SDSC) {
		/* Read Block partial is always enabled in SDSC */
		if (block_size > (1 << p_card.card_max_rd_blk_len)) {
			ERROR
			    ("Block size is greater than Read Maximum block length \n");
			return 1;
		}
	} else {
		/* the connected SD card is of type SDHC (not SDSC). Only 512 bytes. */
		if (block_size != MAX_BLOCK_SIZE) {
			ERROR("Block size must be 512 bytes\n\r");
			return 1;
		}
	}

	mmio_write_16(reg_base + SDMMC_BSR, SDMMC_BSR_BLKSIZE(block_size));

	/* Set read single block in the transfer mode register */
	mmio_write_16(reg_base + SDMMC_TMR, SDMMC_TMR_DTDSEL_READ);

	lan966x_set_data_timeout(SD_DATA_READ);

	/* Enable flags related to transfer data error */
	mmc_setbits_16(reg_base + SDMMC_EISTER,
		       (SDMMC_EISTER_DATTEO | SDMMC_EISTER_DATCRC |
			SDMMC_EISTER_DATEND));

	/* Disable any related IRQ (Only polling for RomCode) */
	mmc_clrbits_16(reg_base + SDMMC_EISIER,
		       (SDMMC_EISIER_DATTEO | SDMMC_EISIER_DATCRC |
			SDMMC_EISIER_DATEND));

	/* Disable Buffer Read Ready IRQ */
	mmc_clrbits_16(reg_base + SDMMC_NISIER, SDMMC_NISIER_BRDRDY);

	mmc_setbits_16(reg_base + SDMMC_NISTER,
		       (SDMMC_NISTER_BRDRDY | SDMMC_NISTER_CMDC));

	/* Call ATF read block function */
	retSize = mmc_read_blocks(block_number, (uintptr_t) dest_buffer, block_size);
	if (retSize == 0u) {
		ERROR("Read of single block failed \n");
		return 1;
	}

	return 0;
}

/* Hold the callback information. Map ATF calls to user application code  */
static const struct mmc_ops lan996x_ops = {
	.init = lan996x_mmc_initialize,
	.send_cmd = lan996x_mmc_send_cmd,
	.set_ios = lan996x_mmc_set_ios,
	.prepare = lan996x_mmc_prepare,
	.read = lan996x_mmc_read,
	.write = lan996x_mmc_write,
};

void lan966x_mmc_init(lan966x_mmc_params_t * params,
		      struct mmc_device_info *info)
{
	int retVal;

	VERBOSE("EMMC: lan966x_mmc_init() \n");

	assert((params != 0) &&
	       ((params->reg_base & MMC_BLOCK_MASK) == 0) &&
	       ((params->desc_base & MMC_BLOCK_MASK) == 0) &&
	       ((params->desc_size & MMC_BLOCK_MASK) == 0) &&
	       (params->desc_size > 0) &&
	       (params->clk_rate > 0) &&
	       ((params->bus_width == MMC_BUS_WIDTH_1) ||
		(params->bus_width == MMC_BUS_WIDTH_4) ||
		(params->bus_width == MMC_BUS_WIDTH_8)));

	memcpy(&lan966x_params, params, sizeof(lan966x_mmc_params_t));
	lan966x_params.mmc_dev_type = info->mmc_dev_type;
	reg_base = lan966x_params.reg_base;
	mmc_init(&lan996x_ops, params->clk_rate, params->bus_width,
		 params->flags, info);

	/* Set bus clock to 10MHz (supported by all SD card type) */
	retVal = lan966x_set_clk_freq(SDCLOCK_10MHZ, SDMMC_CLK_CTRL_PROG_MODE);
	assert(retVal == 0);

	/* Prevent compiler warning in release build */
	(void)retVal;
}
