/*
 * Copyright (C) 2021 Microchip Technology Inc. and its subsidiaries.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef EMMC_H
#define EMMC_H

#include <drivers/mmc.h>
#include <lib/mmio.h>

#define SDCLOCK_400KHZ	400000u
#define SDCLOCK_10MHZ	10000000u
#define SDCLOCK_25MHZ	25000000u
#define SDCLOCK_50MHZ	50000000u

#define SDMMC_CLK_CTRL_DIV_MODE		0
#define SDMMC_CLK_CTRL_PROG_MODE	1

#define ALL_FLAGS	(0xFFFFu)
#define SD_STATUS_ERROR_MASK		0xFFF90008

#define EMMC_POLL_LOOP_DELAY	8u	/* 8µs */
#define EMMC_POLLING_TIMEOUT	2000000u	/* 2sec */

#define TIME_MSEC(x)	(x * 1000)	/* Converts arg from ms to microsec */

#define MMC_HIGH_DENSITY	(3)
#define MMC_NORM_DENSITY	(2)
#define SD_CARD_SDHC_SDXC	(1)
#define SD_CARD_SDSC		(0)

#define MAX_BLOCK_SIZE		512
#define SD_DATA_WRITE		1
#define SD_DATA_READ		0

#define SD_CARD			(0)
#define MMC_CARD		(1)
#define SD_CARD_PHY_SPEC_1_0X	(0)
#define SD_CARD_PHY_SPEC_1_10	(1)
#define SD_CARD_PHY_SPEC_2_00	(2)
#define SD_CARD_PHY_SPEC_3_0X	(3)
#define MMC_CARD_PHY_SPEC_4_X	(4)
#define MMC_CARD_PHY_SPEC_OLD	(5)

#define SD_STATUS_CURRENT_STATE_pos		9
#define SD_STATUS_CURRENT_STATE_msk		(0xFu << SD_STATUS_CURRENT_STATE_pos)
#define SD_STATUS_CURRENT_STATE_IDLE		(0x0u << SD_STATUS_CURRENT_STATE_pos)
#define SD_STATUS_CURRENT_STATE_READY		(0x1u << SD_STATUS_CURRENT_STATE_pos)
#define SD_STATUS_CURRENT_STATE_IDENT		(0x2u << SD_STATUS_CURRENT_STATE_pos)
#define SD_STATUS_CURRENT_STATE_STBY		(0x3u << SD_STATUS_CURRENT_STATE_pos)
#define SD_STATUS_CURRENT_STATE_TRAN		(0x4u << SD_STATUS_CURRENT_STATE_pos)
#define SD_STATUS_CURRENT_STATE_DATA		(0x5u << SD_STATUS_CURRENT_STATE_pos)
#define SD_STATUS_CURRENT_STATE_RCV		(0x6u << SD_STATUS_CURRENT_STATE_pos)
#define SD_STATUS_CURRENT_STATE_PRG		(0x7u << SD_STATUS_CURRENT_STATE_pos)
#define SD_STATUS_CURRENT_STATE_DIS		(0x8u << SD_STATUS_CURRENT_STATE_pos)

#define MMC_CARD_POWER_UP_STATUS	(0x1u << 31)
#define MMC_CARD_ACCESS_MODE_pos	29
#define MMC_CARD_ACCESS_MODE_msk	(0x3u << MMC_CARD_ACCESS_MODE_pos)
#define MMC_CARD_ACCESS_MODE_BYTE	(0x0u << MMC_CARD_ACCESS_MODE_pos)
#define MMC_CARD_ACCESS_MODE_SECTOR	(0x2u << MMC_CARD_ACCESS_MODE_pos)

#define SD_STATUS_ERROR_MASK              0xFFF90008
#define SD_CARD_STATUS_SUCCESS(s)         (0 == ((s) & SD_STATUS_ERROR_MASK))

/****************************************************************************************/
/*      SD Card Commands Definitions                                                    */
/****************************************************************************************/

#if 0
#define SDMMC_CR_CMDIDX_Pos         8
#define SDMMC_CR_CMDIDX_Msk         (0x3Fu << SDMMC_CR_CMDIDX_Pos)
#define SDMMC_CR_CMDIDX(value)      ((SDMMC_CR_CMDIDX_Msk & ((value) << SDMMC_CR_CMDIDX_Pos)))
#define SDMMC_CR_CMDTYP_Pos          6
#define SDMMC_CR_CMDTYP_Msk          (0x3u << SDMMC_CR_CMDTYP_Pos)
#define     SDMMC_CR_CMDTYP_NORMAL   (0x0u << SDMMC_CR_CMDTYP_Pos)
#define     SDMMC_CR_CMDTYP_SUSPEND  (0x1u << SDMMC_CR_CMDTYP_Pos)
#define     SDMMC_CR_CMDTYP_RESUME   (0x2u << SDMMC_CR_CMDTYP_Pos)
#define     SDMMC_CR_CMDTYP_ABORT    (0x3u << SDMMC_CR_CMDTYP_Pos)
#define SDMMC_CR_DPSEL      (0x1u << 5)
#define SDMMC_CR_CMDICEN       (0x1u << 4)
#define SDMMC_CR_CMDCCEN         (0x1u << 3)
#define SDMMC_CR_RESPTYP_Pos     6
#define SDMMC_CR_RESPTYP_Msk     (0x3u << SDMMC_CR_RESPTYP_Pos)
#define     SDMMC_CR_RESPTYP_NORESP (0x0u << SDMMC_CR_RESPTYP_Pos)
#define     SDMMC_CR_RESPTYP_RL136 (0x1u << SDMMC_CR_RESPTYP_Pos)
#define     SDMMC_CR_RESPTYP_RL48  (0x2u << SDMMC_CR_RESPTYP_Pos)
#define     SDMMC_CR_RESPTYP_RL48BUSY (0x3u << SDMMC_CR_RESPTYP_Pos)
#endif

#define SDMMC_CMD0		(SDMMC_CR_CMDIDX(0) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_RESPTYP_NORESP | ((SDMMC_MC1R_CMDTYP_NORMAL | SDMMC_MC1R_OPD) << 16))
#define SDMMC_SD_CMD0		(SDMMC_CR_CMDIDX(0) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_RESPTYP_NORESP)
#define SDMMC_MMC_CMD0		(SDMMC_CR_CMDIDX(0) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_RESPTYP_NORESP | ((SDMMC_MC1R_CMDTYP_NORMAL | SDMMC_MC1R_OPD) << 16))

#define SDMMC_CMD1		(SDMMC_CR_CMDIDX(1) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_RESPTYP_RL48 | ((SDMMC_MC1R_CMDTYP_NORMAL | SDMMC_MC1R_OPD) << 16))
#define SDMMC_SD_CMD1		(SDMMC_CR_CMDIDX(1) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_RESPTYP_RL48)
#define SDMMC_MMC_CMD1		(SDMMC_CR_CMDIDX(1) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_RESPTYP_RL48 | ((SDMMC_MC1R_CMDTYP_NORMAL | SDMMC_MC1R_OPD) << 16))

#define SDMMC_SD_CMD2		(SDMMC_CR_CMDIDX(2) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL136)
#define SDMMC_MMC_CMD2		(SDMMC_CR_CMDIDX(2) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL136 | ((SDMMC_MC1R_CMDTYP_NORMAL | SDMMC_MC1R_OPD) << 16))

#define SDMMC_SD_CMD3		(SDMMC_CR_CMDIDX(3) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48)
#define SDMMC_MMC_CMD3		(SDMMC_CR_CMDIDX(3) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | ((SDMMC_MC1R_CMDTYP_NORMAL | SDMMC_MC1R_OPD) << 16))

#define SDMMC_SD_CMD4		(SDMMC_CR_CMDIDX(4) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_RESPTYP_NORESP)

#define SDMMC_SD_CMD6		(SDMMC_CR_CMDIDX(6) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | SDMMC_CR_DPSEL)
#define SDMMC_MMC_CMD6		(SDMMC_CR_CMDIDX(6) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48BUSY | (SDMMC_MC1R_CMDTYP_NORMAL << 16))

#define SDMMC_SD_CMD7		(SDMMC_CR_CMDIDX(7) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48BUSY)
#define SDMMC_MMC_CMD7		(SDMMC_CR_CMDIDX(7) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48BUSY | (SDMMC_MC1R_CMDTYP_NORMAL << 16))

#define SDMMC_SD_CMD8		(SDMMC_CR_CMDIDX(8) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48)
#define SDMMC_MMC_CMD8		(SDMMC_CR_CMDIDX(8) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | SDMMC_CR_DPSEL | (SDMMC_MC1R_CMDTYP_NORMAL << 16))

#define SDMMC_SD_CMD9		(SDMMC_CR_CMDIDX(9) | SDMMC_CR_CMDTYP_NORMAL  | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL136)
#define SDMMC_MMC_CMD9		(SDMMC_CR_CMDIDX(9) | SDMMC_CR_CMDTYP_NORMAL  | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL136 | (SDMMC_MC1R_CMDTYP_NORMAL << 16))

#define SDMMC_SD_CMD10		(SDMMC_CR_CMDIDX(10) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL136)

#define SDMMC_SD_CMD11		(SDMMC_CR_CMDIDX(11) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48)
#define SDMMC_MMC_CMD11		(SDMMC_CR_CMDIDX(11) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | SDMMC_CR_DPSEL | (SDMMC_MC1R_CMDTYP_STREAM << 16))

#define SDMMC_SD_CMD12		(SDMMC_CR_CMDIDX(12) | SDMMC_CR_CMDTYP_ABORT | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48BUSY)
#define SDMMC_MMC_CMD12		(SDMMC_CR_CMDIDX(12) | SDMMC_CR_CMDTYP_ABORT | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48BUSY | (SDMMC_MC1R_CMDTYP_NORMAL << 16))

#define SDMMC_SD_CMD13		(SDMMC_CR_CMDIDX(13) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48)
#define SDMMC_MMC_CMD13		(SDMMC_CR_CMDIDX(13) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | (SDMMC_MC1R_CMDTYP_NORMAL << 16))

#define SDMMC_SD_CMD16		(SDMMC_CR_CMDIDX(16) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48)
#define SDMMC_MMC_CMD16		(SDMMC_CR_CMDIDX(16) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | (SDMMC_MC1R_CMDTYP_NORMAL << 16))

#define SDMMC_SD_CMD17		(SDMMC_CR_CMDIDX(17) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | SDMMC_CR_DPSEL)
#define SDMMC_MMC_CMD17		(SDMMC_CR_CMDIDX(17) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | SDMMC_CR_DPSEL | (SDMMC_MC1R_CMDTYP_NORMAL << 16))

#define SDMMC_SD_CMD18		(SDMMC_CR_CMDIDX(18) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | SDMMC_CR_DPSEL)
#define SDMMC_MMC_CMD18		(SDMMC_CR_CMDIDX(18) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | SDMMC_CR_DPSEL | (SDMMC_MC1R_CMDTYP_NORMAL << 16))

#define SDMMC_MMC_CMD20		(SDMMC_CR_CMDIDX(20) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | SDMMC_CR_DPSEL | (SDMMC_MC1R_CMDTYP_STREAM << 16))

#define SDMMC_SD_CMD24		(SDMMC_CR_CMDIDX(24) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | SDMMC_CR_DPSEL)
#define SDMMC_MMC_CMD24		(SDMMC_CR_CMDIDX(24) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | SDMMC_CR_DPSEL | (SDMMC_MC1R_CMDTYP_NORMAL << 16))

#define SDMMC_SD_CMD25		(SDMMC_CR_CMDIDX(25) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | SDMMC_CR_DPSEL)
#define SDMMC_MMC_CMD25		(SDMMC_CR_CMDIDX(25) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | SDMMC_CR_DPSEL | (SDMMC_MC1R_CMDTYP_NORMAL << 16))

#define SDMMC_SD_CMD32		(SDMMC_CR_CMDIDX(32) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48)
#define SDMMC_SD_CMD33		(SDMMC_CR_CMDIDX(33) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48)

#define SDMMC_MMC_CMD35		(SDMMC_CR_CMDIDX(35) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | (SDMMC_MC1R_CMDTYP_NORMAL << 16))
#define SDMMC_MMC_CMD36		(SDMMC_CR_CMDIDX(36) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | (SDMMC_MC1R_CMDTYP_NORMAL << 16))

#define SDMMC_SD_CMD38		(SDMMC_CR_CMDIDX(38) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48BUSY)
#define SDMMC_MMC_CMD38		(SDMMC_CR_CMDIDX(38) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48BUSY | (SDMMC_MC1R_CMDTYP_NORMAL << 16))

#define SDMMC_SD_CMD55		(SDMMC_CR_CMDIDX(55) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48)

#define SDMMC_SD_ACMD6		(SDMMC_CR_CMDIDX(6) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48)
#define SDMMC_SD_ACMD13		(SDMMC_CR_CMDIDX(13) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | SDMMC_CR_DPSEL)
#define SDMMC_SD_CMD19		(SDMMC_CR_CMDIDX(19) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48 | SDMMC_CR_DPSEL)
#define SDMMC_SD_ACMD23		(SDMMC_CR_CMDIDX(23) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_CMDICEN | SDMMC_CR_CMDCCEN | SDMMC_CR_RESPTYP_RL48)
#define SDMMC_SD_ACMD41		(SDMMC_CR_CMDIDX(41) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_RESPTYP_RL48)
#define SDMMC_SD_ACMD51		(SDMMC_CR_CMDIDX(51) | SDMMC_CR_CMDTYP_NORMAL | SDMMC_CR_RESPTYP_RL48 | SDMMC_CR_DPSEL)

typedef struct lan966x_mmc_params {
	uintptr_t reg_base;
	uintptr_t desc_base;
	size_t desc_size;
	int clk_rate;
	int bus_width;
	unsigned int flags;
	enum mmc_device_type mmc_dev_type;
} lan966x_mmc_params_t;

typedef struct _card {
	unsigned char card_type;
	unsigned char card_manufacturer_id;
	unsigned char card_application_id;
	unsigned char card_product_name[6];
	unsigned char card_product_revision;
	unsigned char card_product_sn[4];
	unsigned char card_capacity;
	unsigned int card_taac_ns;
	unsigned int card_trans_speed;
	unsigned int card_nsac;
	unsigned char card_r2w_factor;
	unsigned char card_max_rd_blk_len;
	unsigned char card_phy_spec_rev;
} card;

static inline unsigned int get_CSD_field(volatile const unsigned int *p_resp,
					 unsigned int index, unsigned int size)
{
	unsigned int shift;
	unsigned int res;
	unsigned int off;

	index -= 8;		//Remove CRC section
	shift = index % 32;
	off = index / 32;

	res = p_resp[off] >> shift;

	if ((size + shift) > 32) {
		res |= (p_resp[off + 1] << (32 - shift));
	}

	res &= ((1 << size) - 1);

	return res;
}

static inline void mmc_setbits_16(uintptr_t addr, uint16_t set)
{
	mmio_write_16(addr, mmio_read_16(addr) | set);
}

static inline void mmc_clrbits_16(uintptr_t addr, uint16_t clear)
{
	mmio_write_16(addr, mmio_read_16(addr) & ~clear);
}

static inline void mmc_setbits_8(uintptr_t addr, uint8_t set)
{
	mmio_write_8(addr, mmio_read_8(addr) | set);
}

void lan966x_mmc_init(lan966x_mmc_params_t * params,
		      struct mmc_device_info *info);

size_t lan966x_read_single_block(int block_number,
				 uintptr_t dest_buffer, size_t block_size);

#endif	/* EMMC_H */
