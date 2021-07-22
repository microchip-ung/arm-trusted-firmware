/*
 * Copyright (c) 2017, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LAN966X_DEF_H
#define LAN966X_DEF_H

#include "lan966x_targets.h"

/* LAN966X defines */
#define LAN996X_BOOTROM_BASE	UL(0x00000000)
#define LAN996X_BOOTROM_SIZE	UL(1024 * 64)
#define LAN996X_SRAM_BASE	UL(0x00100000)
#define LAN996X_SRAM_SIZE	UL(1024 * 128)
#define LAN996X_QSPI0_MMAP	UL(0x20000000)
#define LAN996X_QSPI0_RANGE	UL(16 * 1024 * 1024)
#define LAN996X_DDR_BASE	UL(0x60000000)
#define LAN996X_DDR_SIZE	UL(1 * 1024 * 1024 * 1024)

#define LAN966x_EMMC_FIP_ADDR	UL(0x00090000)
#define LAN966X_FIP_SIZE	UL(1472 * 1024)

#define LAN966X_GPT_BASE	UL(0x00000000)
#define LAN966X_GPT_SIZE	UL(32 * 1024)

#define LAN996X_AXI_BASE	UL(0xE0000000)
#define LAN996X_AXI_SIZE	UL(0x00900000)

#define LAN996X_ORG_BASE	LAN966X_ORG_0_BASE
#define LAN996X_ORG_SIZE	UL(0x00800000)

#define LAN996X_CPU_BASE	UL(0xE8800000)
#define LAN996X_CPU_SIZE	UL(0x00800000)

/*
 * GIC-400
 */
#define PLAT_LAN966X_GICD_BASE	(LAN966X_GIC400_BASE + 0x1000)
#define PLAT_LAN966X_GICC_BASE	(LAN966X_GIC400_BASE + 0x2000)

#define LAN966X_IRQ_SEC_PHY_TIMER	29

#define LAN966X_IRQ_SEC_SGI_0	8
#define LAN966X_IRQ_SEC_SGI_1	9
#define LAN966X_IRQ_SEC_SGI_2	10
#define LAN966X_IRQ_SEC_SGI_3	11
#define LAN966X_IRQ_SEC_SGI_4	12
#define LAN966X_IRQ_SEC_SGI_5	13
#define LAN966X_IRQ_SEC_SGI_6	14
#define LAN966X_IRQ_SEC_SGI_7	15

/*
 * HMATRIX2, TZ
 */

#define MATRIX_SLAVE_QSPI0	0
#define MATRIX_SLAVE_QSPI1	1
#define MATRIX_SLAVE_TZAESB	2
#define MATRIX_SLAVE_DDR_HSS	3
#define MATRIX_SLAVE_HSS_APB	4
#define MATRIX_SLAVE_FLEXRAM0	5
#define MATRIX_SLAVE_FLEXRAM1	6
#define MATRIX_SLAVE_USB	7

/*
 * Flexcom
 */

#define FLEXCOM_UART_OFFSET		UL(0x200)

/*
 * Flexcom UART related constants
 */
#define FLEXCOM_BAUDRATE            UL(115200)
#define FLEXCOM_UART_CLK_IN_HZ      UL(19200000)

/* QSPI controller(s) */

#define QSPI_SIZE	0x00000100

/* ToDo: Check defines */
#define FACTORY_CLK     UL(30000000)    /* Factory CLK used on sunrise board */

/*
 * Timer
 */
#if defined(LAN966X_ASIC)
#define SYS_COUNTER_FREQ_IN_TICKS	(60000000)
#else
#define SYS_COUNTER_FREQ_IN_TICKS	(5000000)
#endif

#endif /* LAN966X_DEF_H */