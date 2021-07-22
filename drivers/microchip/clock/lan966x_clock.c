/*
 * Copyright (C) 2021 Microchip Technology Inc. and its subsidiaries.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <common/debug.h>
#include <drivers/microchip/lan966x_clock.h>
#include <lib/mmio.h>

#include "lan966x_regs.h"

#define PARENT_RATE 600000000UL

static const uint32_t base = LAN966X_CPU_BASE;

int lan966x_clk_disable(unsigned int clock)
{
	assert(clock < LAN966X_MAX_CLOCK);

	mmio_clrbits_32(CPU_GCK_CFG(base, clock), CPU_GCK_CFG_GCK_ENA(1));

	return 0;
}

int lan966x_clk_enable(unsigned int clock)
{
	assert(clock < LAN966X_MAX_CLOCK);

	mmio_setbits_32(CPU_GCK_CFG(base, clock), CPU_GCK_CFG_GCK_ENA(1));

	return 0;
}

int lan966x_clk_set_rate(unsigned int clock, unsigned long rate)
{
	uint32_t val;
	int div;

	assert(clock < LAN966X_MAX_CLOCK);
	assert(rate > 0);

	val = mmio_read_32(CPU_GCK_CFG(base, clock));

	/* Select CPU_CLK as source always */
        val &= ~CPU_GCK_CFG_GCK_SRC_SEL_M;
        val |= CPU_GCK_CFG_GCK_SRC_SEL(0);

	/* Set Prescaler */
        div = PARENT_RATE / rate;
        val &= ~CPU_GCK_CFG_GCK_PRESCALER_M;
	val |= CPU_GCK_CFG_GCK_PRESCALER(div - 1);
	mmio_write_32(CPU_GCK_CFG(base, clock), val);

	return 0;
}

unsigned long lan966x_clk_get_rate(unsigned int clock)
{
	assert(clock < LAN966X_MAX_CLOCK);
        uint32_t div, val;

	val = mmio_read_32(CPU_GCK_CFG(base, clock));

        div = CPU_GCK_CFG_GCK_PRESCALER_X(val);
        div += 1;

        return PARENT_RATE / div;
}