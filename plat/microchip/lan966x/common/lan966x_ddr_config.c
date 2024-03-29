// SPDX-License-Identifier: (GPL-2.0+ OR MIT)
/*
 * Copyright (C) 2023 Microchip Technology Inc. and its subsidiaries.
 *
 */

#include <ddr_config.h>

const struct ddr_config lan966x_ddr_config = {
	.info = {
		.name = "lan966x 2023-08-14-10:53:11 416024f90cff",
		.speed = 1200,
		.size = 0x38000000,
		.bus_width = 16,
	},
	.main = {
		.dfimisc = 0x00000000,
		.dfitmg0 = 0x04030102,
		.dfitmg1 = 0x00040201,
		.dfiupd0 = 0x40400003,
		.dfiupd1 = 0x004000ff,
		.ecccfg0 = 0x003f7f44,
		.init0 = 0x00020124,
		.init1 = 0x00740000,
		.init3 = 0x1b600004,
		.init4 = 0x00100000,
		.init5 = 0x00080000,
		.mstr = 0x01040001,
		.pccfg = 0x00000000,
		.pwrctl = 0x00000000,
		.rfshctl0 = 0x00210010,
		.rfshctl3 = 0x00000000,
	},

	.timing = {
		.dramtmg0 = 0x0a0f0b0c,
		.dramtmg1 = 0x00020211,
		.dramtmg2 = 0x00000508,
		.dramtmg3 = 0x0000400c,
		.dramtmg4 = 0x05020306,
		.dramtmg5 = 0x04040303,
		.dramtmg8 = 0x00000803,
		.odtcfg = 0x0600060c,
		.rfshtmg = 0x00820057,
	},

	.mapping = {
		.addrmap0 = 0x0000001f,
		.addrmap1 = 0x00040401,
		.addrmap2 = 0x01010100,
		.addrmap3 = 0x13131303,
		.addrmap4 = 0x00001f1f,
		.addrmap5 = 0x04040404,
		.addrmap6 = 0x04040404,
	},

	.phy = {
		.dcr = 0x0000040b,
		.dsgcr = 0xf000641f,
		.dtcr = 0x910035c7,
		.dxccr = 0x44181884,
		.pgcr2 = 0x00f00898,
		.zq0cr0 = 0x4000014a,
		.zq0cr1 = 0x0000107b,
		.zq1cr0 = 0x4000014a,
		.zq1cr1 = 0x0000107b,
	},

	.phy_timing = {
		.dtpr0 = 0xc958ea85,
		.dtpr1 = 0x228bb3c4,
		.dtpr2 = 0x1002e8b4,
		.ptr0 = 0x25a12c90,
		.ptr1 = 0x754f0a8f,
		.ptr2 = 0x00083def,
		.ptr3 = 0x0b449000,
		.ptr4 = 0x06add000,
	},

};
