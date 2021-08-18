/*
 * Copyright (C) 2021 Microchip Technology Inc. and its subsidiaries.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <common/debug.h>
#include <lib/mmio.h>
#include <plat/common/platform.h>
#include <drivers/delay_timer.h> /* XXX - debug */

#include "lan966x_regs.h"
#include "lan966x_private.h"
#include "plat_otp.h"

#define LAN966X_SJTAG_OPEN	0
#define LAN966X_SJTAG_MODE1	1
#define LAN966X_SJTAG_MODE2	2
#define LAN966X_SJTAG_CLOSED	3

#define SJTAG_NREGS_KEY		8
#define SJTAG_NREGS_UUID	3

void lan966x_sjtag_configure(void)
{
	uint32_t w;
	int mode;

	w = mmio_read_32(SJTAG_CTL(LAN966X_SJTAG_BASE));
	mode = SJTAG_CTL_SJTAG_MODE_X(w);

#if defined(IMAGE_BL1) || defined(BL2_AT_EL3)
	/* Initial configuration */
	if (mode == LAN966X_SJTAG_MODE1 || mode == LAN966X_SJTAG_MODE2) {
		uint32_t sjtag_nonce[SJTAG_NREGS_KEY];
		uint32_t sjtag_ssk[SJTAG_NREGS_KEY];
		uint32_t sjtag_uuid[SJTAG_NREGS_UUID];
		int i;

		/* Secure mode, initialize challenge registers */
		INFO("Secure JTAG configured, mode = %d, ctl = %08x\n",
		     mode, mmio_read_32(SJTAG_CTL(LAN966X_SJTAG_BASE)));

		/* Generate nonce */
		for (i = 0; i < SJTAG_NREGS_KEY; i++) {
			sjtag_nonce[i] = lan966x_trng_read();
			mmio_write_32(SJTAG_NONCE(LAN966X_SJTAG_BASE, i), sjtag_nonce[i]);
		}

		/* Read SSK */
		otp_read_otp_sjtag_ssk((uint8_t*) sjtag_ssk, sizeof(sjtag_ssk));

		/* Generate digest with nonce and ssk, write it */
		i = lan966x_derive_key(sjtag_nonce, sizeof(sjtag_nonce),
				       sjtag_ssk, sizeof(sjtag_ssk),
				       sjtag_ssk, sizeof(sjtag_ssk));
		assert(i == sizeof(sjtag_ssk));
		for (i = 0; i < SJTAG_NREGS_KEY; i++)
			mmio_write_32(SJTAG_DEVICE_DIGEST(LAN966X_SJTAG_BASE, i), sjtag_ssk[i]);

		/* Write UUID */
		otp_read_jtag_uuid((uint8_t*) sjtag_uuid, sizeof(sjtag_uuid));
		for (i = 0; i < SJTAG_NREGS_UUID; i++)
			mmio_write_32(SJTAG_UUID(LAN966X_SJTAG_BASE, i), sjtag_uuid[i]);
	}
#endif

#if defined(IMAGE_BL2)
	if (mode == LAN966X_SJTAG_MODE1 || mode == LAN966X_SJTAG_MODE2) {
		INFO("SJTAG: Freezing registers to prevent tampering\n");
		mmio_setbits_32(SJTAG_CTL(LAN966X_SJTAG_BASE), SJTAG_CTL_SJTAG_FREEZE(1));
	}
#endif
}
