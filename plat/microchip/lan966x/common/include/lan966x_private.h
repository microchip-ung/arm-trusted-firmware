/*
 * Copyright (c) 2017, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef LAN966X_PRIVATE_H
#define LAN966X_PRIVATE_H

#include <stdint.h>
#include <plat_crypto.h>
#include <lan96xx_common.h>

/* BL1 -> BL2 */
typedef struct {
	void *fw_config;
	void *mbedtls_heap_addr;
	size_t mbedtls_heap_size;
} shared_memory_desc_t;

extern shared_memory_desc_t shared_memory_desc;

/* BL2 -> BL32, using GPR(3-5) */
/* NOTE: Never delete members, add new data at end */
typedef struct {
	uint32_t ddr_size;
	size_t   boot_offset;
	uint32_t bl2_version;
} bl32_params_t;

/* GPR(3) = tag below, GPR(4) = size, GPR(5) = ptr */
#define BL32_PTR_TAG	0xabedcafe

void lan966x_set_max_trace_level(void);
void lan966x_reset_max_trace_level(void);

void lan966x_console_init(void);
void lan966x_timer_init(void);
void lan966x_ddr_init(void);
uint32_t lan966x_ddr_size(void);
void lan966x_tz_init(void);
void lan966x_tz_finish(void);
void lan966x_crash_console(console_t *console);

#if defined(LAN966X_AES_TESTS)
void lan966x_crypto_tests(void);
#endif

void lan966x_crypto_ecdsa_tests(void);

void lan966x_mbed_heap_set(shared_memory_desc_t *d);

#if defined(LAN966X_EMMC_TESTS)
void lan966x_emmc_tests(void);
#endif

#endif /* LAN966X_PRIVATE_H */
