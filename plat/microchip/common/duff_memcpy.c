/*
 * Copyright (C) 2022 Microchip Technology Inc. and its subsidiaries.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <plat/microchip/common/duff_memcpy.h>

#define DUFF_BODY(elmtype, nelms) \
	size_t n = (nelms + 7) / 8;				\
	switch (nelms % 8) {					\
		case 0: do { *dst_typed++ = *src_typed++;	\
		case 7:      *dst_typed++ = *src_typed++;	\
		case 6:      *dst_typed++ = *src_typed++;	\
		case 5:      *dst_typed++ = *src_typed++;	\
		case 4:      *dst_typed++ = *src_typed++;	\
		case 3:      *dst_typed++ = *src_typed++;	\
		case 2:      *dst_typed++ = *src_typed++;	\
		case 1:      *dst_typed++ = *src_typed++;	\
			} while (--n > 0);			\
	}							\
	return nelms * sizeof(elmtype)

size_t duff_dword_copy(uint64_t *dst_typed, const uint64_t *src_typed, size_t dword_count)
{
	DUFF_BODY(uint64_t, dword_count);
}

size_t duff_word_copy(uint32_t *dst_typed, const uint32_t *src_typed, size_t word_count)
{
	DUFF_BODY(uint32_t, word_count);
}

size_t duff_hword_copy(uint16_t *dst_typed, const uint16_t *src_typed, size_t hword_count)
{
	DUFF_BODY(uint16_t, hword_count);
}

size_t duff_byte_copy(uint8_t *dst_typed, const uint8_t *src_typed, size_t bytes)
{
	DUFF_BODY(uint8_t, bytes);
}

void *duff_memcpy(void *dst, const void *src, size_t bytes)
{
	uintptr_t alignment = ((uintptr_t) dst) | ((uintptr_t) src);
	void *d = dst;

	if ((alignment & 0xF) == 0 && bytes >= sizeof(uint64_t)) {
		size_t copied = duff_dword_copy(dst, src, bytes / sizeof(uint64_t));
		bytes -= copied;
		dst += copied;
		src +=  copied;
	} else if ((alignment & 0x3) == 0 && bytes >= sizeof(uint32_t)) {
		size_t copied = duff_word_copy(dst, src, bytes / sizeof(uint32_t));
		bytes -= copied;
		dst += copied;
		src +=  copied;
	} else if ((alignment & 0x1) == 0 && bytes >= sizeof(uint16_t)) {
		size_t copied = duff_hword_copy(dst, src, bytes / sizeof(uint16_t));
		bytes -= copied;
		dst += copied;
		src +=  copied;
	}
	/* Copy byte residual */
	if (bytes)
		(void) duff_byte_copy(dst, src, bytes);
	return d;
}
