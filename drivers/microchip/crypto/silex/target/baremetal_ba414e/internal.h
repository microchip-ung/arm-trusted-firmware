/*
 * Copyright (c) 2018-2021 Silex Insight sa
 * Copyright (c) 2018-2021 Beerten Engineering
 * SPDX-License-Identifier: BSD-3-Clause
 */


#ifndef INTERNAL_HEADER_FILE
#define INTERNAL_HEADER_FILE

#include <stdint.h>

struct sx_pk_cmd_def;

struct sx_regs
{
   char *base;
};

struct sx_pk_req
{
   struct sx_regs regs;
   char *cryptoram;
   int slot_sz;
   int op_size;
   const struct sx_pk_cmd_def *cmd;
   struct sx_pk_cnx *cnx;
   const char *outputops[12];
   void *userctxt;
   int ik_mode;
};

void sx_pk_wrreg(struct sx_regs *regs, uint32_t addr, uint32_t v);

uint32_t sx_pk_rdreg(struct sx_regs *regs, uint32_t addr);

struct sx_pk_blinder** sx_pk_get_blinder(struct sx_pk_cnx *cnx);

#endif
