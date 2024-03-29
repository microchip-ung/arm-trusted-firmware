/** Blinding header file
 *
 * @file
 *
 * Copyright (c) 2018-2021 Silex Insight sa
 * Copyright (c) 2014-2021 Beerten Engineering scs
 * SPDX-License-Identifier: BSD-3-Clause
 */


#ifndef BLINDING_HEADER_FILE
#define BLINDING_HEADER_FILE

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sx_pk_cnx;

/** Blinding factor used for Counter Measures */
typedef uint64_t sx_pk_blind_factor;

/** Blinding structure**/
struct sx_pk_blinder {
   union sx_pk_blinder_state {
      sx_pk_blind_factor blind; /**< Blind factor state of generation function */
      void* custom; /**< Custom state of generation function */
   } state; /**< Structure for state saving of generation function */
   sx_pk_blind_factor (*generate) (struct sx_pk_blinder *); /**< Function pointer to a blinding generator */
};

/** Activate the blinding countermeasures where available
 *
 * @param[inout] cnx Connection structure obtained through sx_pk_open() at startup
 * @param[in] prng Pointer to blinder structure that holds the blinder generation function
*/
void sx_pk_cnx_configure_blinding(struct sx_pk_cnx *cnx, struct sx_pk_blinder *prng);

/** Fills the blinder with default blind factor generation function
 *
 * @param[inout] blinder Blinder to fill
 * @param[in] seed Non-zero random value for the default blind generation function
*/
void sx_pk_default_blinder(struct sx_pk_blinder *blinder, sx_pk_blind_factor seed);

#ifdef __cplusplus
}
#endif

#endif
