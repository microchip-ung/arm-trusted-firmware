/*
 * Copyright (C) 2021 Microchip Technology Inc. and its subsidiaries.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <common/debug.h>
#include <drivers/auth/crypto_mod.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/bignum.h>
#include <mbedtls/error.h>

#include <pkcl.h>
#include <sha.h>

// 192 bit Elliptic curve sample
// P = 2^256 - 2^224 - 2^96 + 1
const uint8_t au1ModuloP[] = {
0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// "a" parameter in curve equation = -3
// x^3 = x^2 + a*x + b
const uint8_t au1ACurve[] = {
0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};

// Base point A abscissa
const uint8_t au1PtA_X[] = {
0x00, 0x00, 0x00, 0x00, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81,
0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96
};

// Base point A ordinate
const uint8_t au1PtA_Y[] = {
0x00, 0x00, 0x00, 0x00, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57,
0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
};

// Base point A height
const uint8_t au1PtA_Z[] = {
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

// OrderPointBase
const uint8_t au1OrderPoint[] = {
0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad,
0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
};


// Private KEY
const uint8_t au1PrivateKey[] = {
0x00, 0x00, 0x00, 0x00, 0x4a, 0x91, 0x11, 0x29, 0xe5, 0x49, 0xd5, 0x7c,
0xeb, 0x8a, 0xc4, 0x31, 0x56, 0x4c, 0x66, 0x8c, 0x12, 0xef, 0xfc, 0x74,
0x9c, 0x5b, 0xa6, 0x67, 0x46, 0xfb, 0x2b, 0x32, 0x08, 0x38, 0x02, 0x35
};

// Public key abscissa
const uint8_t au1PtKeyGen_X[]  = {
0x00, 0x00, 0x00, 0x00, 0x61, 0x8c, 0xf7, 0x57, 0x5a, 0x2e, 0xd4, 0x39,
0xaf, 0x2c, 0xbf, 0x95, 0x04, 0x32, 0xe2, 0x70, 0xa0, 0xdb, 0x6d, 0xfa,
0x52, 0x5a, 0xd4, 0xce, 0x8b, 0x23, 0x05, 0x16, 0x04, 0x23, 0x3a, 0x48
};

// Public key ordinate
const uint8_t au1PtKeyGen_Y[]  = {
0x00, 0x00, 0x00, 0x00, 0x95, 0x71, 0x1c, 0xc1, 0xa4, 0x1e, 0xcc, 0x6e,
0x57, 0x6a, 0x23, 0x7e, 0x47, 0x35, 0xd6, 0xb8, 0x87, 0xc3, 0xd8, 0x76,
0xd9, 0x0a, 0x2d, 0xce, 0x01, 0x36, 0x4c, 0xd6, 0xa3, 0xa8, 0x7b, 0xb1
};

// Public key height
const uint8_t au1PtKeyGen_Z[] = {
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

// K
const uint8_t au1ScalarNumber[] = {
0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad,
0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x49
};

// Reduction contant
const uint8_t au1Cns[] = {
0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFE,
0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
0x00, 0x00, 0x00, 0x05
};

// Random number
const uint8_t au1RandomNumber[] = {
0x00, 0x00, 0x00, 0x00, 0xfb, 0xd1, 0x2d, 0xc5, 0x4a, 0xb9, 0x9f, 0xfe,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0x9e, 0x5e, 0x9a,
0x81, 0x6C, 0xCC, 0x33, 0xB8, 0x64, 0x2B, 0xED, 0xF9, 0x05, 0xC3, 0xD3
};

// "b" parameter in curve equation
// x^3 = x^2 + a*x + b
const uint8_t au1BCurve[] = {
0x00, 0x00, 0x00, 0x00, 0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7,
0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0,
0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b
};

const uint8_t au1HashValue[] = {
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A,
0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D};

const uint8_t au1TrueResult_R[] = {
0x00, 0x00, 0x00, 0x00, 0x62, 0xd9, 0x77, 0x9d, 0xbe, 0xe9, 0xb0, 0x53, 0x40,
0x42, 0x74, 0x2d, 0x3a, 0xb5, 0x4c, 0xad, 0xc1, 0xd2, 0x38, 0x98, 0x0f, 0xce,
0x97, 0xdb, 0xb4, 0xdd, 0x9d, 0xc1, 0xdb, 0x6f, 0xb3, 0x93
};

const uint8_t au1TrueResult_S[] = {
0x00, 0x00, 0x00, 0x00, 0x8f, 0x90, 0x5b, 0xa1, 0xf6, 0xcd, 0x98, 0xbb, 0xeb,
0x91, 0x4b, 0x0a, 0x4c, 0xd2, 0x08, 0xb3, 0x94, 0xcd, 0x62, 0x78, 0xe6, 0x31,
0xb3, 0x24, 0xc9, 0x20, 0x47, 0xb8, 0xe6, 0x85, 0xeb, 0x83
};

//******************************************************************************
// Expected results in signature with fixed parameters
// Message = "abc"
// R = 0x62d9779dbee9b0534042742d3ab54cadc1d238980fce97dbb4dd9dc1db6fb393
// S = 0x8f905ba1f6cd98bbeb914b0a4cd208b394cd6278e631b324c92047b8e685eb83
//******************************************************************************

void lan966x_crypto_ecdsa_mbedtls(void)
{
	mbedtls_ecp_keypair kp;
	mbedtls_mpi r, s;
	uint8_t hash[20];

	sha_calc(MBEDTLS_MD_SHA1, "abc", 3, hash);

	pkcl_ecdsa_verify_signature(MBEDTLS_PK_ECDSA,
				    &kp, &r, &s,
				    hash, sizeof(hash));
}

//- Function -----------------------------------------
// u2InitECCParamsECDSAGeneration()
//
// Initialises an ECC_Struct structure for ECDSA signature
// generation
//
// Input parameters :
//   pECC_Structure - ECC_Struct - Input
//        pECC_Structure that contains pointers to
//        curve data in EEPROM or in RAM
//   bRandomKeys - bool - Input
//        flag that indicates if public and private
//        keys are to be genrated from random
//        When bRandomKeys is set to false, the
//        function uses keys in curve.h
//
// Output values :
//  none
//- Remarks ------------------------------------------
// Data pointed by pECC_Structure is in MSB mode with
// 4 "0" bytes padding on the MSB side
// Plesae refer to "curve.h"
//----------------------------------------------------
static inline
void vInitECCParamsECDSAGeneration(ECC_Struct *pECC_Structure)
{
	memset(pECC_Structure, 0, sizeof(*pECC_Structure));

	pECC_Structure->u2ModuloPSize    = sizeof(au1ModuloP) - 4;
	pECC_Structure->u2OrderSize      = sizeof(au1OrderPoint) - 4;

	pECC_Structure->pfu1ModuloP      = (pfu1) au1ModuloP;
	pECC_Structure->pfu1ACurve       = (pfu1) au1ACurve;
	pECC_Structure->pfu1APointX      = (pfu1) au1PtA_X;
	pECC_Structure->pfu1APointY      = (pfu1) au1PtA_Y;
	pECC_Structure->pfu1APointZ      = (pfu1) au1PtA_Z;
	pECC_Structure->pfu1APointOrder  = (pfu1) au1OrderPoint;
	pECC_Structure->pfu1HashValue    = (pfu1) au1HashValue;

	pECC_Structure->pfu1PrivateKey   = (pfu1) au1PrivateKey;
}

//- Function -----------------------------------------
// u2InitECCParamsECDSAGeneration()
//
// Initialises an ECC_Struct struture for ECDSA signature
// verification
//
// Input parameters :
//   pECC_Structure - ECC_Struct - Input
//        pECC_Structure that conatains pointers to
//        curve data in EEPROM or in RAM
//   bRandomKeys - bool - Input
//        flag that indicates if public key
//        has been generated from random
//        When bRandomKeys is set to False, the
//        function use keys in curve.h
//
// Output values :
//  none
//- Remarks ------------------------------------------
// Data pointed by pECC_Structure is in MSB mode with
// 4 "0" bytes padding on the MSB side
// Plesae refer to "curve.h"
//----------------------------------------------------
static inline
void vInitECCParamsECDSAVerification(ECC_Struct *pECC_Structure)
{
	memset(pECC_Structure, 0, sizeof(*pECC_Structure));

	pECC_Structure->u2ModuloPSize    = sizeof(au1ModuloP) - 4;
	pECC_Structure->u2OrderSize      = sizeof(au1OrderPoint) - 4;

	pECC_Structure->pfu1ModuloP      = (pfu1) au1ModuloP;
	pECC_Structure->pfu1ACurve       = (pfu1) au1ACurve;
	pECC_Structure->pfu1APointX      = (pfu1) au1PtA_X;
	pECC_Structure->pfu1APointY      = (pfu1) au1PtA_Y;
	pECC_Structure->pfu1APointZ      = (pfu1) au1PtA_Z;
	pECC_Structure->pfu1APointOrder  = (pfu1) au1OrderPoint;
	pECC_Structure->pfu1HashValue    = (pfu1) au1HashValue;

	pECC_Structure->pfu1PublicKeyX   = (pfu1) au1PtKeyGen_X;
	pECC_Structure->pfu1PublicKeyY   = (pfu1) au1PtKeyGen_Y;
	pECC_Structure->pfu1PublicKeyZ   = (pfu1) au1PtKeyGen_Z;
}

void lan966x_crypto_ecdsa_tests(void)
{
	ECC_Struct ecc;
	uint8_t sig[256];

	vInitECCParamsECDSAGeneration(&ecc);

	DemoGenerate(&ecc,
		     &au1ScalarNumber[0],
		     sig);

	vInitECCParamsECDSAVerification(&ecc);

	DemoVerify(&ecc,
		   au1TrueResult_R,
		   au1TrueResult_S);
}
