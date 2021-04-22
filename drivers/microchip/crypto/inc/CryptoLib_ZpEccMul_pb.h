//========================================================================
//
//   NOTE :    THIS SOFTWARE IS SUPPLIED FOR DEMONSTRATION PURPOSES ONLY.
//             THERE IS NO SECURITY BUILT INTO THIS SOFTWARE
//
//========================================================================
//
//        Copyright (c) Atmel Corporation 2012 All rigths reserved
//                     ATMEL CONFIDENTIAL PROPRIETARY
//
//========================================================================
//                             DISCLAIMER
//
//    Atmel reserves the right to make changes without further notice
//    to any product herein to improve reliability, function or design.
//    Atmel does not assume any liability arising out of the
//    application or use of any product, circuit, or software described
//    herein; neither does it convey any license under its patent rights
//    nor the rights of others. Atmel products are not designed,
//    intended or authorized for use as components in systems intended
//    for surgical implant into the body or other applications intended
//    to support life, or for any other application in which the failure
//    of the Atmel product could create a situation where personal
//    injury or death may occur. Should Buyer purchase or use Atmel
//    products for any such intended or unauthorized application, Buyer
//    shall indemnify and hold Atmel and its officers, employees,
//    subsidiaries, affiliates, and distributors harmless against all
//    claims, costs, damages and expenses, and reasonable attorney fees
//    arising out of, directly or indirectly, any claim of personal
//    injury or death associated with such unintended or unauthorized
//    use, even if such claim alleges that Atmel was negligent
//    regarding the design or manufacture of the part. Atmel and the
//    Atmel logo are registered trademarks of the Atmel corporation.
//========================================================================
//      ATMEL CryptoLib Library
//------------------------------------------------------------------------
//      File: CryptoLib_ZpEccMul_pb.h
//------------------------------------------------------------------------
//      Description: definition of types for the EccAdd
//------------------------------------------------------------------------
#ifndef _CRYPTOLIBZPECCMUL_INCLUDED
#define _CRYPTOLIBZPECCMUL_INCLUDED

// Structure definition
typedef struct _CPKCL_ZpEccMul {
               nu1       nu1ModBase;
               nu1       nu1CnsBase;
               u2        u2ModLength;

               nu1       nu1PointBase;
               nu1       nu1KBase;                   
               nu1       nu1Workspace;           
               nu1       nu1ABase;               
               u2        u2KLength;
               } _CPKCL_ZPECCMUL, *_P_CPKCL_ZPECCMUL;


#endif // _CRYPTOLIBZPECCDBL_INCLUDED
