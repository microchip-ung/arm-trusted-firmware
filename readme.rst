Microchip/UNG Trusted Firmware-A
================================

This software has been modified by Microchip Technology Inc. to add
support for the following SoC's:

* `lan966x_b0`: LAN966X revision B - BL1 secure bootrom
* `lan969x_a0`: LAN969X revision A - BL1 secure bootrom

It is possible to build the software by following the normal TFA
guidelines, but the (Ruby) wrapper `scripts/build.rb` script is
offered as it ensures using the proper options for the platform. Refer
to the script help (`--help` option).

You should be able to compile the software using Ubuntu 22.04, but in
order to shield you from platform software issues, you should consider
using docker, along with a wrapper script - see
https://github.com/microchip-ung/docker-run for more info. So with
docker install, just run `dr ./scripts/build.rb ...`. (At first run it
docker will download a docker image, but after that the overhead is
minimal).

.. warning::
   The keys found in the `keys/` directory are *purely* for
   demonstration purposes and *must* be replaced with own keys before
   software deployment.

*Orignial TF-A Readme file below:*

Trusted Firmware-A
==================

Trusted Firmware-A (TF-A) is a reference implementation of secure world software
for `Arm A-Profile architectures`_ (Armv8-A and Armv7-A), including an Exception
Level 3 (EL3) `Secure Monitor`_. It provides a suitable starting point for
productization of secure world boot and runtime firmware, in either the AArch32
or AArch64 execution states.

TF-A implements Arm interface standards, including:

-  `Power State Coordination Interface (PSCI)`_
-  `Trusted Board Boot Requirements CLIENT (TBBR-CLIENT)`_
-  `SMC Calling Convention`_
-  `System Control and Management Interface (SCMI)`_
-  `Software Delegated Exception Interface (SDEI)`_

The code is designed to be portable and reusable across hardware platforms and
software models that are based on the Armv8-A and Armv7-A architectures.

In collaboration with interested parties, we will continue to enhance TF-A
with reference implementations of Arm standards to benefit developers working
with Armv7-A and Armv8-A TrustZone technology.

Users are encouraged to do their own security validation, including penetration
testing, on any secure world code derived from TF-A.

More Info and Documentation
---------------------------

To find out more about Trusted Firmware-A, please `view the full documentation`_
that is available through `trustedfirmware.org`_.

--------------

*Copyright (c) 2013-2019, Arm Limited and Contributors. All rights reserved.*

.. _Armv7-A and Armv8-A: https://developer.arm.com/products/architecture/a-profile
.. _Secure Monitor: http://www.arm.com/products/processors/technologies/trustzone/tee-smc.php
.. _Power State Coordination Interface (PSCI): PSCI_
.. _PSCI: http://infocenter.arm.com/help/topic/com.arm.doc.den0022d/Power_State_Coordination_Interface_PDD_v1_1_DEN0022D.pdf
.. _Trusted Board Boot Requirements CLIENT (TBBR-CLIENT): https://developer.arm.com/docs/den0006/latest/trusted-board-boot-requirements-client-tbbr-client-armv8-a
.. _SMC Calling Convention: http://infocenter.arm.com/help/topic/com.arm.doc.den0028b/ARM_DEN0028B_SMC_Calling_Convention.pdf
.. _System Control and Management Interface (SCMI): SCMI_
.. _SCMI: http://infocenter.arm.com/help/topic/com.arm.doc.den0056a/DEN0056A_System_Control_and_Management_Interface.pdf
.. _Software Delegated Exception Interface (SDEI): SDEI_
.. _SDEI: http://infocenter.arm.com/help/topic/com.arm.doc.den0054a/ARM_DEN0054A_Software_Delegated_Exception_Interface.pdf
.. _Arm A-Profile architectures: https://developer.arm.com/architectures/cpu-architecture/a-profile
.. _view the full documentation: https://www.trustedfirmware.org/docs/tf-a
.. _trustedfirmware.org: http://www.trustedfirmware.org
