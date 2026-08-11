# Boot ROM Errata

This document records known defects in the **on-chip boot ROM (BL1)** of the
Microchip platforms supported by this repository.

Because BL1 executes from mask ROM, these defects cannot be corrected by a
firmware (FIP) update on affected silicon. Each entry therefore describes how
the issue manifests and the build- or provisioning-side workaround that avoids
triggering it. Defects that live only in updatable firmware (BL2/BL31/BL32) do
not belong here — they are fixed in the normal source tree and its change
history.

## Entry format

Each erratum has a stable ID (`ERR-<SOC>-<NNN>`), the affected stepping(s), a
description of the observable failure, the root cause, and a workaround.

---

## ERR-LAN969X-001 — ECDSA verification fails for certificate/key values with a leading zero byte

| | |
|---|---|
| **Platform** | lan969x (Laguna) |
| **Affected steppings** | A0 |
| **Boot stage** | BL1 (boot ROM) |
| **Status** | Present in ROM — not fixable by firmware update; mitigated at build/provisioning time |
| **References** | Jira `LMSTAX-1677` (firmware fix), `UNG_LAGUNA-690` (ROM erratum); `LMSTAX-1657` / `LMSTAX-1676` (build-side guards) |

### Description

The boot ROM's ECDSA-P256 verification (Silex PK accelerator driver,
`sx_pk_mpi2mem()` in `drivers/microchip/crypto/silex_crypto.c`) left-aligns the
operand written to the BA414e accelerator and zero-pads it at the *tail*. The
accelerator expects a fixed-width, big-endian operand zero-padded at the
*front*.

Any P-256 value whose most-significant byte is `0x00` — i.e. a value below
2^248, which occurs for roughly **1 in 256** of random coordinates/scalars — is
therefore written shifted left by one or more bytes, corrupting the operand.
This affects the public-key coordinates (`X`, `Y`) and the signature scalars
(`r`, `s`).

Because the ROTPK hash is committed to OTP, an affected **ROT key cannot be
recovered** once programmed: the part will no longer complete secure boot.

### Affected verifications (BL1 / ROM)

BL1 authenticates, against the ROTPK, the certificates that root the chain of
trust:

- `trusted_boot_fw_cert` (image id **6**)
- `trusted_key_cert`

A leading-zero byte in the **ROTPK coordinate (X or Y)**, or in the **signature
(r or s) of the `trusted_boot_fw_cert`**, triggers the defect in ROM.

> Note: the same source file is also linked into BL2, where the equivalent
> failures (subkey certificates, content certificates, e.g. the Non-Trusted FW
> content certificate, image id 15) are corrected by the firmware fix in
> `LMSTAX-1677`. Only the BL1/ROM verifications above are unfixable in the
> field.

### How it manifests

Secure boot stops at the first affected image with one of:

- Leading-zero **X or Y** (a public-key coordinate) → point is off-curve →
  `SX_ERR_POINT_NOT_ON_CURVE` (**12**), logged as `Authenticated image id=6 (sign) = 12`.
- Leading-zero **r or s** (a signature scalar) → `SX_ERR_INVALID_SIGNATURE`
  (**7**), logged as `... id=6 sign=7`.

Both terminate boot with `Failed to load image ... (-80)`.

The failure is **key-/signature-dependent and intermittent across regenerations**:
regenerating the key or re-signing (which uses a fresh random `k`) will usually
produce clean values and appear to "fix" the problem, which is why it hides in
CI and in the field. Roughly **7.5%** of freshly generated certificate chains
contain at least one affected value somewhere.

### Workaround

Guarantee that no value verified by the ROM has a leading `0x00` byte, by
screening at key-generation, certificate-generation and provisioning time
(before the ROTPK hash is written to OTP):

1. **ROT key** — reject any ROT key whose public-key `X` or `Y` coordinate
   (32-byte big-endian, P-256) has a most-significant byte of `0x00`; regenerate
   until both coordinates are clean. This is mandatory: an affected ROTPK in OTP
   is unrecoverable.
2. **Certificate signatures** — reject/re-sign any certificate whose ECDSA
   signature `r` or `s` has a leading `0x00`. Re-signing draws a new random `k`,
   so re-running the signer produces clean scalars. At minimum this must cover
   the `trusted_boot_fw_cert`; screening the whole chain is simplest and also
   covers the BL2-verified certificates on unfixed firmware.
3. **Customer ROT keys** — vet customer-supplied ROT keys against rule 1 before
   accepting them for provisioning.

These guards are implemented build-side (see `LMSTAX-1657` / `LMSTAX-1676`) and
must remain in place for affected silicon regardless of the firmware fix.

### Not affected

- **lan966x** — the boot ROM uses a different accelerator path (PKCL,
  `drivers/microchip/crypto/pkcl.c`). Its operand marshalling is little-endian
  into pre-zeroed fixed-width slots, so a stripped leading `0x00` lands correctly
  as a zero high byte. lan966x is **not** affected by this erratum.
