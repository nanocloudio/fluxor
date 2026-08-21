# hsm_key_vault — PKCS#11 KEY_VAULT backend (Linux)

A kernel-resident **contract backend**, not a graph module. It is listed
under `modules/builtin/linux/` for inventory visibility only; it cannot be
instantiated from a graph YAML and declares no ports or params.

## What it is

`src/platform/linux/hsm_key_vault.rs` maps the `KEY_VAULT` (0x0010)
contract opcodes onto a PKCS#11 token:
`GENERATE` → `C_GenerateKeyPair` (non-extractable, key born in the token),
`SIGN` → raw `CKM_ECDSA` folded to low-s, `ECDH` → `CKM_ECDH1_DERIVE`,
`PUBLIC` → `CKA_EC_POINT`. `VERIFY` delegates to the kernel software
implementation (touches no custodial material); `STORE` is `ENOSYS`.

It registers at platform boot via `try_register_from_env`, replacing the
kernel software backend's class dispatch + vtable — the platform-
overridable backend pattern documented in `src/kernel/key_vault.rs`.
Consumers notice only through the contract's discovery opcodes:
`TIER = PROCESS_HW`, `CAPS = GENERATE | PUBLIC | NON_EXTRACTABLE |
ALG_P256`.

## Activation

Unset `FLUXOR_HSM_PKCS11_MODULE` → kernel software backend stays live.

```sh
export FLUXOR_HSM_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
export FLUXOR_HSM_TOKEN_LABEL=fluxor        # or FLUXOR_HSM_SLOT_ID=<n>
export FLUXOR_HSM_USER_PIN=1234
```

## Why it lives in the kernel binary

It dlopens a host C library (PKCS#11), which the PIC sandbox cannot do.
Per the kernel-residency rule in `docs/architecture/abi_layers.md`
("What may live in the kernel binary"), a service backend like this is
allowed in `src/platform/<platform>/` only behind an existing kernel
service contract, with honest `TIER`/`CAPS` advertisement and a
descriptor here.
