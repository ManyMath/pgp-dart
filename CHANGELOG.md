## 0.0.1-dev.5

- Remove native_toolchain_rust builds.  Drop the Dart Native Assets build hook 
  and the `native_assets_cli` / `native_toolchain_rust_mirror` dependencies.
  The package now loads a prebuilt `libpgp_ffi` at runtime via 
  `DynamicLibrary.open`, searching the executable and working directories plus 
  `pgp-ffi/target/release/`. Build the crate yourself with 
  `cargo build --release --manifest-path pgp-ffi/Cargo.toml`.

## 0.0.1-dev.4

- Add certificate key management following `pgp-ffi`: `exportArmored`,
  `revoke`, `addTransportEncryptionSubkey`, `revokeSubkey`, `addUserId`, and
  `revokeUserId` on `Certificate`.

## 0.0.1-dev.3

- Track `pgp-ffi` opaque certificate types.  `PGP` now returns `Certificate`
  handles from `generateKey` and `certificateFromArmored`; release them with
  `Certificate.dispose`.

## 0.0.1-dev.1

- Initial version.
