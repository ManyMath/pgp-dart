## 0.0.1-dev.3

- Track `pgp-ffi` opaque certificate types.  `PGP` now returns `Certificate`
  handles from `generateKey` and `certificateFromArmored`; release them with
  `Certificate.dispose`.

## 0.0.1-dev.1

- Initial version.
