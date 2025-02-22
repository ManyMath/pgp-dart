# `pgp`
OpenPGP and Sequoia for Dart, backed by the `pgp-ffi` Rust crate.

`package:pgp` is the Flutter-free, pure-Dart `dart:ffi` binding over a prebuilt
native library (`libpgp_ffi.{so,dylib,dll}`). It does not ship or build the
binary for you; build the crate first (see
[Building the native library](#building-the-native-library)). A separate
`pgp_flutter` package will build and bundle it via cargokit for Flutter apps.

## Getting started
Add the package:
```sh
dart pub add pgp
```

Generate a certificate, manage its keys and user IDs, and export it:
```dart
import 'package:pgp/pgp.dart';

void main() {
  final pgp = PGP();
  var cert = pgp.generateKey('someone@example.org');

  // Key-management methods return a new certificate; dispose the old one.
  final updated = cert.addUserId('other@example.org');
  cert.dispose();
  cert = updated;

  print(cert.exportArmored());
  cert.dispose();
}
```

See `example/pgp_example.dart` for the full set of operations: adding and
revoking user IDs and subkeys, and revoking the certificate. Build the native
library first, then run it from the package root:
```sh
dart run example/pgp_example.dart
```

## Building the native library
The package loads `libpgp_ffi` at runtime via `DynamicLibrary.open`. The crate
lives in the `pgp-ffi` git submodule; build it with `cargo`:
```sh
git submodule update --init   # fetch pgp-ffi if needed
cargo build --release --manifest-path pgp-ffi/Cargo.toml
```
The artifact lands in `pgp-ffi/target/release/`: `libpgp_ffi.so` (Linux),
`libpgp_ffi.dylib` (macOS), or `pgp_ffi.dll` (Windows).

The loader searches that directory relative to the current directory, so
running from the package root works without copying anything. For a compiled
executable, put the library on the dynamic library search path: next to the
executable (or its `lib/`), in the working directory (or its `lib/`), or on
`LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH` / `PATH`. If loading fails, the package
throws an `ArgumentError` listing every path it tried.

## Development
- To generate the `lib/src/pgp-ffi_bindings_generated.dart` bindings for the
  `pgp-ffi` C header:
  ```
  dart run ffigen --config ffigen.yaml
  ```
- New bindings expose opaque pointers and status codes.  Each native function
  needs a hand-written wrapper in `lib/src/pgp_base.dart` (see `generateKey`).
