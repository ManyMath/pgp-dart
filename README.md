# `pgp`
OpenPGP and Sequoia for Dart, backed by the `pgp-ffi` Rust crate.

## Getting started
Add the package:
```sh
dart pub add pgp
```

Generate a certificate and release it when done:
```dart
import 'package:pgp/pgp.dart';

void main() {
  final pgp = PGP();
  final cert = pgp.generateKey('someone@example.org');
  // ... use cert.pointer with further FFI calls ...
  cert.dispose();
}
```

## Development
- To generate the `lib/src/pgp-ffi_bindings_generated.dart` bindings for the
  `pgp-ffi` C header:
  ```
  dart run ffigen --config ffigen.yaml
  ```
- New bindings expose opaque pointers and status codes.  Each native function
  needs a hand-written wrapper in `lib/src/pgp_base.dart` (see `generateKey`).
