# `pgp`
OpenPGP and Sequoia for Dart, backed by the `pgp-ffi` Rust crate.

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
revoking user IDs and subkeys, and revoking the certificate.

## Development
- To generate the `lib/src/pgp-ffi_bindings_generated.dart` bindings for the
  `pgp-ffi` C header:
  ```
  dart run ffigen --config ffigen.yaml
  ```
- New bindings expose opaque pointers and status codes.  Each native function
  needs a hand-written wrapper in `lib/src/pgp_base.dart` (see `generateKey`).
