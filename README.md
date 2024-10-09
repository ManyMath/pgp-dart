# `pgp`
OpenPGP and Sequoia for Dart.  A command-line interface and library.

## Getting started
Run the command-line interface:
```sh
dart pub activate pgp
pgp
```

or use the library as in:
```dart
dart pub add pgp
```
<!--
```dart
import 'package:pgp/pgp.dart';

void main() {
    final pgp = OpenPGP();
    final keyPair = pgp.generateKeyPair();
    final publicKey = keyPair.publicKey;
}
```

## Development
- To generate `pgp-ffi_bindings_generated.dart` Dart bindings for C:
  ```
  dart --enable-experiment=native-assets run ffigen --config ffigen.yaml
  ```
- If bindings are generated for a new (not previously supported/included in 
  `lib/pgp_base.dart`) function, a wrapper must be written for it by hand 
  (see: `generateMnemonic`, `generateAddress`).
