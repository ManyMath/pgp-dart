# `pgp`

OpenPGP for Dart.  A command-line interface and library.

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
