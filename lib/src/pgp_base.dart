import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

import 'pgp-ffi_bindings_generated.dart';

const String _libName = 'pgp_ffi';

/// The dynamic library in which the symbols for [PgpFfiBindings] can be found.
final DynamicLibrary _dylib = () {
  if (Platform.isMacOS || Platform.isIOS) {
    return DynamicLibrary.open(
        'rust/target/release/$_libName.framework/lib$_libName');
  }
  if (Platform.isAndroid || Platform.isLinux) {
    return DynamicLibrary.open('pgp-ffi/target/release/lib$_libName.so');
  }
  if (Platform.isWindows) {
    return DynamicLibrary.open('pgp-ffi/target/release/lib$_libName.dll');
  }
  throw UnsupportedError('Unknown platform: ${Platform.operatingSystem}');
}();

/// The bindings to the native functions in [_dylib].
final PgpFfiBindings _bindings = PgpFfiBindings(_dylib);

class PGP {
  /// Generates a new PGP key.
  String generateKey() {
    final resultPointer = _bindings.generate_key();
    final result = resultPointer.cast<Utf8>().toDartString();
    calloc.free(resultPointer); // Free memory
    return result;
  }

  /// Exports the key in ASCII-armored format.
  String exportAsciiKey(String cert) {
    final certPointer = cert.toNativeUtf8();
    final resultPointer = _bindings.export_ascii_key(certPointer.cast());
    final result = resultPointer.cast<Utf8>().toDartString();
    calloc.free(certPointer);
    calloc.free(resultPointer); // Free memory
    return result;
  }

  /// Encrypts the provided message with the given PGP certificate.
  String encryptMessage(String cert, String message) {
    final certPointer = cert.toNativeUtf8();
    final messagePointer = message.toNativeUtf8();
    final resultPointer =
        _bindings.encrypt_message(certPointer.cast(), messagePointer.cast());
    final result = resultPointer.cast<Utf8>().toDartString();
    calloc.free(certPointer);
    calloc.free(messagePointer);
    calloc.free(resultPointer); // Free memory
    return result;
  }

  /// Decrypts the provided ciphertext with the given PGP certificate.
  String decryptMessage(String cert, String ciphertext) {
    final certPointer = cert.toNativeUtf8();
    final ciphertextPointer = ciphertext.toNativeUtf8();
    final resultPointer =
        _bindings.decrypt_message(certPointer.cast(), ciphertextPointer.cast());
    final result = resultPointer.cast<Utf8>().toDartString();
    calloc.free(certPointer);
    calloc.free(ciphertextPointer);
    calloc.free(resultPointer); // Free memory
    return result;
  }
}
