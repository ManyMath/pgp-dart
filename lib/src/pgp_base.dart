import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

import 'pgp-ffi_bindings_generated.dart' as ffi;

const String _libName = 'pgp_ffi';

/// The dynamic library in which the symbols for [ffi.PgpFfiBindings] can be
/// found.
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
final ffi.PgpFfiBindings _bindings = ffi.PgpFfiBindings(_dylib);

/// Status code returned by a `pgp-ffi` call.
class PgpException implements Exception {
  /// The non-zero `FFIError` code returned by `pgp-ffi`.
  final int code;

  PgpException(this.code);

  @override
  String toString() => 'PgpException: pgp-ffi returned $code';
}

/// A handle to an OpenPGP certificate owned by `pgp-ffi`.
///
/// The mutating methods return a new [Certificate]; the receiver is left
/// untouched and must be released separately.  Call [dispose] to free a
/// certificate once it is no longer needed.
class Certificate {
  final Pointer<ffi.Certificate> _ptr;

  Certificate._(this._ptr);

  /// The opaque native pointer, for passing to further FFI calls.
  Pointer<ffi.Certificate> get pointer => _ptr;

  /// Exports the certificate as an ASCII-armored secret key block.
  String exportArmored() {
    final out = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_certificate_export_armored(_ptr, out);
      if (code != 0) throw PgpException(code);
      final armored = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value); // Allocated by pgp-ffi with malloc.
      return armored;
    } finally {
      calloc.free(out);
    }
  }

  /// Revokes the certificate, returning the revoked certificate.
  Certificate revoke() =>
      _derive((out) => _bindings.pgp_certificate_revoke(_ptr, out));

  /// Adds a transport-encryption subkey, returning the updated certificate.
  Certificate addTransportEncryptionSubkey() => _derive((out) =>
      _bindings.pgp_certificate_add_transport_encryption_subkey(_ptr, out));

  /// Frees the native certificate.  The handle must not be used afterwards.
  void dispose() => _bindings.pgp_certificate_free(_ptr);

  /// Runs a `pgp-ffi` call that writes a new certificate to its out-pointer.
  Certificate _derive(int Function(Pointer<Pointer<ffi.Certificate>>) call) {
    final out = calloc<Pointer<ffi.Certificate>>();
    try {
      final code = call(out);
      if (code != 0) throw PgpException(code);
      return Certificate._(out.value);
    } finally {
      calloc.free(out);
    }
  }
}

class PGP {
  /// Generates a new certificate carrying [userId].
  Certificate generateKey(String userId) {
    final userIdPointer = userId.toNativeUtf8();
    final out = calloc<Pointer<ffi.Certificate>>();
    try {
      final code =
          _bindings.pgp_key_generate(userIdPointer.cast(), out);
      if (code != 0) throw PgpException(code);
      return Certificate._(out.value);
    } finally {
      calloc.free(userIdPointer);
      calloc.free(out);
    }
  }

  /// Parses an ASCII-armored certificate.
  Certificate certificateFromArmored(String armored) {
    final armoredPointer = armored.toNativeUtf8();
    final out = calloc<Pointer<ffi.Certificate>>();
    try {
      final code =
          _bindings.pgp_certificate_from_armored(armoredPointer.cast(), out);
      if (code != 0) throw PgpException(code);
      return Certificate._(out.value);
    } finally {
      calloc.free(armoredPointer);
      calloc.free(out);
    }
  }
}
