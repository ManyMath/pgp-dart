import 'dart:ffi';

import 'package:ffi/ffi.dart';

import 'native_library.dart';
import 'pgp-ffi_bindings_generated.dart' as ffi;

/// The bindings to the native functions in [nativeLibrary].
final ffi.PgpFfiBindings _bindings = ffi.PgpFfiBindings(nativeLibrary);

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

  /// Revokes the subkey at [index] (counting subkeys only), returning the
  /// updated certificate.
  Certificate revokeSubkey(int index) => _derive(
      (out) => _bindings.pgp_certificate_revoke_subkey(_ptr, index, out));

  /// Adds [userId] to the certificate, returning the updated certificate.
  Certificate addUserId(String userId) {
    final userIdPointer = userId.toNativeUtf8();
    try {
      return _derive((out) => _bindings.pgp_certificate_add_userid(
          _ptr, userIdPointer.cast(), out));
    } finally {
      calloc.free(userIdPointer);
    }
  }

  /// Revokes the exact-match [userId], returning the updated certificate.
  Certificate revokeUserId(String userId) {
    final userIdPointer = userId.toNativeUtf8();
    try {
      return _derive((out) => _bindings.pgp_certificate_revoke_userid(
          _ptr, userIdPointer.cast(), out));
    } finally {
      calloc.free(userIdPointer);
    }
  }

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
