import 'dart:ffi';

import 'package:ffi/ffi.dart';

import 'native_library.dart';
import 'pgp-ffi_bindings_generated.dart' as ffi;

/// The bindings to the native functions in [nativeLibrary].
final ffi.PgpFfiBindings _bindings = ffi.PgpFfiBindings(nativeLibrary);

/// A snapshot of certificate metadata returned by [Certificate.info].
class CertificateInfo {
  /// 40-character uppercase hex fingerprint (v4 key).
  final String fingerprint;

  /// All user IDs on the certificate, including revoked ones.
  final List<String> userIds;

  /// Primary key expiration as seconds since the Unix epoch; 0 means no expiry.
  final int expiryEpoch;

  const CertificateInfo({
    required this.fingerprint,
    required this.userIds,
    required this.expiryEpoch,
  });

  /// Whether this certificate has an expiry date set.
  bool get hasExpiry => expiryEpoch != 0;

  /// The expiry as a UTC [DateTime], or null if no expiry is set.
  DateTime? get expiryDate => hasExpiry
      ? DateTime.fromMillisecondsSinceEpoch(expiryEpoch * 1000, isUtc: true)
      : null;
}

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

  /// Exports the certificate as an ASCII-armored public key block.
  String exportPublicArmored() => _exportArmored(
        _bindings.pgp_certificate_export_public_armored,
      );

  /// Exports the certificate as an ASCII-armored secret key block.
  String exportSecretArmored() => _exportArmored(
        _bindings.pgp_certificate_export_secret_armored,
      );

  /// Exports the certificate as an ASCII-armored secret key block.
  ///
  /// Prefer [exportPublicArmored] when sharing a certificate with others.
  String exportArmored() => exportSecretArmored();

  /// Encrypts [plaintext] to this certificate as an ASCII-armored message.
  String encrypt(String plaintext) => _transformString(
        plaintext,
        _bindings.pgp_certificate_encrypt_string,
      );

  /// Decrypts an ASCII-armored [message] with this secret certificate.
  String decrypt(String message) => _transformString(
        message,
        _bindings.pgp_certificate_decrypt_string,
      );

  /// Signs [plaintext] with this secret certificate as an armored message.
  String sign(String plaintext) => _transformString(
        plaintext,
        _bindings.pgp_certificate_sign_string,
      );

  /// Verifies an armored signed [message] with this certificate.
  ///
  /// Returns the message plaintext if the signature is valid.
  String verify(String message) => _transformString(
        message,
        _bindings.pgp_certificate_verify_string,
      );

  String _exportArmored(
    int Function(Pointer<ffi.Certificate>, Pointer<Pointer<Char>>) call,
  ) {
    final out = calloc<Pointer<Char>>();
    try {
      final code = call(_ptr, out);
      if (code != 0) throw PgpException(code);
      final armored = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value); // Allocated by pgp-ffi with malloc.
      return armored;
    } finally {
      calloc.free(out);
    }
  }

  String _transformString(
    String input,
    int Function(
      Pointer<ffi.Certificate>,
      Pointer<Char>,
      Pointer<Pointer<Char>>,
    ) call,
  ) {
    final inputPointer = input.toNativeUtf8();
    final out = calloc<Pointer<Char>>();
    try {
      final code = call(_ptr, inputPointer.cast(), out);
      if (code != 0) throw PgpException(code);
      final result = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value); // Allocated by pgp-ffi with malloc.
      return result;
    } finally {
      calloc.free(inputPointer);
      calloc.free(out);
    }
  }

  /// Revokes the certificate, returning the revoked certificate.
  Certificate revoke() =>
      _derive((out) => _bindings.pgp_certificate_revoke(_ptr, out));

  /// Adds a transport-encryption subkey, returning the updated certificate.
  Certificate addTransportEncryptionSubkey() => _derive((out) =>
      _bindings.pgp_certificate_add_transport_encryption_subkey(_ptr, out));

  /// Adds a signing subkey, returning the updated certificate.
  Certificate addSigningSubkey() =>
      _derive((out) => _bindings.pgp_certificate_add_signing_subkey(_ptr, out));

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

  /// Returns the primary key fingerprint as a 40-character uppercase hex string.
  String fingerprint() {
    final out = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_certificate_fingerprint(_ptr, out);
      if (code != 0) throw PgpException(code);
      final result = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value);
      return result;
    } finally {
      calloc.free(out);
    }
  }

  /// Returns all user IDs on this certificate, including revoked ones.
  List<String> userIds() {
    final out = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_certificate_userids(_ptr, out);
      if (code != 0) throw PgpException(code);
      final raw = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value);
      return raw.isEmpty ? [] : raw.split('\n');
    } finally {
      calloc.free(out);
    }
  }

  /// Returns the primary key expiration as seconds since the Unix epoch,
  /// or 0 if the certificate has no expiry.
  int expiryEpoch() {
    final out = calloc<Int64>();
    try {
      final code = _bindings.pgp_certificate_expiry_epoch(_ptr, out);
      if (code != 0) throw PgpException(code);
      return out.value;
    } finally {
      calloc.free(out);
    }
  }

  /// Returns a [CertificateInfo] snapshot combining fingerprint, user IDs,
  /// and expiry epoch in a single call.
  CertificateInfo info() => CertificateInfo(
        fingerprint: fingerprint(),
        userIds: userIds(),
        expiryEpoch: expiryEpoch(),
      );

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
  /// Encrypts [plaintext] to every certificate in [recipients], returning a
  /// single ASCII-armored OpenPGP message that any recipient can decrypt.
  ///
  /// Throws [PgpException] if [recipients] is empty or no certificate has a
  /// usable transport-encryption subkey.
  static String encryptToRecipients(
      List<Certificate> recipients, String plaintext) {
    if (recipients.isEmpty) throw PgpException(-4); // FFIError::NotFound

    final certsArray =
        calloc<Pointer<ffi.Certificate>>(recipients.length);
    for (var i = 0; i < recipients.length; i++) {
      certsArray[i] = recipients[i].pointer;
    }
    final plaintextPtr = plaintext.toNativeUtf8();
    final out = calloc<Pointer<Char>>();
    try {
      final code = _bindings.pgp_encrypt_string_to_recipients(
        certsArray.cast(),
        recipients.length,
        plaintextPtr.cast(),
        out,
      );
      if (code != 0) throw PgpException(code);
      final result = out.value.cast<Utf8>().toDartString();
      calloc.free(out.value);
      return result;
    } finally {
      calloc.free(certsArray);
      calloc.free(plaintextPtr);
      calloc.free(out);
    }
  }

  /// Generates a new certificate carrying [userId].
  Certificate generateKey(String userId) {
    final userIdPointer = userId.toNativeUtf8();
    final out = calloc<Pointer<ffi.Certificate>>();
    try {
      final code = _bindings.pgp_key_generate(userIdPointer.cast(), out);
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
