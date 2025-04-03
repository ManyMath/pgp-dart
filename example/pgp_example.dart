import 'package:pgp/pgp.dart';

void main() {
  final pgp = PGP();

  // Generate a certificate with encryption and signing subkeys.
  var cert = pgp.generateKey('someone@example.org');
  final publicCert = pgp.certificateFromArmored(cert.exportPublicArmored());

  final encrypted = publicCert.encrypt('hello OpenPGP');
  print(cert.decrypt(encrypted));

  final signed = cert.sign('hello signed OpenPGP');
  print(publicCert.verify(signed));
  publicCert.dispose();

  // Key-management methods return a new certificate; dispose the old one.
  cert = _replace(cert, cert.addUserId('other@example.org'));
  cert = _replace(cert, cert.addTransportEncryptionSubkey());
  cert = _replace(cert, cert.revokeUserId('other@example.org'));
  cert = _replace(cert, cert.revokeSubkey(0));
  cert = _replace(cert, cert.revoke());

  print(cert.exportSecretArmored());
  cert.dispose();
}

/// Disposes [old] and returns [updated] in its place.
Certificate _replace(Certificate old, Certificate updated) {
  old.dispose();
  return updated;
}
