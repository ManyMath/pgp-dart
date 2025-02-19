import 'package:pgp/pgp.dart';

void main() {
  final pgp = PGP();

  // Generate a certificate, then evolve it through the key-management API.
  // Each step returns a new certificate, so the previous handle is disposed.
  var cert = pgp.generateKey('someone@example.org');
  cert = _replace(cert, cert.addUserId('other@example.org'));
  cert = _replace(cert, cert.addTransportEncryptionSubkey());
  cert = _replace(cert, cert.revokeUserId('other@example.org'));
  cert = _replace(cert, cert.revokeSubkey(1));
  cert = _replace(cert, cert.revoke());

  print(cert.exportArmored());
  cert.dispose();
}

/// Disposes [old] and returns [updated] in its place.
Certificate _replace(Certificate old, Certificate updated) {
  old.dispose();
  return updated;
}
