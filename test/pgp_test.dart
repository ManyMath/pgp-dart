import 'package:pgp/pgp.dart';
import 'package:test/test.dart';

void main() {
  final pgp = PGP();

  test('generateKey returns a certificate handle', () {
    final cert = pgp.generateKey('someone@example.org');
    expect(cert.pointer.address, isNonZero);
    cert.dispose();
  });

  test('certificateFromArmored rejects invalid input', () {
    expect(() => pgp.certificateFromArmored('not a certificate'),
        throwsA(isA<PgpException>()));
  });

  test('exportArmored round-trips through certificateFromArmored', () {
    final cert = pgp.generateKey('someone@example.org');
    final armored = cert.exportArmored();
    expect(armored, contains('-----BEGIN PGP'));

    final parsed = pgp.certificateFromArmored(armored);
    expect(parsed.pointer.address, isNonZero);

    parsed.dispose();
    cert.dispose();
  });

  test('revoke returns a revoked certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final revoked = cert.revoke();
    expect(revoked.pointer.address, isNonZero);
    revoked.dispose();
    cert.dispose();
  });

  test('addTransportEncryptionSubkey returns an updated certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final updated = cert.addTransportEncryptionSubkey();
    expect(updated.pointer.address, isNonZero);
    updated.dispose();
    cert.dispose();
  });

  test('revokeSubkey revokes the generated subkey', () {
    // A generated certificate carries one transport-encryption subkey.
    final cert = pgp.generateKey('someone@example.org');
    final updated = cert.revokeSubkey(0);
    expect(updated.pointer.address, isNonZero);
    updated.dispose();
    cert.dispose();
  });

  test('addUserId returns an updated certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final updated = cert.addUserId('other@example.org');
    expect(updated.pointer.address, isNonZero);
    updated.dispose();
    cert.dispose();
  });
}
