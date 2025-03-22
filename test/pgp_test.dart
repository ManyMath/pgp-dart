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
    expect(armored, contains('-----BEGIN PGP PRIVATE KEY BLOCK-----'));

    final parsed = pgp.certificateFromArmored(armored);
    expect(parsed.pointer.address, isNonZero);

    parsed.dispose();
    cert.dispose();
  });

  test('exportPublicArmored emits a public key block', () {
    final cert = pgp.generateKey('someone@example.org');
    final armored = cert.exportPublicArmored();
    expect(armored, contains('-----BEGIN PGP PUBLIC KEY BLOCK-----'));
    expect(armored, isNot(contains('PRIVATE KEY BLOCK')));
    cert.dispose();
  });

  test('exportSecretArmored emits a private key block', () {
    final cert = pgp.generateKey('someone@example.org');
    final armored = cert.exportSecretArmored();
    expect(armored, contains('-----BEGIN PGP PRIVATE KEY BLOCK-----'));
    cert.dispose();
  });

  test('encrypt and decrypt round-trip through a public certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final publicCert = pgp.certificateFromArmored(cert.exportPublicArmored());

    final encrypted = publicCert.encrypt('hello OpenPGP');
    expect(encrypted, contains('-----BEGIN PGP MESSAGE-----'));
    expect(cert.decrypt(encrypted), 'hello OpenPGP');

    publicCert.dispose();
    cert.dispose();
  });

  test('decrypt rejects a public-only certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final publicCert = pgp.certificateFromArmored(cert.exportPublicArmored());
    final encrypted = publicCert.encrypt('hello OpenPGP');

    expect(() => publicCert.decrypt(encrypted), throwsA(isA<PgpException>()));

    publicCert.dispose();
    cert.dispose();
  });

  test('sign and verify round-trip through a public certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final publicCert = pgp.certificateFromArmored(cert.exportPublicArmored());

    final signed = cert.sign('hello signed OpenPGP');
    expect(signed, contains('-----BEGIN PGP MESSAGE-----'));
    expect(publicCert.verify(signed), 'hello signed OpenPGP');

    publicCert.dispose();
    cert.dispose();
  });

  test('verify rejects a different certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final other = pgp.generateKey('other@example.org');
    final signed = cert.sign('hello signed OpenPGP');

    expect(() => other.verify(signed), throwsA(isA<PgpException>()));

    other.dispose();
    cert.dispose();
  });

  test('revoke returns a revoked certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final revoked = cert.revoke();
    expect(revoked.pointer.address, isNonZero);
    revoked.dispose();
    cert.dispose();
  });

  test('addSigningSubkey returns an updated certificate', () {
    final cert = pgp.generateKey('someone@example.org');
    final updated = cert.addSigningSubkey();
    expect(updated.pointer.address, isNonZero);
    updated.dispose();
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
    // The first generated subkey is transport-encryption capable.
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

  test('revokeUserId revokes an added user ID', () {
    final cert = pgp.generateKey('someone@example.org');
    final withUser = cert.addUserId('other@example.org');
    final revoked = withUser.revokeUserId('other@example.org');
    expect(revoked.pointer.address, isNonZero);
    revoked.dispose();
    withUser.dispose();
    cert.dispose();
  });
}
