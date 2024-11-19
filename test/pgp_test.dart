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
}
