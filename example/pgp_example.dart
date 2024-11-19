import 'package:pgp/pgp.dart';

void main() {
  final pgp = PGP();

  // Generate a certificate for a user ID.
  final cert = pgp.generateKey('someone@example.org');
  print('Generated certificate: ${cert.pointer}');

  // Release the native certificate when done.
  cert.dispose();
}
