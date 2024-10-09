import 'package:pgp/pgp.dart';

void main() {
  final pgp = PGP();

  // Generate a PGP key.
  final key = pgp.generateKey();
  print("Generated Key: \n$key");

  // Export the key in ASCII-armored format.
  final asciiKey = pgp.exportAsciiKey(key);
  print("ASCII-Armored Key: \n$asciiKey");

  // Encrypt a message.
  const message = "Hello, world!";
  final encrypted = pgp.encryptMessage(key, message);
  print("Encrypted Message: \n$encrypted");

  // Decrypt the message.
  final decrypted = pgp.decryptMessage(key, encrypted);
  print("Decrypted Message: \n$decrypted");
}
