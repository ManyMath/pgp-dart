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

  group('key expiration', () {
    test('generateKeyWithExpiry returns a valid certificate handle', () {
      final cert = pgp.generateKeyWithExpiry(
          'alice@example.org', const Duration(hours: 1));
      expect(cert.pointer.address, isNonZero);
      cert.dispose();
    });

    test('generateKeyWithExpiry with Duration.zero behaves like generateKey', () {
      final cert =
          pgp.generateKeyWithExpiry('alice@example.org', Duration.zero);
      final encrypted = cert.encrypt('hello');
      expect(encrypted, contains('-----BEGIN PGP MESSAGE-----'));
      cert.dispose();
    });

    test('generateKeyWithExpiry with null validity behaves like generateKey', () {
      final cert = pgp.generateKeyWithExpiry('alice@example.org', null);
      expect(cert.pointer.address, isNonZero);
      cert.dispose();
    });

    test('generateKeyWithExpiry expiry is readable via expiryEpoch', () {
      final cert = pgp.generateKeyWithExpiry(
          'alice@example.org', const Duration(hours: 1));
      expect(cert.expiryEpoch(), greaterThan(0));
      cert.dispose();
    });

    test('setExpiry returns an updated certificate handle', () {
      final cert = pgp.generateKey('alice@example.org');
      final updated = cert.setExpiry(const Duration(hours: 2));
      expect(updated.pointer.address, isNonZero);
      updated.dispose();
      cert.dispose();
    });

    test('setExpiry with null clears the expiry', () {
      final cert = pgp.generateKey('alice@example.org');
      final withExpiry = cert.setExpiry(const Duration(hours: 2));
      final cleared = withExpiry.setExpiry(null);
      expect(cleared.expiryEpoch(), 0);
      cleared.dispose();
      withExpiry.dispose();
      cert.dispose();
    });

    test('key with far-future expiry can encrypt and decrypt', () {
      final cert = pgp.generateKeyWithExpiry(
          'alice@example.org', const Duration(days: 365));
      final encrypted = cert.encrypt('expiring key test');
      expect(cert.decrypt(encrypted), 'expiring key test');
      cert.dispose();
    });
  });

  group('detached signatures', () {
    test('signDetached returns an armored signature block', () {
      final cert = pgp.generateKey('someone@example.org');
      final sig = cert.signDetached('hello detached OpenPGP');
      expect(sig, contains('-----BEGIN PGP SIGNATURE-----'));
      cert.dispose();
    });

    test('signDetached does not wrap content in a PGP Message', () {
      final cert = pgp.generateKey('someone@example.org');
      final sig = cert.signDetached('hello detached OpenPGP');
      expect(sig, isNot(contains('-----BEGIN PGP MESSAGE-----')));
      cert.dispose();
    });

    test('verifyDetached round-trips through a public certificate', () {
      final cert = pgp.generateKey('someone@example.org');
      final pub =
          pgp.certificateFromArmored(cert.exportPublicArmored());
      const plain = 'hello detached OpenPGP';
      final sig = cert.signDetached(plain);
      expect(pub.verifyDetached(plain, sig), isTrue);
      pub.dispose();
      cert.dispose();
    });

    test('verifyDetached rejects a different certificate', () {
      final cert = pgp.generateKey('someone@example.org');
      final other = pgp.generateKey('other@example.org');
      final sig = cert.signDetached('hello detached OpenPGP');
      expect(
        () => other.verifyDetached('hello detached OpenPGP', sig),
        throwsA(isA<PgpException>()),
      );
      other.dispose();
      cert.dispose();
    });

    test('verifyDetached rejects tampered content', () {
      final cert = pgp.generateKey('someone@example.org');
      final sig = cert.signDetached('hello detached OpenPGP');
      expect(
        () => cert.verifyDetached('tampered content', sig),
        throwsA(isA<PgpException>()),
      );
      cert.dispose();
    });
  });

  group('passphrase-protected keys', () {
    test('unlock with correct passphrase enables decrypt', () {
      final locked = pgp.generateLockedKey('locked@example.org', 'hunter2');
      final unlocked = locked.unlock('hunter2');
      final pub =
          pgp.certificateFromArmored(locked.exportPublicArmored());
      final cipher = pub.encrypt('secret message');
      expect(unlocked.decrypt(cipher), 'secret message');
      pub.dispose();
      unlocked.dispose();
      locked.dispose();
    });

    test('unlock with wrong passphrase throws PgpException(-2)', () {
      final locked =
          pgp.generateLockedKey('locked@example.org', 'correcthorse');
      expect(
        () => locked.unlock('wrongpassphrase'),
        throwsA(isA<PgpException>().having((e) => e.code, 'code', -2)),
      );
      locked.dispose();
    });

    test('unlock on public-only cert throws PgpException(-4)', () {
      final cert = pgp.generateKey('someone@example.org');
      final pub =
          pgp.certificateFromArmored(cert.exportPublicArmored());
      expect(
        () => pub.unlock('anypassphrase'),
        throwsA(isA<PgpException>().having((e) => e.code, 'code', -4)),
      );
      pub.dispose();
      cert.dispose();
    });

    test('unlock then sign produces a verifiable message', () {
      final locked =
          pgp.generateLockedKey('signer@example.org', 's3cr3t');
      final unlocked = locked.unlock('s3cr3t');
      final pub =
          pgp.certificateFromArmored(locked.exportPublicArmored());
      final signed = unlocked.sign('authenticated text');
      expect(pub.verify(signed), 'authenticated text');
      pub.dispose();
      unlocked.dispose();
      locked.dispose();
    });

    test('unlock on already-unlocked cert is a no-op', () {
      final cert = pgp.generateKey('someone@example.org');
      final same = cert.unlock('');
      expect(same.pointer.address, isNonZero);
      same.dispose();
      cert.dispose();
    });
  });

  group('certificate inspection', () {
    test('fingerprint is 40-character uppercase hex', () {
      final cert = pgp.generateKey('alice@example.org');
      final fp = cert.fingerprint();
      expect(fp.length, 40);
      expect(fp, matches(RegExp(r'^[0-9A-F]{40}$')));
      cert.dispose();
    });

    test('fingerprint is stable across export/import round-trip', () {
      final cert = pgp.generateKey('alice@example.org');
      final fp1 = cert.fingerprint();
      final parsed =
          pgp.certificateFromArmored(cert.exportPublicArmored());
      final fp2 = parsed.fingerprint();
      expect(fp1, fp2);
      parsed.dispose();
      cert.dispose();
    });

    test('userIds contains the user ID supplied at generation', () {
      final cert = pgp.generateKey('alice@example.org');
      expect(cert.userIds(), contains('alice@example.org'));
      cert.dispose();
    });

    test('userIds lists multiple user IDs after addUserId', () {
      final cert = pgp.generateKey('alice@example.org');
      final updated = cert.addUserId('alias@example.org');
      final ids = updated.userIds();
      expect(ids, contains('alice@example.org'));
      expect(ids, contains('alias@example.org'));
      updated.dispose();
      cert.dispose();
    });

    test('userIds still lists a revoked user ID', () {
      final cert = pgp.generateKey('alice@example.org');
      final withExtra = cert.addUserId('alias@example.org');
      final revoked = withExtra.revokeUserId('alias@example.org');
      expect(revoked.userIds(), contains('alias@example.org'));
      revoked.dispose();
      withExtra.dispose();
      cert.dispose();
    });

    test('expiryEpoch returns 0 for a certificate with no expiry', () {
      final cert = pgp.generateKey('alice@example.org');
      expect(cert.expiryEpoch(), 0);
      cert.dispose();
    });

    test('info() returns consistent CertificateInfo', () {
      final cert = pgp.generateKey('alice@example.org');
      final info = cert.info();
      expect(info.fingerprint, cert.fingerprint());
      expect(info.userIds, containsAll(cert.userIds()));
      expect(info.expiryEpoch, cert.expiryEpoch());
      expect(info.hasExpiry, isFalse);
      expect(info.expiryDate, isNull);
      cert.dispose();
    });
  });

  group('encryptToRecipients', () {
    test('encrypts to two recipients, each can decrypt', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final alicePub =
          pgp.certificateFromArmored(alice.exportPublicArmored());
      final bobPub = pgp.certificateFromArmored(bob.exportPublicArmored());

      final cipher =
          PGP.encryptToRecipients([alicePub, bobPub], 'hello both');
      expect(cipher, contains('-----BEGIN PGP MESSAGE-----'));
      expect(alice.decrypt(cipher), 'hello both');
      expect(bob.decrypt(cipher), 'hello both');

      alicePub.dispose();
      bobPub.dispose();
      alice.dispose();
      bob.dispose();
    });

    test('sender-can-read pattern', () {
      final sender = pgp.generateKey('sender@example.org');
      final receiver = pgp.generateKey('receiver@example.org');
      final senderPub =
          pgp.certificateFromArmored(sender.exportPublicArmored());
      final receiverPub =
          pgp.certificateFromArmored(receiver.exportPublicArmored());

      final cipher =
          PGP.encryptToRecipients([senderPub, receiverPub], 'sent mail');
      expect(sender.decrypt(cipher), 'sent mail');
      expect(receiver.decrypt(cipher), 'sent mail');

      senderPub.dispose();
      receiverPub.dispose();
      sender.dispose();
      receiver.dispose();
    });

    test('single recipient matches encrypt()', () {
      final cert = pgp.generateKey('solo@example.org');
      final pub = pgp.certificateFromArmored(cert.exportPublicArmored());

      final viaMulti = PGP.encryptToRecipients([pub], 'solo message');
      expect(cert.decrypt(viaMulti), 'solo message');

      pub.dispose();
      cert.dispose();
    });

    test('throws PgpException for empty recipient list', () {
      expect(
        () => PGP.encryptToRecipients([], 'hello'),
        throwsA(isA<PgpException>()),
      );
    });

    test('non-recipient cannot decrypt', () {
      final alice = pgp.generateKey('alice@example.org');
      final bob = pgp.generateKey('bob@example.org');
      final eve = pgp.generateKey('eve@example.org');
      final alicePub =
          pgp.certificateFromArmored(alice.exportPublicArmored());
      final bobPub = pgp.certificateFromArmored(bob.exportPublicArmored());

      final cipher = PGP.encryptToRecipients([alicePub, bobPub], 'secret');
      expect(() => eve.decrypt(cipher), throwsA(isA<PgpException>()));

      alicePub.dispose();
      bobPub.dispose();
      alice.dispose();
      bob.dispose();
      eve.dispose();
    });
  });
}
