import { describe, expect, it } from '@ohos/hypium';
import { Base64Url } from '../main/ets/jwt/Base64Url';
import { JwtBuilder, JwtParts } from '../main/ets/jwt/JwtBuilder';
import { PemKeyLoader, PemType } from '../main/ets/jwt/PemKeyLoader';

export default function jwtBuilderTest() {
  describe('JwtBuilder', () => {
    it('headerIsPs256Jwt', 0, () => {
      const parts = JwtBuilder.unsigned(JwtBuilder.header('k1'), JwtBuilder.claims('i', 's', 'a', 0, 1, 'j'));
      expect(parts.header).assertEqual('eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImsxIn0');
    });

    it('expIsIatPlusLifetime', 0, () => {
      const claims = JwtBuilder.claims('iss', 'sub', 'aud', 1700000000, 3600, 'id-1');
      expect(claims.iat).assertEqual(1700000000);
      expect(claims.exp).assertEqual(1700003600);
    });

    it('payloadContainsAllClaims', 0, () => {
      const parts = JwtBuilder.unsigned(JwtBuilder.header('k1'),
        JwtBuilder.claims('iss', 'sub', 'aud', 10, 20, 'id-1'));
      expect(Base64Url.decodeText(parts.payload))
        .assertEqual('{"iss":"iss","sub":"sub","aud":"aud","iat":10,"exp":30,"jti":"id-1"}');
    });

    it('signingInputIsHeaderDotPayload', 0, () => {
      const parts = new JwtParts();
      parts.header = 'aaa';
      parts.payload = 'bbb';
      parts.signature = 'ccc';
      expect(JwtBuilder.signingInput(parts)).assertEqual('aaa.bbb');
      expect(parts.token()).assertEqual('aaa.bbb.ccc');
    });

    it('splitNeedsThreeParts', 0, () => {
      expect(JwtBuilder.split('a.b.c').payload).assertEqual('b');
      let failed = false;
      try {
        JwtBuilder.split('a.b');
      } catch (err) {
        failed = true;
      }
      expect(failed).assertTrue();
    });
  });

  describe('PemKeyLoader', () => {
    it('detectsPemTypes', 0, () => {
      expect(PemKeyLoader.detect('-----BEGIN PRIVATE KEY-----')).assertEqual(PemType.PKCS8_PRIVATE);
      expect(PemKeyLoader.detect('-----BEGIN RSA PRIVATE KEY-----')).assertEqual(PemType.PKCS1_PRIVATE);
      expect(PemKeyLoader.detect('-----BEGIN ENCRYPTED PRIVATE KEY-----')).assertEqual(PemType.ENCRYPTED_PRIVATE);
      expect(PemKeyLoader.detect('-----BEGIN PUBLIC KEY-----')).assertEqual(PemType.X509_PUBLIC);
      expect(PemKeyLoader.detect('hello')).assertEqual(PemType.UNKNOWN);
    });

    it('rejectsPublicKeyAsPrivateKey', 0, () => {
      let message = '';
      try {
        PemKeyLoader.checkPrivateKey('-----BEGIN PUBLIC KEY-----');
      } catch (err) {
        message = (err as Error).message;
      }
      expect(message.includes('X.509 public key')).assertTrue();
    });

    it('rejectsEncryptedKey', 0, () => {
      let failed = false;
      try {
        PemKeyLoader.checkPrivateKey('-----BEGIN ENCRYPTED PRIVATE KEY-----');
      } catch (err) {
        failed = true;
      }
      expect(failed).assertTrue();
    });
  });
}
