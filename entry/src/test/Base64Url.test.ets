import { describe, expect, it } from '@ohos/hypium';
import { Base64Url } from '../main/ets/jwt/Base64Url';

export default function base64UrlTest() {
  describe('Base64Url', () => {
    it('emptyInputGivesEmptyString', 0, () => {
      expect(Base64Url.encode(new Uint8Array(0))).assertEqual('');
    });

    it('paddingIsRemoved', 0, () => {
      expect(Base64Url.encodeText('f')).assertEqual('Zg');
      expect(Base64Url.encodeText('fo')).assertEqual('Zm8');
      expect(Base64Url.encodeText('foo')).assertEqual('Zm9v');
    });

    it('plusAndSlashAreReplaced', 0, () => {
      // Standard Base64 of 0xFB 0xFF is "+/8=".
      expect(Base64Url.encode(new Uint8Array([0xfb, 0xff]))).assertEqual('-_8');
    });

    it('decodeRestoresBytesWithoutPadding', 0, () => {
      const bytes = Base64Url.decode('-_8');
      expect(bytes.length).assertEqual(2);
      expect(bytes[0]).assertEqual(0xfb);
      expect(bytes[1]).assertEqual(0xff);
    });

    it('utf8TextRoundTrips', 0, () => {
      const encoded = Base64Url.encodeText('çğü ✓');
      expect(encoded).assertEqual('w6fEn8O8IOKckw');
      expect(Base64Url.decodeText(encoded)).assertEqual('çğü ✓');
    });

    it('fourByteCharacterRoundTrips', 0, () => {
      const encoded = Base64Url.encodeText('⌚ 😀');
      expect(encoded).assertEqual('4oyaIPCfmIA');
      expect(Base64Url.decodeText(encoded)).assertEqual('⌚ 😀');
    });

    it('invalidCharacterThrows', 0, () => {
      let failed = false;
      try {
        Base64Url.decode('ab+c');
      } catch (err) {
        failed = true;
      }
      expect(failed).assertTrue();
    });

    it('jwtHeaderEncodingMatchesReference', 0, () => {
      expect(Base64Url.encodeText('{"alg":"PS256","typ":"JWT","kid":"k1"}'))
        .assertEqual('eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImsxIn0');
    });
  });
}
