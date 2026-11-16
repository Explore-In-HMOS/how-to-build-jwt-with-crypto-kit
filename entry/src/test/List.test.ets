import base64UrlTest from './Base64Url.test';
import jwtBuilderTest from './JwtBuilder.test';

export default function testsuite() {
  base64UrlTest();
  jwtBuilderTest();
}
