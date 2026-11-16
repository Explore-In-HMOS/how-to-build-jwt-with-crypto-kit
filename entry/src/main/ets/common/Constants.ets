export class Constants {
  // Crypto Architecture Kit algorithm string for PS256 (RSASSA-PSS, SHA-256, MGF1 with SHA-256).
  static readonly SIGN_ALGORITHM: string = 'RSA2048|PSS|SHA256|MGF1_SHA256';
  static readonly KEY_ALGORITHM: string = 'RSA2048';
  // PS256 uses a salt as long as the SHA-256 digest.
  static readonly PSS_SALT_LENGTH: number = 32;

  static readonly CONFIG_FILE: string = 'config.json';
  static readonly PRIVATE_KEY_FILE: string = 'keys/service_account.pem';
  static readonly PUBLIC_KEY_FILE: string = 'keys/service_account.pub.pem';

  static readonly HTTP_TIMEOUT_MS: number = 10000;
  // Refresh the access token this long before it expires.
  static readonly TOKEN_REFRESH_MARGIN_S: number = 30;
  // Warn when the watch clock and the server clock differ by more than this.
  static readonly MAX_CLOCK_SKEW_S: number = 60;
  static readonly MOCK_TOKEN_LIFETIME_S: number = 120;

  static readonly LOG_LIMIT: number = 20;
  static readonly LOG_DOMAIN: number = 0x0022;
  static readonly LOG_TAG: string = 'JwtSigner';
}
