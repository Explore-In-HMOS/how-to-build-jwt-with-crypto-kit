import { common } from '@kit.AbilityKit';
import { util } from '@kit.ArkTS';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { Constants } from '../common/Constants';
import { Base64Url } from '../jwt/Base64Url';
import { JwtBuilder } from '../jwt/JwtBuilder';
import { PssSigner } from '../jwt/PssSigner';
import { AuthConfig } from './AuthConfig';
import { ApiResult, AuthTransport, TokenResult } from './AuthTransport';

/**
 * An in-app stand-in for the token server. It does what a real server does:
 * it verifies the PS256 signature with its own copy of the public key and
 * checks aud, exp and iat. Used when config.json has no server URLs.
 */
export class MockAuthTransport implements AuthTransport {
  private context: common.Context;
  private config: AuthConfig;
  private publicKey?: cryptoFramework.PubKey;
  private currentToken: string = '';
  private tokenExpiresAt: number = 0;
  private subject: string = '';

  constructor(context: common.Context, config: AuthConfig) {
    this.context = context;
    this.config = config;
  }

  name(): string {
    return 'local mock server';
  }

  async exchange(jwt: string): Promise<TokenResult> {
    const parts = JwtBuilder.split(jwt);
    const valid = await PssSigner.verify(await this.loadPublicKey(),
      Base64Url.utf8(JwtBuilder.signingInput(parts)), Base64Url.decode(parts.signature));
    if (!valid) {
      throw new Error('invalid_grant: the signature is not valid');
    }
    const claims = JSON.parse(Base64Url.decodeText(parts.payload)) as Record<string, Object>;
    const now = Math.floor(Date.now() / 1000);
    if (claims['aud'] !== this.config.audience) {
      throw new Error('invalid_grant: wrong audience');
    }
    if ((claims['exp'] as number) <= now) {
      throw new Error('invalid_grant: the JWT has expired');
    }
    if ((claims['iat'] as number) > now + Constants.MAX_CLOCK_SKEW_S) {
      throw new Error('invalid_grant: iat is in the future');
    }
    this.subject = claims['sub'] as string;
    this.currentToken = `mock-${util.generateRandomUUID()}`;
    this.tokenExpiresAt = now + Constants.MOCK_TOKEN_LIFETIME_S;

    const result = new TokenResult();
    result.accessToken = this.currentToken;
    result.expiresInSeconds = Constants.MOCK_TOKEN_LIFETIME_S;
    result.serverTimeMs = Date.now();
    return result;
  }

  async callApi(accessToken: string): Promise<ApiResult> {
    const result = new ApiResult();
    if (accessToken !== this.currentToken || Date.now() / 1000 >= this.tokenExpiresAt) {
      result.code = 401;
      result.body = '{"error":"invalid_token"}';
      return result;
    }
    result.code = 200;
    result.body = `{"message":"Hello, ${this.subject}"}`;
    return result;
  }

  private async loadPublicKey(): Promise<cryptoFramework.PubKey> {
    if (this.publicKey === undefined) {
      const pem = AuthConfig.readRawText(this.context, Constants.PUBLIC_KEY_FILE);
      const keyPair = await cryptoFramework.createAsyKeyGenerator(Constants.KEY_ALGORITHM).convertPemKey(pem, null);
      this.publicKey = keyPair.pubKey;
    }
    return this.publicKey;
  }
}
