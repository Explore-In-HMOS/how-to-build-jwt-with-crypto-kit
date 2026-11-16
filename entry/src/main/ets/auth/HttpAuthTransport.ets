import { http } from '@kit.NetworkKit';
import { Constants } from '../common/Constants';
import { AuthConfig } from './AuthConfig';
import { ApiResult, AuthTransport, JWT_BEARER_GRANT, TokenResult } from './AuthTransport';

/** Talks to a real token endpoint, for example tools/verify-server. */
export class HttpAuthTransport implements AuthTransport {
  private config: AuthConfig;

  constructor(config: AuthConfig) {
    this.config = config;
  }

  name(): string {
    return this.config.tokenUrl;
  }

  async exchange(jwt: string): Promise<TokenResult> {
    const body = `grant_type=${encodeURIComponent(JWT_BEARER_GRANT)}&assertion=${encodeURIComponent(jwt)}`;
    const header: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' };
    const response = await this.request(this.config.tokenUrl, http.RequestMethod.POST, header, body);
    const text = response.result as string;
    if (response.responseCode !== 200) {
      throw new Error(`Token endpoint returned HTTP ${response.responseCode}: ${text.substring(0, 120)}`);
    }
    const json = JSON.parse(text) as Record<string, Object>;
    const result = new TokenResult();
    result.accessToken = typeof json['access_token'] === 'string' ? json['access_token'] as string : '';
    result.expiresInSeconds = typeof json['expires_in'] === 'number' ? json['expires_in'] as number : 0;
    result.serverTimeMs = HttpAuthTransport.serverTime(response.header);
    if (result.accessToken.length === 0) {
      throw new Error('The token response has no access_token');
    }
    return result;
  }

  async callApi(accessToken: string): Promise<ApiResult> {
    const header: Record<string, string> = { 'Authorization': `Bearer ${accessToken}` };
    const response = await this.request(this.config.apiUrl, http.RequestMethod.GET, header, undefined);
    const result = new ApiResult();
    result.code = response.responseCode;
    result.body = response.result as string;
    return result;
  }

  private async request(url: string, method: http.RequestMethod, header: Record<string, string>,
    body: string | undefined): Promise<http.HttpResponse> {
    const client = http.createHttp();
    try {
      return await client.request(url, {
        method: method,
        header: header,
        extraData: body,
        expectDataType: http.HttpDataType.STRING,
        connectTimeout: Constants.HTTP_TIMEOUT_MS,
        readTimeout: Constants.HTTP_TIMEOUT_MS
      });
    } finally {
      client.destroy();
    }
  }

  private static serverTime(header: Object): number {
    const headers = header as Record<string, string>;
    const date = headers['date'] ?? headers['Date'];
    if (date === undefined) {
      return 0;
    }
    const time = Date.parse(date);
    return Number.isNaN(time) ? 0 : time;
  }
}
