export class TokenResult {
  accessToken: string = '';
  expiresInSeconds: number = 0;
  // Server clock from the HTTP Date header, 0 when unknown.
  serverTimeMs: number = 0;
}

export class ApiResult {
  code: number = 0;
  body: string = '';
}

/** The JWT bearer grant (RFC 7523) and one protected API call. */
export interface AuthTransport {
  name(): string;
  exchange(jwt: string): Promise<TokenResult>;
  callApi(accessToken: string): Promise<ApiResult>;
}

export const JWT_BEARER_GRANT: string = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
