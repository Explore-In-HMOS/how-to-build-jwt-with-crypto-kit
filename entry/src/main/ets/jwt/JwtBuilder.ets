import { Base64Url } from './Base64Url';

export class JwtHeader {
  alg: string = 'PS256';
  typ: string = 'JWT';
  kid: string = '';
}

export class JwtClaims {
  iss: string = '';
  sub: string = '';
  aud: string = '';
  iat: number = 0;
  exp: number = 0;
  jti: string = '';
}

export class JwtParts {
  header: string = '';
  payload: string = '';
  signature: string = '';

  token(): string {
    return `${this.header}.${this.payload}.${this.signature}`;
  }
}

/**
 * Builds the JWT pieces. Signing is not done here, so the builder is pure
 * and unit tested: header.payload is the "signing input".
 */
export class JwtBuilder {
  static header(keyId: string): JwtHeader {
    const header = new JwtHeader();
    header.kid = keyId;
    return header;
  }

  /** `nowSeconds` is the Unix time in seconds; exp = iat + lifetime. */
  static claims(issuer: string, subject: string, audience: string, nowSeconds: number, lifetimeSeconds: number,
    jwtId: string): JwtClaims {
    const claims = new JwtClaims();
    claims.iss = issuer;
    claims.sub = subject;
    claims.aud = audience;
    claims.iat = nowSeconds;
    claims.exp = nowSeconds + lifetimeSeconds;
    claims.jti = jwtId;
    return claims;
  }

  static unsigned(header: JwtHeader, claims: JwtClaims): JwtParts {
    const parts = new JwtParts();
    parts.header = Base64Url.encodeText(JSON.stringify(header));
    parts.payload = Base64Url.encodeText(JSON.stringify(claims));
    return parts;
  }

  static signingInput(parts: JwtParts): string {
    return `${parts.header}.${parts.payload}`;
  }

  /** Splits a compact JWT. Throws when it does not have three parts. */
  static split(token: string): JwtParts {
    const pieces = token.split('.');
    if (pieces.length !== 3) {
      throw new Error('A JWT must have three parts');
    }
    const parts = new JwtParts();
    parts.header = pieces[0];
    parts.payload = pieces[1];
    parts.signature = pieces[2];
    return parts;
  }
}
