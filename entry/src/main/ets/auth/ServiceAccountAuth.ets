import { common } from '@kit.AbilityKit';
import { util } from '@kit.ArkTS';
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { Constants } from '../common/Constants';
import { LogLevel } from '../common/Logger';
import { Base64Url } from '../jwt/Base64Url';
import { JwtBuilder, JwtParts } from '../jwt/JwtBuilder';
import { PemKeyLoader } from '../jwt/PemKeyLoader';
import { PssSigner } from '../jwt/PssSigner';
import { AuthConfig } from './AuthConfig';
import { ApiResult, AuthTransport, TokenResult } from './AuthTransport';

export enum StepId {
  LOAD_KEY = 0,
  BUILD = 1,
  SIGN = 2,
  VERIFY = 3,
  TOKEN = 4,
  API = 5
}

export enum StepStatus {
  IDLE = 'idle',
  RUNNING = 'running',
  OK = 'ok',
  FAILED = 'failed'
}

export class StepReport {
  id: StepId;
  name: string;
  status: StepStatus = StepStatus.IDLE;
  ms: number = 0;
  detail: string = '';

  constructor(id: StepId, name: string) {
    this.id = id;
    this.name = name;
  }
}

export const STEP_NAMES: string[] = ['Load key', 'Build header + payload', 'Sign PS256', 'Self-verify',
  'Token request', 'API call'];

export interface AuthListener {
  onStep: (report: StepReport) => void;
  onJwt: (parts: JwtParts, expiresAt: number) => void;
  onToken: (expiresAt: number) => void;
  onLog: (message: string, level: LogLevel) => void;
}

/**
 * The complete service account flow:
 * PEM key -> JWT (PS256) -> access token (JWT bearer grant) -> protected API.
 * A JWT and an access token are reused until they are near expiry.
 */
export class ServiceAccountAuth {
  private context: common.Context;
  private config: AuthConfig;
  private transport: AuthTransport;
  private listener: AuthListener;
  private keyPair?: cryptoFramework.KeyPair;
  private jwt?: JwtParts;
  private jwtExpiresAt: number = 0;
  private accessToken: string = '';
  private tokenExpiresAt: number = 0;

  constructor(context: common.Context, config: AuthConfig, transport: AuthTransport, listener: AuthListener) {
    this.context = context;
    this.config = config;
    this.transport = transport;
    this.listener = listener;
  }

  setTransport(transport: AuthTransport): void {
    this.transport = transport;
    this.accessToken = '';
    this.tokenExpiresAt = 0;
  }

  async generateJwt(): Promise<JwtParts> {
    const keyPair = await this.step(StepId.LOAD_KEY, async () => this.loadKeyPair(),
      () => this.keyPair === undefined ? '' : 'RSA 2048 key pair');

    const nowSeconds = Math.floor(Date.now() / 1000);
    const parts = await this.step(StepId.BUILD, async () => {
      const header = JwtBuilder.header(this.config.keyId);
      const claims = JwtBuilder.claims(this.config.issuer, this.config.subject, this.config.audience, nowSeconds,
        this.config.lifetimeSeconds, util.generateRandomUUID());
      return JwtBuilder.unsigned(header, claims);
    }, (result: JwtParts) => `${result.header.length + result.payload.length + 1} chars, Base64URL`);

    const signingInput = Base64Url.utf8(JwtBuilder.signingInput(parts));
    const signature = await this.step(StepId.SIGN, () => PssSigner.sign(keyPair.priKey, signingInput),
      (result: Uint8Array) => `${result.length} bytes, salt ${Constants.PSS_SALT_LENGTH}`);
    parts.signature = Base64Url.encode(signature);

    await this.step(StepId.VERIFY, async () => {
      const valid = await PssSigner.verify(keyPair.pubKey, signingInput, signature);
      if (!valid) {
        throw new Error('The signature does not verify with the public key');
      }
      return valid;
    }, () => 'signature verified');

    this.jwt = parts;
    this.jwtExpiresAt = nowSeconds + this.config.lifetimeSeconds;
    this.listener.onJwt(parts, this.jwtExpiresAt);
    return parts;
  }

  async fetchToken(): Promise<string> {
    const jwt = await this.ensureJwt();
    const result = await this.step(StepId.TOKEN, () => this.transport.exchange(jwt.token()),
      (token: TokenResult) => `expires in ${token.expiresInSeconds} s`);
    this.accessToken = result.accessToken;
    this.tokenExpiresAt = Math.floor(Date.now() / 1000) + result.expiresInSeconds;
    this.listener.onToken(this.tokenExpiresAt);
    this.checkClock(result.serverTimeMs);
    return this.accessToken;
  }

  /** Calls the API. An expired or rejected token is refreshed one time. */
  async callApi(): Promise<ApiResult> {
    const token = await this.ensureToken();
    let result = await this.step(StepId.API, () => this.transport.callApi(token),
      (api: ApiResult) => `HTTP ${api.code}`);
    if (result.code === 401) {
      this.listener.onLog('API returned 401: getting a new access token', LogLevel.WARN);
      const freshToken = await this.fetchToken();
      result = await this.step(StepId.API, () => this.transport.callApi(freshToken),
        (api: ApiResult) => `HTTP ${api.code} (after refresh)`);
    }
    return result;
  }

  private async ensureJwt(): Promise<JwtParts> {
    const now = Math.floor(Date.now() / 1000);
    if (this.jwt !== undefined && this.jwtExpiresAt - now > Constants.TOKEN_REFRESH_MARGIN_S) {
      return this.jwt;
    }
    return this.generateJwt();
  }

  private async ensureToken(): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    if (this.accessToken.length > 0 && this.tokenExpiresAt - now > Constants.TOKEN_REFRESH_MARGIN_S) {
      return this.accessToken;
    }
    if (this.accessToken.length > 0) {
      this.listener.onLog('Access token is near expiry: refreshing', LogLevel.INFO);
    }
    return this.fetchToken();
  }

  private async loadKeyPair(): Promise<cryptoFramework.KeyPair> {
    if (this.keyPair === undefined) {
      const privatePem = AuthConfig.readRawText(this.context, Constants.PRIVATE_KEY_FILE);
      const publicPem = AuthConfig.readRawText(this.context, Constants.PUBLIC_KEY_FILE);
      this.keyPair = await PemKeyLoader.load(privatePem, publicPem);
      this.listener.onLog(`Key loaded: ${PemKeyLoader.detect(privatePem)}`, LogLevel.INFO);
    }
    return this.keyPair;
  }

  private checkClock(serverTimeMs: number): void {
    if (serverTimeMs === 0) {
      return;
    }
    const skew = Math.round((Date.now() - serverTimeMs) / 1000);
    if (Math.abs(skew) > Constants.MAX_CLOCK_SKEW_S) {
      this.listener.onLog(skew > 0 ?
        `Watch clock is ${skew} s ahead of the server: iat can be in the future` :
        `Watch clock is ${-skew} s behind the server: the JWT can expire early`, LogLevel.WARN);
    }
  }

  /** Runs one step, reports its status and duration, and passes errors on. */
  private async step<T>(id: StepId, task: () => Promise<T>, detail: (result: T) => string): Promise<T> {
    const report = new StepReport(id, STEP_NAMES[id]);
    report.status = StepStatus.RUNNING;
    this.listener.onStep(report);
    const start = Date.now();
    try {
      const result = await task();
      const done = new StepReport(id, STEP_NAMES[id]);
      done.status = StepStatus.OK;
      done.ms = Date.now() - start;
      done.detail = detail(result);
      this.listener.onStep(done);
      return result;
    } catch (err) {
      const failed = new StepReport(id, STEP_NAMES[id]);
      failed.status = StepStatus.FAILED;
      failed.ms = Date.now() - start;
      failed.detail = err instanceof Error ? err.message : JSON.stringify(err);
      this.listener.onStep(failed);
      throw new Error(`${STEP_NAMES[id]} failed: ${failed.detail}`);
    }
  }
}
