import { common } from '@kit.AbilityKit';
import { util } from '@kit.ArkTS';
import { Constants } from '../common/Constants';

/** Values from rawfile/config.json. Empty URLs mean: use the local mock server. */
export class AuthConfig {
  tokenUrl: string = '';
  apiUrl: string = '';
  issuer: string = '';
  subject: string = '';
  audience: string = '';
  keyId: string = '';
  lifetimeSeconds: number = 3600;

  static load(context: common.Context): AuthConfig {
    const text = AuthConfig.readRawText(context, Constants.CONFIG_FILE);
    const json = JSON.parse(text) as Record<string, Object>;
    const config = new AuthConfig();
    config.tokenUrl = AuthConfig.text(json, 'tokenUrl');
    config.apiUrl = AuthConfig.text(json, 'apiUrl');
    config.issuer = AuthConfig.text(json, 'issuer');
    config.subject = AuthConfig.text(json, 'subject');
    config.audience = AuthConfig.text(json, 'audience');
    config.keyId = AuthConfig.text(json, 'keyId');
    const lifetime = json['lifetimeSeconds'];
    if (typeof lifetime === 'number') {
      config.lifetimeSeconds = lifetime;
    }
    return config;
  }

  static readRawText(context: common.Context, path: string): string {
    const bytes = context.resourceManager.getRawFileContentSync(path);
    return util.TextDecoder.create('utf-8').decodeToString(bytes);
  }

  hasServer(): boolean {
    return this.tokenUrl.length > 0 && this.apiUrl.length > 0;
  }

  private static text(json: Record<string, Object>, key: string): string {
    const value = json[key];
    return typeof value === 'string' ? value : '';
  }
}
