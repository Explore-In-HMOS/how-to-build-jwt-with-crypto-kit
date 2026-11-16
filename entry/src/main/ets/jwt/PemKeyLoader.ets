import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { Constants } from '../common/Constants';

export enum PemType {
  PKCS8_PRIVATE = 'PKCS#8 private key',
  PKCS1_PRIVATE = 'PKCS#1 RSA private key',
  ENCRYPTED_PRIVATE = 'encrypted private key',
  X509_PUBLIC = 'X.509 public key',
  PKCS1_PUBLIC = 'PKCS#1 RSA public key',
  UNKNOWN = 'unknown'
}

/**
 * Loads an RSA key pair from PEM text. Never log the private key text:
 * error messages name only the PEM type.
 */
export class PemKeyLoader {
  static detect(pem: string): PemType {
    if (pem.includes('-----BEGIN PRIVATE KEY-----')) {
      return PemType.PKCS8_PRIVATE;
    }
    if (pem.includes('-----BEGIN RSA PRIVATE KEY-----')) {
      return pem.includes('ENCRYPTED') ? PemType.ENCRYPTED_PRIVATE : PemType.PKCS1_PRIVATE;
    }
    if (pem.includes('-----BEGIN ENCRYPTED PRIVATE KEY-----')) {
      return PemType.ENCRYPTED_PRIVATE;
    }
    if (pem.includes('-----BEGIN PUBLIC KEY-----')) {
      return PemType.X509_PUBLIC;
    }
    if (pem.includes('-----BEGIN RSA PUBLIC KEY-----')) {
      return PemType.PKCS1_PUBLIC;
    }
    return PemType.UNKNOWN;
  }

  /** Throws a readable error for a private key that this sample cannot use. */
  static checkPrivateKey(pem: string): PemType {
    const type = PemKeyLoader.detect(pem);
    if (type === PemType.ENCRYPTED_PRIVATE) {
      throw new Error('The private key is encrypted. Use a key without a password.');
    }
    if (type !== PemType.PKCS8_PRIVATE && type !== PemType.PKCS1_PRIVATE) {
      throw new Error(`Expected an RSA private key in PEM format, found: ${type}.`);
    }
    return type;
  }

  /**
   * Converts the PEM text to a key pair. `convertPemKey` (API 12+) accepts
   * PKCS#8 and PKCS#1 private keys and X.509 or PKCS#1 public keys.
   */
  static async load(privatePem: string, publicPem: string | null): Promise<cryptoFramework.KeyPair> {
    PemKeyLoader.checkPrivateKey(privatePem);
    if (publicPem !== null && PemKeyLoader.detect(publicPem) === PemType.UNKNOWN) {
      throw new Error('The public key is not in PEM format.');
    }
    const generator = cryptoFramework.createAsyKeyGenerator(Constants.KEY_ALGORITHM);
    return generator.convertPemKey(publicPem, privatePem);
  }
}
