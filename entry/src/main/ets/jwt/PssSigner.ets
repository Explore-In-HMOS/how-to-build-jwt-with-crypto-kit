import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { Constants } from '../common/Constants';

/**
 * SHA256withRSA/PSS with a 32-byte salt (JWT "PS256").
 * The salt length is set after init and before sign/verify.
 */
export class PssSigner {
  static async sign(privateKey: cryptoFramework.PriKey, data: Uint8Array): Promise<Uint8Array> {
    const signer = cryptoFramework.createSign(Constants.SIGN_ALGORITHM);
    await signer.init(privateKey);
    signer.setSignSpec(cryptoFramework.SignSpecItem.PSS_SALT_LEN_NUM, Constants.PSS_SALT_LENGTH);
    const signature = await signer.sign({ data: data });
    return signature.data;
  }

  static async verify(publicKey: cryptoFramework.PubKey, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
    const verifier = cryptoFramework.createVerify(Constants.SIGN_ALGORITHM);
    await verifier.init(publicKey);
    verifier.setVerifySpec(cryptoFramework.SignSpecItem.PSS_SALT_LEN_NUM, Constants.PSS_SALT_LENGTH);
    return verifier.verify({ data: data }, { data: signature });
  }
}
