const ALPHABET: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

/**
 * Base64URL (RFC 4648 §5) without padding, as JWT requires, and UTF-8
 * conversion. Written in plain ArkTS (no native kit), so the same code runs
 * on the watch and in local unit tests. `util.Base64Helper` gives standard
 * Base64; JWT then needs '+' -> '-', '/' -> '_' and no '=' padding.
 */
export class Base64Url {
  static encode(bytes: Uint8Array): string {
    let out = '';
    let i = 0;
    for (; i + 2 < bytes.length; i += 3) {
      const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
      out += ALPHABET[(n >> 18) & 63] + ALPHABET[(n >> 12) & 63] + ALPHABET[(n >> 6) & 63] + ALPHABET[n & 63];
    }
    const rest = bytes.length - i;
    if (rest === 1) {
      const n = bytes[i] << 16;
      out += ALPHABET[(n >> 18) & 63] + ALPHABET[(n >> 12) & 63];
    } else if (rest === 2) {
      const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
      out += ALPHABET[(n >> 18) & 63] + ALPHABET[(n >> 12) & 63] + ALPHABET[(n >> 6) & 63];
    }
    return out;
  }

  /** Accepts Base64URL with or without padding. Throws on other characters. */
  static decode(value: string): Uint8Array {
    const clean = value.replace(/=+$/, '');
    const out = new Uint8Array(Math.floor(clean.length * 3 / 4));
    let buffer = 0;
    let bits = 0;
    let index = 0;
    for (let i = 0; i < clean.length; i++) {
      const digit = ALPHABET.indexOf(clean[i]);
      if (digit < 0) {
        throw new Error(`Invalid Base64URL character at ${i}`);
      }
      buffer = (buffer << 6) | digit;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out[index++] = (buffer >> bits) & 0xff;
      }
    }
    return out.subarray(0, index);
  }

  static encodeText(text: string): string {
    return Base64Url.encode(Base64Url.utf8(text));
  }

  static decodeText(value: string): string {
    return Base64Url.fromUtf8(Base64Url.decode(value));
  }

  static utf8(text: string): Uint8Array {
    const bytes: number[] = [];
    for (let i = 0; i < text.length; i++) {
      let code = text.charCodeAt(i);
      // Join a surrogate pair into one code point.
      if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
        const low = text.charCodeAt(i + 1);
        if (low >= 0xdc00 && low <= 0xdfff) {
          code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
          i++;
        }
      }
      if (code < 0x80) {
        bytes.push(code);
      } else if (code < 0x800) {
        bytes.push(0xc0 | (code >> 6), 0x80 | (code & 63));
      } else if (code < 0x10000) {
        bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
      } else {
        bytes.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 63), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
      }
    }
    return new Uint8Array(bytes);
  }

  static fromUtf8(bytes: Uint8Array): string {
    let out = '';
    let i = 0;
    while (i < bytes.length) {
      const b = bytes[i];
      let code = 0;
      if (b < 0x80) {
        code = b;
        i += 1;
      } else if (b < 0xe0) {
        code = ((b & 31) << 6) | (bytes[i + 1] & 63);
        i += 2;
      } else if (b < 0xf0) {
        code = ((b & 15) << 12) | ((bytes[i + 1] & 63) << 6) | (bytes[i + 2] & 63);
        i += 3;
      } else {
        code = ((b & 7) << 18) | ((bytes[i + 1] & 63) << 12) | ((bytes[i + 2] & 63) << 6) | (bytes[i + 3] & 63);
        i += 4;
      }
      out += String.fromCodePoint(code);
    }
    return out;
  }
}
