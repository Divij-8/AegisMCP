/**
 * Credential secret hashing — scrypt via node:crypto, no third-party deps.
 *
 * Only the derived hash and a per-credential salt are ever persisted. The
 * plaintext secret never leaves this module's call boundary.
 *
 * The hasher is an injectable interface so tests can substitute a fast fake
 * while production and integration tests exercise the real scrypt parameters.
 */

import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";

/** Algorithm identifier persisted with each credential. */
export const SCRYPT_ALGORITHM = "scrypt-v1";

const SCRYPT_N = 16_384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 32;
const SALT_BYTES = 16;
const SCRYPT_MAXMEM = 64 * 1024 * 1024;

function scryptAsync(password: string, salt: string, keylen: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCallback(
      password,
      salt,
      keylen,
      { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, maxmem: SCRYPT_MAXMEM },
      (error, derivedKey) => {
        if (error) reject(error);
        else resolve(derivedKey);
      },
    );
  });
}

export interface SecretHasher {
  /** Algorithm identifier written to agent_credentials.hash_algo. */
  readonly algorithm: string;
  /** Fresh random salt, hex encoded. */
  generateSalt(): string;
  /** Derive a storable hash (hex) for a secret. */
  hash(secret: string, salt: string): Promise<string>;
  /** Constant-time verification of a secret against a stored hash. */
  verify(secret: string, salt: string, expectedHash: string): Promise<boolean>;
}

export interface ScryptHasherOptions {
  /**
   * Optional server-side pepper mixed into the KDF input. Adds defense in
   * depth if the credential table leaks without the application environment.
   * Empty by default so local/dev setups need no extra configuration.
   *
   * IMMUTABLE: the pepper is not stored per credential, so it must stay the
   * same for the entire lifetime of every credential created with it. Changing
   * it makes all existing credentials fail verification (a full authentication
   * outage). To change the pepper, rotate credentials: create new credentials
   * under the new pepper, migrate clients, then revoke the old ones.
   */
  readonly pepper?: string;
}

export class ScryptSecretHasher implements SecretHasher {
  readonly algorithm = SCRYPT_ALGORITHM;

  private readonly pepper: string;

  constructor(options: ScryptHasherOptions = {}) {
    this.pepper = options.pepper ?? "";
  }

  generateSalt(): string {
    return randomBytes(SALT_BYTES).toString("hex");
  }

  async hash(secret: string, salt: string): Promise<string> {
    const derived = await scryptAsync(this.applyPepper(secret), salt, SCRYPT_KEYLEN);
    return derived.toString("hex");
  }

  async verify(secret: string, salt: string, expectedHash: string): Promise<boolean> {
    const derived = await scryptAsync(this.applyPepper(secret), salt, SCRYPT_KEYLEN);
    const expected = Buffer.from(expectedHash, "hex");
    if (expected.length !== derived.length) return false;
    return timingSafeEqual(derived, expected);
  }

  private applyPepper(secret: string): string {
    return this.pepper.length > 0 ? `${this.pepper}:${secret}` : secret;
  }
}
