import { describe, it, expect } from "vitest";
import { SCRYPT_ALGORITHM, ScryptSecretHasher } from "./hash.js";

describe("ScryptSecretHasher", () => {
  const hasher = new ScryptSecretHasher();

  it("reports the persisted algorithm identifier", () => {
    expect(hasher.algorithm).toBe(SCRYPT_ALGORITHM);
    expect(SCRYPT_ALGORITHM).toBe("scrypt-v1");
  });

  it("generates a 32-character hex salt", () => {
    expect(hasher.generateSalt()).toMatch(/^[0-9a-f]{32}$/);
  });

  it("generates distinct salts", () => {
    expect(hasher.generateSalt()).not.toBe(hasher.generateSalt());
  });

  it("produces a 64-character hex hash that does not contain the secret", async () => {
    const salt = hasher.generateSalt();
    const secret = "super-secret-value";
    const hash = await hasher.hash(secret, salt);

    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hash).not.toContain(secret);
  });

  it("verifies the correct secret", async () => {
    const salt = hasher.generateSalt();
    const hash = await hasher.hash("correct-horse", salt);
    await expect(hasher.verify("correct-horse", salt, hash)).resolves.toBe(true);
  });

  it("rejects the wrong secret", async () => {
    const salt = hasher.generateSalt();
    const hash = await hasher.hash("correct-horse", salt);
    await expect(hasher.verify("wrong-horse", salt, hash)).resolves.toBe(false);
  });

  it("produces different hashes for the same secret under different salts", async () => {
    const first = await hasher.hash("same-secret", hasher.generateSalt());
    const second = await hasher.hash("same-secret", hasher.generateSalt());
    expect(first).not.toBe(second);
  });

  it("returns false for a malformed stored hash instead of throwing", async () => {
    const salt = hasher.generateSalt();
    await expect(hasher.verify("secret", salt, "00")).resolves.toBe(false);
  });

  it("changes the derived hash when a pepper is configured", async () => {
    const salt = hasher.generateSalt();
    const peppered = new ScryptSecretHasher({ pepper: "server-pepper" });

    const plain = await hasher.hash("secret", salt);
    const withPepper = await peppered.hash("secret", salt);

    expect(withPepper).not.toBe(plain);
    await expect(peppered.verify("secret", salt, plain)).resolves.toBe(false);
    await expect(peppered.verify("secret", salt, withPepper)).resolves.toBe(true);
  });
});
