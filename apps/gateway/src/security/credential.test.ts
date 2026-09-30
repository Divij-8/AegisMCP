import { describe, it, expect } from "vitest";
import {
  API_KEY_PREFIX,
  extractPresentedCredential,
  formatApiKey,
  generateKeyId,
  generateSecret,
  parseApiKey,
} from "./credential.js";

describe("generateKeyId / generateSecret", () => {
  it("produces 32-character hex key ids", () => {
    expect(generateKeyId()).toMatch(/^[0-9a-f]{32}$/);
  });

  it("produces 64-character hex secrets", () => {
    expect(generateSecret()).toMatch(/^[0-9a-f]{64}$/);
  });

  it("produces distinct values", () => {
    expect(generateKeyId()).not.toBe(generateKeyId());
    expect(generateSecret()).not.toBe(generateSecret());
  });
});

describe("formatApiKey / parseApiKey", () => {
  it("round-trips a generated key", () => {
    const keyId = generateKeyId();
    const secret = generateSecret();
    const key = formatApiKey(keyId, secret);

    expect(key.startsWith(`${API_KEY_PREFIX}_`)).toBe(true);
    expect(parseApiKey(key)).toEqual({ keyId, secret });
  });

  it("rejects an empty string", () => {
    expect(parseApiKey("")).toBeNull();
  });

  it("rejects a wrong prefix", () => {
    const key = formatApiKey(generateKeyId(), generateSecret());
    expect(parseApiKey(`xxxx${key.slice(4)}`)).toBeNull();
  });

  it("rejects a missing secret segment", () => {
    expect(parseApiKey(`${API_KEY_PREFIX}_${generateKeyId()}`)).toBeNull();
  });

  it("rejects an empty secret segment", () => {
    expect(parseApiKey(`${API_KEY_PREFIX}_${generateKeyId()}_`)).toBeNull();
  });

  it("rejects a short secret", () => {
    expect(parseApiKey(`${API_KEY_PREFIX}_${generateKeyId()}_abcd`)).toBeNull();
  });

  it("rejects a short key id", () => {
    expect(parseApiKey(`${API_KEY_PREFIX}_abcd_${generateSecret()}`)).toBeNull();
  });

  it("rejects uppercase hex (non-canonical encoding)", () => {
    expect(
      parseApiKey(`${API_KEY_PREFIX}_${generateKeyId().toUpperCase()}_${generateSecret()}`),
    ).toBeNull();
  });

  it("rejects extra underscore segments", () => {
    expect(
      parseApiKey(`${API_KEY_PREFIX}_${generateKeyId()}_${generateSecret()}_extra`),
    ).toBeNull();
  });
});

describe("extractPresentedCredential", () => {
  it("returns none when no credential header is present", () => {
    expect(extractPresentedCredential({})).toEqual({ kind: "none" });
  });

  it("returns none for empty header values", () => {
    expect(extractPresentedCredential({ authorization: "   ", apiKey: "" })).toEqual({
      kind: "none",
    });
  });

  it("extracts a Bearer token case-insensitively", () => {
    expect(extractPresentedCredential({ authorization: "bearer abc123" })).toEqual({
      kind: "presented",
      value: "abc123",
    });
  });

  it("trims the Bearer token", () => {
    expect(extractPresentedCredential({ authorization: "Bearer   abc123  " })).toEqual({
      kind: "presented",
      value: "abc123",
    });
  });

  it("treats a non-Bearer Authorization header as presented (malformed downstream)", () => {
    expect(extractPresentedCredential({ authorization: "Basic dXNlcjpwYXNz" })).toEqual({
      kind: "presented",
      value: "Basic dXNlcjpwYXNz",
    });
  });

  it("falls back to X-API-Key when Authorization is absent", () => {
    expect(extractPresentedCredential({ apiKey: "abc123" })).toEqual({
      kind: "presented",
      value: "abc123",
    });
  });

  it("prefers Authorization over X-API-Key", () => {
    expect(
      extractPresentedCredential({ authorization: "Bearer primary", apiKey: "secondary" }),
    ).toEqual({ kind: "presented", value: "primary" });
  });

  it("uses the first value when a header repeats", () => {
    expect(
      extractPresentedCredential({ authorization: ["Bearer first", "Bearer second"] }),
    ).toEqual({ kind: "presented", value: "first" });
  });
});
