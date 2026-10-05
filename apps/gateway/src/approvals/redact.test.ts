import { describe, it, expect } from "vitest";
import {
  canonicalize,
  hashArguments,
  isSensitiveKey,
  redactArguments,
  REDACTED,
} from "./redact.js";

describe("isSensitiveKey", () => {
  it.each([
    "password",
    "apiKey",
    "api_key",
    "secret",
    "authorization",
    "access_token",
    "clientSecret",
  ])("treats %s as sensitive", (key) => {
    expect(isSensitiveKey(key)).toBe(true);
  });

  it.each(["message", "path", "count", "name"])("treats %s as non-sensitive", (key) => {
    expect(isSensitiveKey(key)).toBe(false);
  });
});

describe("redactArguments", () => {
  it("redacts sensitive values and keeps safe ones", () => {
    const redacted = redactArguments({ message: "hello", password: "hunter2" });
    expect(redacted).toEqual({ message: "hello", password: REDACTED });
  });

  it("redacts nested sensitive keys", () => {
    const redacted = redactArguments({
      user: { name: "ada", token: "abc" },
      items: [{ secret: "x" }, { value: 1 }],
    });
    expect(redacted).toEqual({
      user: { name: "ada", token: REDACTED },
      items: [{ secret: REDACTED }, { value: 1 }],
    });
  });

  it("does not mutate the input", () => {
    const input = { password: "hunter2" };
    redactArguments(input);
    expect(input.password).toBe("hunter2");
  });

  it("returns undefined for undefined input", () => {
    expect(redactArguments(undefined)).toBeUndefined();
  });

  it("depth-bounds nested structures", () => {
    let deep: Record<string, unknown> = { value: 1 };
    for (let i = 0; i < 12; i++) deep = { nested: deep };
    const redacted = JSON.stringify(redactArguments(deep));
    expect(redacted).toContain("TRUNCATED");
  });

  it("never leaks a secret embedded in a nested sensitive key", () => {
    const redacted = JSON.stringify(
      redactArguments({ outer: { auth: { bearer: "SUPER-SECRET" } } }),
    );
    expect(redacted).not.toContain("SUPER-SECRET");
  });
});

describe("canonicalize", () => {
  it("is key-order independent", () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe(canonicalize({ a: 2, b: 1 }));
  });

  it("distinguishes different structures", () => {
    expect(canonicalize({ a: 1 })).not.toBe(canonicalize({ a: 2 }));
  });
});

describe("hashArguments", () => {
  it("is deterministic regardless of key order", () => {
    expect(hashArguments({ a: "1", b: "2" })).toBe(hashArguments({ b: "2", a: "1" }));
  });

  it("changes when argument values change (binding integrity)", () => {
    expect(hashArguments({ id: 1 })).not.toBe(hashArguments({ id: 2 }));
  });

  it("hashes undefined and empty distinctly from each other", () => {
    expect(hashArguments(undefined)).not.toBe(hashArguments({}));
  });
});
