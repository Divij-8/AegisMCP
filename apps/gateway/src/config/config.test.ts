import { describe, it, expect } from "vitest";
import { ConfigurationError, parseAuthRequired } from "./index.js";

describe("parseAuthRequired", () => {
  it("treats an unset value as false", () => {
    expect(parseAuthRequired(undefined)).toBe(false);
  });

  it("treats empty and whitespace-only values as false", () => {
    expect(parseAuthRequired("")).toBe(false);
    expect(parseAuthRequired("   ")).toBe(false);
    expect(parseAuthRequired("\t")).toBe(false);
  });

  it.each(["true", "TRUE", "True", "tRuE", "  true  "])("accepts %s as true", (value) => {
    expect(parseAuthRequired(value)).toBe(true);
  });

  it.each(["false", "FALSE", "False", "fAlSe", "  false  "])("accepts %s as false", (value) => {
    expect(parseAuthRequired(value)).toBe(false);
  });

  it.each(["yes", "no", "1", "0", "on", "off", "required", "truthy"])(
    "rejects the unrecognized value %s",
    (value) => {
      expect(() => parseAuthRequired(value)).toThrow(ConfigurationError);
      expect(() => parseAuthRequired(value)).toThrow(/Invalid AUTH_REQUIRED/);
    },
  );
});
