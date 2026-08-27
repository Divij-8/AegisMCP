import { describe, it, expect } from "vitest";
import { validatePolicies } from "./validate.js";
import type { Policy } from "./types.js";

function validPolicy(overrides?: Partial<Policy>): Policy {
  return {
    id: "test-policy",
    decision: "ALLOW",
    match: {},
    reason: "Test policy",
    ...overrides,
  };
}

describe("validatePolicies", () => {
  it("accepts a valid policy array", () => {
    expect(() => validatePolicies([validPolicy()])).not.toThrow();
  });

  it("accepts empty policy array", () => {
    expect(() => validatePolicies([])).not.toThrow();
  });

  it("accepts empty match object (catch-all)", () => {
    expect(() => validatePolicies([validPolicy({ match: {} })])).not.toThrow();
  });

  it("accepts multiple valid policies", () => {
    expect(() =>
      validatePolicies([
        validPolicy({ id: "p1" }),
        validPolicy({ id: "p2", decision: "DENY" }),
        validPolicy({ id: "p3", decision: "REQUIRE_APPROVAL" }),
      ]),
    ).not.toThrow();
  });

  it("rejects policy with empty id", () => {
    expect(() => validatePolicies([validPolicy({ id: "" })])).toThrow(/non-empty string/);
  });

  it("rejects policy with whitespace-only id", () => {
    expect(() => validatePolicies([validPolicy({ id: "   " })])).toThrow(/non-empty string/);
  });

  it("rejects policy with duplicate id", () => {
    expect(() =>
      validatePolicies([validPolicy({ id: "dup" }), validPolicy({ id: "dup" })]),
    ).toThrow(/duplicate id "dup"/);
  });

  it("rejects policy with invalid decision", () => {
    expect(() =>
      validatePolicies([validPolicy({ decision: "INVALID" as Policy["decision"] })]),
    ).toThrow(/invalid decision/);
  });

  it("rejects policy with null match", () => {
    expect(() =>
      validatePolicies([validPolicy({ match: null as unknown as Policy["match"] })]),
    ).toThrow(/match must be an object/);
  });

  it("rejects policy with array match", () => {
    expect(() =>
      validatePolicies([validPolicy({ match: ["a"] as unknown as Policy["match"] })]),
    ).toThrow(/match must be an object/);
  });

  it("rejects policy with empty reason", () => {
    expect(() => validatePolicies([validPolicy({ reason: "" })])).toThrow(
      /reason must be a non-empty string/,
    );
  });

  it("rejects policy with whitespace-only reason", () => {
    expect(() => validatePolicies([validPolicy({ reason: "  " })])).toThrow(
      /reason must be a non-empty string/,
    );
  });

  it("reports the index of the first invalid policy", () => {
    expect(() => validatePolicies([validPolicy({ id: "good" }), validPolicy({ id: "" })])).toThrow(
      /index 1/,
    );
  });

  it("reports the policy id in the error message", () => {
    expect(() => validatePolicies([validPolicy({ id: "bad-policy", reason: "" })])).toThrow(
      /"bad-policy"/,
    );
  });
});
