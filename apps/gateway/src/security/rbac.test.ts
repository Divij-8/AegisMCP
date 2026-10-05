import { describe, it, expect } from "vitest";
import {
  hasPermission,
  isAgentRole,
  permissionsFor,
  resolveRole,
  type Permission,
} from "./rbac.js";

describe("rbac", () => {
  it("recognizes only the declared roles", () => {
    expect(isAgentRole("ADMIN")).toBe(true);
    expect(isAgentRole("OPERATOR")).toBe(true);
    expect(isAgentRole("AUDITOR")).toBe(true);
    expect(isAgentRole("AGENT")).toBe(true);
    expect(isAgentRole("SUPERUSER")).toBe(false);
  });

  it("treats a missing role as AGENT (least privilege)", () => {
    expect(resolveRole({})).toBe("AGENT");
  });

  it("gives AGENT no control-plane permissions", () => {
    expect(permissionsFor("AGENT")).toHaveLength(0);
    for (const permission of [
      "approval:read",
      "approval:decide",
      "policy:read",
      "policy:write",
      "agent:read",
      "agent:manage",
      "server:read",
      "audit:read",
    ] as Permission[]) {
      expect(hasPermission({ role: "AGENT" }, permission)).toBe(false);
      expect(hasPermission({}, permission)).toBe(false);
    }
  });

  it("gives AUDITOR read-only access", () => {
    expect(hasPermission({ role: "AUDITOR" }, "audit:read")).toBe(true);
    expect(hasPermission({ role: "AUDITOR" }, "policy:read")).toBe(true);
    expect(hasPermission({ role: "AUDITOR" }, "policy:write")).toBe(false);
    expect(hasPermission({ role: "AUDITOR" }, "approval:decide")).toBe(false);
    expect(hasPermission({ role: "AUDITOR" }, "agent:manage")).toBe(false);
  });

  it("gives OPERATOR decision and management powers but not admin-only ones", () => {
    expect(hasPermission({ role: "OPERATOR" }, "approval:decide")).toBe(true);
    expect(hasPermission({ role: "OPERATOR" }, "policy:write")).toBe(true);
    expect(hasPermission({ role: "OPERATOR" }, "agent:manage")).toBe(true);
    expect(hasPermission({ role: "OPERATOR" }, "audit:read")).toBe(true);
    // ADMIN-only: an OPERATOR must not be able to mint privileged principals.
    expect(hasPermission({ role: "OPERATOR" }, "role:assign")).toBe(false);
  });

  it("reserves role:assign for ADMIN", () => {
    expect(hasPermission({ role: "ADMIN" }, "role:assign")).toBe(true);
    expect(hasPermission({ role: "AUDITOR" }, "role:assign")).toBe(false);
    expect(hasPermission({ role: "AGENT" }, "role:assign")).toBe(false);
  });

  it("gives ADMIN every permission", () => {
    for (const permission of permissionsFor("ADMIN")) {
      expect(hasPermission({ role: "ADMIN" }, permission)).toBe(true);
    }
  });
});
