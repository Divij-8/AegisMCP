import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { SecurityHarness, hasDb } from "./helpers.js";
import type { HarnessPolicy } from "./helpers.js";

const d = describe.skipIf(!hasDb);

const PREFIX = "sec-pol-";
const T = (name: string) => `${PREFIX}${name}`;

d("SECURITY: policy cannot be bypassed", () => {
  const h = new SecurityHarness(PREFIX, []);
  let agent = "";
  let operator = "";

  beforeAll(() => h.setup());
  afterAll(() => h.teardown());
  beforeEach(async () => {
    await h.clean();
    agent = await h.provision(`${PREFIX}agent`);
    operator = await h.provision(`${PREFIX}operator`, "OPERATOR");
  });

  async function start(policies: readonly HarnessPolicy[]) {
    return h.startGateway({ policies });
  }

  async function decision(base: string, tool: string, args: Record<string, unknown> = {}) {
    const res = await h.mcp(base, agent, tool, args);
    const body = (await res.json()) as { result?: unknown; error?: { code: number } };
    if (body.result !== undefined) return "ALLOW";
    if (body.error?.code === -32003) return "DENY";
    if (body.error?.code === -32002) return "REQUIRE_APPROVAL";
    throw new Error(`unexpected decision: ${JSON.stringify(body)}`);
  }

  it("DENY wins over a higher-priority ALLOW", async () => {
    const tool = T("prio");
    const gw = await start([
      { id: T("deny"), decision: "DENY", match: { tool }, reason: "deny", priority: 0 },
      { id: T("allow"), decision: "ALLOW", match: { tool }, reason: "allow", priority: 1000 },
    ]);
    expect(await decision(gw.base, tool)).toBe("DENY");
    expect(h.connections).toBe(0);
    await gw.close();
  });

  it("an argument-constrained ALLOW cannot override a broad DENY", async () => {
    const tool = T("argdeny");
    const gw = await start([
      {
        id: T("allow-read"),
        decision: "ALLOW",
        match: { tool, arguments: { mode: { equals: "read" } } },
        reason: "read ok",
      },
      { id: T("deny-all"), decision: "DENY", match: { tool }, reason: "never" },
    ]);
    expect(await decision(gw.base, tool, { mode: "read" })).toBe("DENY");
    expect(h.connections).toBe(0);
    await gw.close();
  });

  it("REQUIRE_APPROVAL wins over ALLOW", async () => {
    const tool = T("appr");
    const gw = await start([
      { id: T("allow"), decision: "ALLOW", match: { tool }, reason: "allow" },
      { id: T("appr"), decision: "REQUIRE_APPROVAL", match: { tool }, reason: "approve" },
    ]);
    expect(await decision(gw.base, tool)).toBe("REQUIRE_APPROVAL");
    expect(h.connections).toBe(0);
    await gw.close();
  });

  it("a missing policy fails closed (DENY)", async () => {
    const gw = await start([
      { id: T("allow-other"), decision: "ALLOW", match: { tool: T("other") }, reason: "x" },
    ]);
    expect(await decision(gw.base, T("unlisted"))).toBe("DENY");
    expect(h.connections).toBe(0);
    await gw.close();
  });

  it("a disabled DENY does not apply and a disabled ALLOW does not apply", async () => {
    const denyTool = T("toggle-deny");
    const allowTool = T("toggle-allow");
    const gw = await start([]);

    // DENY created then disabled: request falls back to default DENY anyway, so
    // add an ALLOW for the same tool and verify disabling the DENY permits it.
    await h.admin(gw.base, operator, "/policies", {
      method: "POST",
      body: JSON.stringify({
        id: T("r-allow"),
        decision: "ALLOW",
        match: { tool: allowTool },
        reason: "allow",
      }),
    });
    await h.admin(gw.base, operator, "/policies", {
      method: "POST",
      body: JSON.stringify({
        id: T("r-deny"),
        decision: "DENY",
        match: { tool: allowTool },
        reason: "deny",
      }),
    });
    // Note: the DENY applies (severity) regardless of the ALLOW.
    expect(await decision(gw.base, allowTool)).toBe("DENY");

    const disable = await h.admin(gw.base, operator, `/policies/${T("r-deny")}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled: false }),
    });
    expect(disable.status).toBe(200);
    expect(await decision(gw.base, allowTool)).toBe("ALLOW");

    // A disabled ALLOW is ignored → default DENY.
    await h.admin(gw.base, operator, "/policies", {
      method: "POST",
      body: JSON.stringify({
        id: T("r-allow2"),
        decision: "ALLOW",
        match: { tool: denyTool },
        reason: "allow",
      }),
    });
    expect(await decision(gw.base, denyTool)).toBe("ALLOW");
    await h.admin(gw.base, operator, `/policies/${T("r-allow2")}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled: false }),
    });
    expect(await decision(gw.base, denyTool)).toBe("DENY");

    await gw.close();
  });

  it("does not apply a policy scoped to an unknown server", async () => {
    const tool = T("server-scope");
    const gw = await start([
      {
        id: T("other-server"),
        decision: "ALLOW",
        match: { tool, server: `${PREFIX}not-our-server` },
        reason: "x",
      },
    ]);
    expect(await decision(gw.base, tool)).toBe("DENY");
    await gw.close();
  });

  it("does not apply a policy scoped to an unknown agent", async () => {
    const tool = T("agent-scope");
    const gw = await start([
      {
        id: T("other-agent"),
        decision: "ALLOW",
        match: { tool, agent: `${PREFIX}someone-else` },
        reason: "x",
      },
    ]);
    expect(await decision(gw.base, tool)).toBe("DENY");
    await gw.close();
  });

  it("does not apply a method-scoped policy to a different method", async () => {
    const gw = await start([
      { id: T("list-only"), decision: "ALLOW", match: { method: "tools/list" }, reason: "list" },
    ]);
    const res = await h.mcp(gw.base, agent, T("anything"), {});
    const body = (await res.json()) as { error?: { code: number } };
    expect(body.error?.code).toBe(-32003);
    await gw.close();
  });

  it("argument constraints match exactly and fail closed on type manipulation", async () => {
    const tool = T("argtypes");
    const gw = await start([
      {
        id: T("allow-read"),
        decision: "ALLOW",
        match: { tool, arguments: { mode: { equals: "read" } } },
        reason: "read",
      },
    ]);
    expect(await decision(gw.base, tool, { mode: "read" })).toBe("ALLOW");
    expect(await decision(gw.base, tool, { mode: "write" })).toBe("DENY");
    expect(await decision(gw.base, tool, { mode: ["read"] })).toBe("DENY");
    expect(await decision(gw.base, tool, {})).toBe("DENY");
    expect(await decision(gw.base, tool, { mode: 1 })).toBe("DENY");
    await gw.close();
  });

  it("rejects malformed policy definitions without changing state", async () => {
    const gw = await start([]);

    const bad: Array<{ id: string; body: Record<string, unknown> }> = [
      { id: "", body: { id: "", decision: "ALLOW", match: {}, reason: "x" } },
      { id: T("bad1"), body: { id: T("bad1"), decision: "MAYBE", match: {}, reason: "x" } },
      { id: T("bad2"), body: { id: T("bad2"), decision: "ALLOW", match: {}, reason: "" } },
      {
        id: T("bad3"),
        body: { id: T("bad3"), decision: "ALLOW", match: { tool: 5 }, reason: "x" },
      },
      {
        id: T("bad4"),
        body: { id: T("bad4"), decision: "ALLOW", match: { arguments: { mode: {} } }, reason: "x" },
      },
    ];
    for (const { body } of bad) {
      const res = await h.admin(gw.base, operator, "/policies", {
        method: "POST",
        body: JSON.stringify(body),
      });
      expect(res.status).toBe(400);
    }

    // None of the rejected policies may exist (assert by id, not global count).
    for (const { id } of bad) {
      if (id === "") continue;
      expect((await h.admin(gw.base, operator, `/policies/${id}`)).status).toBe(404);
    }

    await gw.close();
  });

  it("keeps authorization consistent while a policy is modified during requests", async () => {
    const tool = T("reload-race");
    const gw = await start([
      { id: T("allow-race"), decision: "ALLOW", match: { tool }, reason: "allow" },
    ]);

    const toggle = h.admin(gw.base, operator, `/policies/${T("allow-race")}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled: false }),
    });
    const requests = Array.from({ length: 12 }, () => h.mcp(gw.base, agent, tool, {}));
    const [toggleRes, ...responses] = await Promise.all([toggle, ...requests]);
    expect(toggleRes.status).toBe(200);

    for (const response of responses) {
      expect(response.status).toBe(200);
      const body = (await response.json()) as { result?: unknown; error?: { code: number } };
      const valid =
        body.result !== undefined || body.error?.code === -32003 || body.error?.code === -32002;
      expect(valid).toBe(true);
    }

    // After the reload completes, the disabled policy consistently denies.
    expect(await decision(gw.base, tool)).toBe("DENY");
    await gw.close();
  });
});
