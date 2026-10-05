import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { SecurityHarness, hasDb } from "./helpers.js";

const d = describe.skipIf(!hasDb);

const PREFIX = "sec-fuzz-";
const TOOL = `${PREFIX}tool`;
const policies = [
  { id: `${PREFIX}allow`, decision: "ALLOW" as const, match: { tool: TOOL }, reason: "fuzz allow" },
];

// Patterns that indicate an internal error leaked to the client.
const LEAK_PATTERNS = [
  /node_modules/,
  /\bat\s+\w+\s+\(/,
  /\.ts:\d+/,
  /TypeError/,
  /FastifyError/,
  /\/Users\//,
];

function assertNoLeak(text: string): void {
  for (const pattern of LEAK_PATTERNS) {
    expect(pattern.test(text)).toBe(false);
  }
}

d("SECURITY: malformed/hostile input is handled safely", () => {
  const h = new SecurityHarness(PREFIX, policies);
  let agent = "";
  let admin = "";

  beforeAll(() => h.setup());
  afterAll(() => h.teardown());
  beforeEach(async () => {
    await h.clean();
    agent = await h.provision(`${PREFIX}agent`);
    admin = await h.provision(`${PREFIX}admin`, "ADMIN");
  });

  async function post(base: string, body: string, contentType = "application/json") {
    return fetch(`${base}/mcp`, {
      method: "POST",
      headers: { "content-type": contentType, authorization: `Bearer ${agent}` },
      body,
    });
  }

  it("survives malformed JSON-RPC envelopes without crashing or leaking", async () => {
    const gw = await h.startGateway();
    const cases: Array<[string, number]> = [
      ["{", -32700],
      ["[1,2,3]", -32600],
      ['"a string"', -32600],
      ["42", -32600],
      ["null", -32600],
      ['{"id":1}', -32600],
      ['{"jsonrpc":"2.0","id":1}', -32600],
      ['{"jsonrpc":"1.0","id":1,"method":"tools/call"}', -32600],
      ['{"jsonrpc":"2.0","id":1,"method":123}', -32600],
      ['{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":123}}', -32602],
      [
        '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":[]}}',
        -32602,
      ],
      [
        '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","_meta":{"io.modelcontextprotocol/protocolVersion":"bogus"}}}',
        -32600,
      ],
    ];
    for (const [body, expected] of cases) {
      const res = await post(gw.base, body);
      expect(res.status).toBe(200);
      const text = await res.text();
      const parsed = JSON.parse(text) as { error?: { code: number } };
      expect(parsed.error?.code).toBe(expected);
      assertNoLeak(text);
    }
    await gw.close();
  });

  it("tolerates duplicate JSON keys, unicode, and extreme values", async () => {
    const gw = await h.startGateway();
    const bodies = [
      '{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/call","params":{"name":"' +
        TOOL +
        '","arguments":{}}}',
      JSON.stringify({
        jsonrpc: "2.0",
        id: "😀",
        method: "tools/call",
        params: { name: TOOL, arguments: { emoji: "🎉" } },
      }),
      JSON.stringify({
        jsonrpc: "2.0",
        id: -1.5e308,
        method: "tools/call",
        params: { name: TOOL, arguments: { n: 1e308 } },
      }),
    ];
    for (const body of bodies) {
      const res = await post(gw.base, body);
      expect(res.status).toBe(200);
      assertNoLeak(await res.text());
    }
    await gw.close();
  });

  it("rejects oversized request bodies deterministically", async () => {
    const gw = await h.startGateway();
    const huge = "x".repeat(2 * 1024 * 1024);
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: TOOL, arguments: { big: huge } },
    });

    // The server may either answer 413/200 or reset the connection mid-write
    // (a valid refusal of an oversized body). Both are safe; neither may leak.
    try {
      const res = await post(gw.base, body);
      expect([413, 200]).toContain(res.status);
      assertNoLeak(await res.text());
    } catch (error) {
      expect(String(error)).toMatch(/ECONNRESET|fetch failed|socket hang up/i);
    }

    // Still available and serving normal requests afterwards.
    expect((await fetch(`${gw.base}/health`)).status).toBe(200);
    const ok = await h.mcp(gw.base, agent, TOOL, { n: 1 });
    expect(ok.status).toBe(200);
    await gw.close();
  });

  it("rejects deeply nested and huge tool arguments without crashing", async () => {
    const gw = await h.startGateway();
    let deep: Record<string, unknown> = {};
    for (let i = 0; i < 2000; i++) deep = { child: deep };
    const res = await post(
      gw.base,
      JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: TOOL, arguments: deep },
      }),
    );
    expect(res.status).toBe(200);
    assertNoLeak(await res.text());

    // Still available afterwards.
    expect((await fetch(`${gw.base}/health`)).status).toBe(200);
    await gw.close();
  });

  it("validates admin query parameters and pagination deterministically", async () => {
    const gw = await h.startGateway();
    const badQueries = [
      "/policies?limit=0",
      "/policies?limit=-1",
      "/policies?limit=100000",
      "/policies?limit=abc",
      "/policies?offset=-5",
      "/policies?offset=abc",
      "/audit?since=notanumber",
      "/approvals?status=BOGUS",
    ];
    for (const path of badQueries) {
      const res = await h.admin(gw.base, admin, path);
      expect(res.status).toBe(400);
      assertNoLeak(await res.text());
    }
    await gw.close();
  });

  it("handles hostile admin request bodies without crashing", async () => {
    const gw = await h.startGateway();
    const bodies = [
      "null",
      "[]",
      '"str"',
      "42",
      '{"id":{}}',
      '{"id":""}',
      '{"decision":["ALLOW"],"id":"x","reason":"y"}',
    ];
    for (const body of bodies) {
      const res = await h.admin(gw.base, admin, "/policies", { method: "POST", body });
      expect([400, 415]).toContain(res.status);
      assertNoLeak(await res.text());
    }
    // Malformed JSON in an admin body must not 500.
    const malformed = await fetch(`${gw.base}/admin/policies`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${admin}` },
      body: "{",
    });
    expect(malformed.status).toBeGreaterThanOrEqual(400);
    expect(malformed.status).toBeLessThan(500);
    assertNoLeak(await malformed.text());

    // Invalid JSON-RPC ids and unknown approval ids.
    const approvals = await Promise.all(
      ["", "   ", "apr_" + "f".repeat(5000), "../../etc/passwd", "<script>alert(1)</script>"].map(
        (id) => h.admin(gw.base, admin, `/approvals/${encodeURIComponent(id)}`),
      ),
    );
    for (const res of approvals) {
      // Any 4xx is acceptable (404 unknown, 400 invalid, 414 URI too long).
      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(res.status).toBeLessThan(500);
      assertNoLeak(await res.text());
    }

    expect((await fetch(`${gw.base}/health`)).status).toBe(200);
    await gw.close();
  });
});
