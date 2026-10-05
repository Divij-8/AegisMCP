import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { SecurityHarness, hasDb } from "./helpers.js";

const d = describe.skipIf(!hasDb);

const PREFIX = "sec-perf-";
const SAFE = `${PREFIX}safe`;
const DENY = `${PREFIX}deny`;
const APPR = `${PREFIX}appr`;

const policies = [
  { id: `${PREFIX}allow`, decision: "ALLOW" as const, match: { tool: SAFE }, reason: "safe" },
  { id: `${PREFIX}deny`, decision: "DENY" as const, match: { tool: DENY }, reason: "denied" },
  {
    id: `${PREFIX}require`,
    decision: "REQUIRE_APPROVAL" as const,
    match: { tool: APPR },
    reason: "approval",
  },
];

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1]! + sorted[mid]!) / 2 : sorted[mid]!;
}

function percentile(values: number[], p: number): number {
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1);
  return sorted[index]!;
}

d("PERFORMANCE: end-to-end latency baseline (HTTP, PostgreSQL)", () => {
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

  async function measure(n: number, fn: () => Promise<unknown>): Promise<number[]> {
    await fn();
    await fn(); // warmup
    const samples: number[] = [];
    for (let i = 0; i < n; i++) {
      const start = performance.now();
      await fn();
      samples.push(performance.now() - start);
    }
    return samples;
  }

  // Generous timeout: this test performs real Postgres round-trips and runs
  // alongside other DB suites.
  it(
    "records latency for allowed / denied / auth-failure / approval / approved",
    { timeout: 60_000 },
    async () => {
      const gw = await h.startGateway();

      const allowed = await measure(12, () =>
        h.mcp(gw.base, agent, SAFE, { n: 1 }, {}, crypto.randomUUID()),
      );
      const denied = await measure(12, () =>
        h.mcp(gw.base, agent, DENY, {}, {}, crypto.randomUUID()),
      );
      const authFail = await measure(12, () =>
        h.mcp(gw.base, "amcp_bad_bad", SAFE, {}, {}, crypto.randomUUID()),
      );
      const approvalRequired = await measure(10, () =>
        h.mcp(gw.base, agent, APPR, { n: 1 }, {}, crypto.randomUUID()),
      );

      const approved = await measure(6, async () => {
        const created = await h.createApproval(gw.base, agent, APPR, { n: 1 });
        await h.approveVia(gw.base, admin, created.approvalId);
        return h.mcp(gw.base, agent, APPR, { n: 1 }, { "x-aegis-approval-id": created.approvalId });
      });

      const report = [
        ["allowed (ALLOW)", allowed],
        ["denied (DENY)", denied],
        ["auth failure", authFail],
        ["approval required (create)", approvalRequired],
        ["approved (create+approve+execute)", approved],
      ] as const;

      const lines = report.map(
        ([name, samples]) =>
          `  ${name.padEnd(34)} median=${median(samples).toFixed(2)}ms p95=${percentile(samples, 95).toFixed(2)}ms`,
      );
      console.log("\nEnd-to-end latency baseline:\n" + lines.join("\n") + "\n");

      // Loose guardrails: catch pathological regressions, not normal variance.
      for (const [, samples] of report) {
        expect(percentile(samples, 95)).toBeLessThan(1500);
      }

      await gw.close();
    },
  );
});
