import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { BufferedAuditSink } from "./sink.js";
import type { AuditEventRepository, Page } from "../repositories/types.js";
import type { AuditEvent } from "./types.js";

function makeEvent(overrides?: Partial<AuditEvent>): AuditEvent {
  return {
    eventType: "request",
    requestId: 1,
    occurredAt: Date.now(),
    agentId: "agent-1",
    serverId: "server-1",
    method: "tools/call",
    toolName: "echo",
    decision: "ALLOW",
    policyId: "allow-echo",
    reason: "test",
    outcome: "forwarded",
    upstreamStatus: 200,
    latencyMs: 5,
    ...overrides,
  };
}

class FakeAuditRepository implements AuditEventRepository {
  public batches: AuditEvent[][] = [];
  public failNext = 0;

  async insertBatch(events: readonly AuditEvent[]): Promise<void> {
    if (this.failNext > 0) {
      this.failNext -= 1;
      throw new Error("db unavailable");
    }
    this.batches.push([...events]);
  }

  async list(): Promise<Page<AuditEvent & { id: string }>> {
    return { items: [], total: 0, limit: 0, offset: 0 };
  }

  async findById(): Promise<(AuditEvent & { id: string }) | null> {
    return null;
  }
}

describe("BufferedAuditSink", () => {
  let repo: FakeAuditRepository;

  beforeEach(() => {
    vi.useFakeTimers();
    repo = new FakeAuditRepository();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function makeSink(options = {}) {
    return new BufferedAuditSink(repo, { flushIntervalMs: 1_000, ...options });
  }

  it("record() does not persist immediately (non-blocking)", async () => {
    const sink = makeSink();
    sink.record(makeEvent());
    expect(repo.batches).toHaveLength(0);
    expect(sink.stats().queued).toBe(1);
    await sink.close();
  });

  it("flush() delivers queued events as a batch", async () => {
    const sink = makeSink();
    sink.record(makeEvent({ requestId: 1 }));
    sink.record(makeEvent({ requestId: 2 }));
    await sink.flush();

    expect(repo.batches).toHaveLength(1);
    expect(repo.batches[0]).toHaveLength(2);
    expect(sink.stats().flushed).toBe(2);
    expect(sink.stats().queued).toBe(0);
    await sink.close();
  });

  it("background timer flushes automatically", async () => {
    const sink = makeSink();
    sink.record(makeEvent());

    await vi.advanceTimersByTimeAsync(1_100);
    expect(sink.stats().flushed).toBe(1);
    await sink.close();
  });

  it("close() drains remaining events and stops the timer", async () => {
    const sink = makeSink();
    sink.record(makeEvent({ requestId: "a" }));
    sink.record(makeEvent({ requestId: "b" }));
    await sink.close();

    expect(repo.batches.at(-1)).toHaveLength(2);

    sink.record(makeEvent({ requestId: "c" }));
    await vi.advanceTimersByTimeAsync(10_000);
    expect(sink.stats().queued).toBe(0);
    expect(sink.stats().flushed).toBe(2);
  });

  it("drops the OLDEST event when the queue is full and counts it", async () => {
    const sink = makeSink({ maxQueueSize: 3, maxAttempts: 1 });
    sink.record(makeEvent({ requestId: 1 }));
    sink.record(makeEvent({ requestId: 2 }));
    sink.record(makeEvent({ requestId: 3 }));
    sink.record(makeEvent({ requestId: 4 }));

    expect(sink.stats().dropped).toBe(1);
    expect(sink.stats().queued).toBe(3);

    await sink.flush();
    expect(repo.batches[0]!.map((e) => e.requestId)).toEqual([2, 3, 4]);
    await sink.close();
  });

  it("counts events as failed after exhausting retries and continues", async () => {
    const onError = vi.fn();
    const sink = makeSink({ maxAttempts: 2, onError });
    repo.failNext = 2; // fail every attempt (maxAttempts = 2)
    sink.record(makeEvent({ requestId: 1 }));

    const firstFlush = sink.flush();
    await vi.advanceTimersByTimeAsync(1_000); // run retry backoff timers (100ms, 200ms)
    await firstFlush;

    expect(sink.stats().failed).toBe(1);
    expect(sink.stats().flushed).toBe(0);
    expect(onError).toHaveBeenCalled();

    repo.failNext = 0;
    sink.record(makeEvent({ requestId: 2 }));
    await sink.flush();
    expect(sink.stats().flushed).toBe(1);
    await sink.close();
  });

  it("flushes in batches of batchSize", async () => {
    const sink = makeSink({ batchSize: 2 });
    for (let i = 0; i < 5; i++) sink.record(makeEvent({ requestId: i }));
    await sink.flush();

    expect(repo.batches.map((b) => b.length)).toEqual([2, 2, 1]);
    expect(sink.stats().flushed).toBe(5);
    await sink.close();
  });

  it("stats() exposes all four counters", async () => {
    const onError = vi.fn();
    const sink = makeSink({ maxQueueSize: 1, maxAttempts: 1, onError });
    expect(sink.stats()).toEqual({ queued: 0, flushed: 0, failed: 0, dropped: 0 });

    sink.record(makeEvent({ requestId: 1 }));
    sink.record(makeEvent({ requestId: 2 })); // drops #1
    await sink.flush();

    const stats = sink.stats();
    expect(stats.dropped).toBe(1);
    expect(stats.flushed).toBe(1);
    expect(stats.failed).toBe(0);
    expect(stats.queued).toBe(0);
    await sink.close();
  });

  it("close() is idempotent", async () => {
    const sink = makeSink();
    await sink.close();
    await expect(sink.close()).resolves.toBeUndefined();
  });
});
