/**
 * Buffered audit sink — non-blocking capture, batched PostgreSQL delivery.
 *
 * record() enqueues synchronously and returns immediately: the MCP proxy
 * path never awaits a database write. A background timer flushes batches;
 * flush() drains on shutdown/tests; close() stops the timer and drains.
 *
 * Under pressure (queue at capacity) the OLDEST event is dropped and the
 * dropped counter increments — the gateway never applies backpressure to
 * proxied requests. Persistence failures increment failed after retries.
 *
 * Counters (queued/flushed/failed/dropped) are exposed through stats() so
 * metrics can be added later without changing call sites.
 */

import type { AuditEvent, AuditSink, AuditSinkStats } from "./types.js";
import type { AuditEventRepository } from "../repositories/types.js";

export interface BufferedAuditSinkOptions {
  /** Max events held in memory before oldest are dropped. Default 10,000. */
  readonly maxQueueSize?: number;
  /** Batch size target for each flush. Default 100. */
  readonly batchSize?: number;
  /** Interval between background flushes. Default 5,000ms. */
  readonly flushIntervalMs?: number;
  /** Attempts per batch before counting it failed. Default 3. */
  readonly maxAttempts?: number;
  /** Error observer — defaults to console.error. */
  readonly onError?: (error: unknown) => void;
}

const DEFAULTS = {
  maxQueueSize: 10_000,
  batchSize: 100,
  flushIntervalMs: 5_000,
  maxAttempts: 3,
} as const;

export class BufferedAuditSink implements AuditSink {
  private queue: AuditEvent[] = [];
  private flushPromise: Promise<void> = Promise.resolve();
  private timer: NodeJS.Timeout | undefined;
  private closed = false;

  private flushed = 0;
  private failed = 0;
  private dropped = 0;

  constructor(
    private readonly repository: AuditEventRepository,
    private readonly options: BufferedAuditSinkOptions = {},
  ) {
    const { flushIntervalMs } = { ...DEFAULTS, ...options };
    this.timer = setInterval(() => {
      void this.flush().catch(this.options.onError);
    }, flushIntervalMs);
    this.timer.unref?.();
  }

  record(event: AuditEvent): void {
    if (this.closed) return;

    if (this.queue.length >= this.maxQueueSize) {
      this.queue.shift();
      this.dropped += 1;
    }
    this.queue.push(event);
  }

  /**
   * Drain the queue in batches. Concurrent calls serialize — each flush
   * waits for the previous one, so close() always fully drains.
   */
  flush(): Promise<void> {
    const task = (async () => {
      await this.flushPromise.catch(() => {});
      while (this.queue.length > 0) {
        const batch = this.queue.splice(0, this.batchSize);
        await this.deliver(batch);
      }
    })();
    this.flushPromise = task;
    return task;
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    if (this.timer !== undefined) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
    await this.flush();
  }

  stats(): AuditSinkStats {
    return {
      queued: this.queue.length,
      flushed: this.flushed,
      failed: this.failed,
      dropped: this.dropped,
    };
  }

  private get maxQueueSize(): number {
    return this.options.maxQueueSize ?? DEFAULTS.maxQueueSize;
  }

  private get batchSize(): number {
    return this.options.batchSize ?? DEFAULTS.batchSize;
  }

  private get maxAttempts(): number {
    return this.options.maxAttempts ?? DEFAULTS.maxAttempts;
  }

  private async deliver(batch: readonly AuditEvent[]): Promise<void> {
    for (let attempt = 1; attempt <= this.maxAttempts; attempt++) {
      try {
        await this.repository.insertBatch(batch);
        this.flushed += batch.length;
        return;
      } catch (error) {
        if (attempt === this.maxAttempts) {
          this.failed += batch.length;
          const onError = this.options.onError ?? ((err: unknown) => console.error(err));
          onError(error);
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, attempt * 100));
      }
    }
  }
}
