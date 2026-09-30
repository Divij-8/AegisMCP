/**
 * PolicyStore — supplies an atomically readable, immutable snapshot of the
 * active policy set.
 *
 * The PolicyEngine stays pure (no DB, no IO). This store is the only piece
 * that knows where policies come from. A successful reload swaps the
 * snapshot reference in one assignment; readers always see a complete,
 * consistent policy set — never a half-updated one.
 */

import type { Policy } from "./types.js";
import type { PolicyRepository } from "../repositories/types.js";
import { PolicyEngine } from "./engine.js";
import { validatePolicies } from "./validate.js";

export interface PolicySnapshot {
  readonly policies: readonly Policy[];
  readonly loadedAt: number;
}

export class PolicyStore {
  private snapshot: PolicySnapshot;

  constructor(
    private readonly repository: PolicyRepository | null,
    initialPolicies: readonly Policy[] = [],
  ) {
    validatePolicies([...initialPolicies]);
    this.snapshot = Object.freeze({
      policies: Object.freeze([...initialPolicies]),
      loadedAt: Date.now(),
    });
  }

  /**
   * Build a PolicyEngine from the current snapshot. Call per request —
   * construction is cheap (validate + freeze of a small array) and guarantees
   * a request never sees a stale engine after a successful reload.
   */
  buildEngine(): PolicyEngine {
    return new PolicyEngine([...this.snapshot.policies]);
  }

  /** Current snapshot without building an engine (introspection/tests). */
  getSnapshot(): PolicySnapshot {
    return this.snapshot;
  }

  /**
   * Reload policies from the repository and swap the snapshot atomically.
   *
   * @returns true if the snapshot changed.
   * @throws if persistence fails or loaded policies are invalid — callers
   *         decide whether to crash (startup) or keep serving (runtime).
   */
  async reload(): Promise<boolean> {
    if (this.repository === null) return false;

    const policies = await this.repository.listEnabled();
    validatePolicies([...policies]); // throws on invalid rows — fail-closed

    const next: PolicySnapshot = Object.freeze({
      policies: Object.freeze([...policies]),
      loadedAt: Date.now(),
    });

    const changed = JSON.stringify(next.policies) !== JSON.stringify(this.snapshot.policies);
    this.snapshot = next;
    return changed;
  }

  /**
   * Perform a reload, keeping the last-known-good snapshot on failure.
   * Intended for periodic/background refresh where throwing is not useful.
   *
   * @returns true if the snapshot changed; false on failure (unchanged).
   */
  async reloadSafe(): Promise<boolean> {
    try {
      return await this.reload();
    } catch {
      return false;
    }
  }
}
