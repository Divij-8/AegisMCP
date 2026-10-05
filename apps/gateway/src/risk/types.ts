/**
 * Risk domain types.
 *
 * Risk is computed AFTER policy evaluation and can only ever make a decision
 * MORE restrictive. It can never turn a DENY into an ALLOW.
 */

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** Ascending severity — higher wins. */
export const RISK_SEVERITY: Record<RiskLevel, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

/** A single explainable risk finding. */
export interface RiskFinding {
  /** Stable machine-readable signal, e.g. "destructive-tool". */
  readonly signal: string;
  /** Human-readable explanation for operators/audit. */
  readonly detail: string;
  /** The level this finding implies on its own. */
  readonly level: RiskLevel;
}

/** Result of evaluating a request against the risk rules. */
export interface RiskAssessment {
  /** Highest level across all findings, or the configured baseline. */
  readonly level: RiskLevel;
  /** Every signal that contributed, deterministic order. */
  readonly findings: readonly RiskFinding[];
  /** Human-readable summary — always non-empty. */
  readonly reason: string;
  /** True when the assessment requests enhanced auditing (MEDIUM+). */
  readonly enhancedAudit: boolean;
}
