/**
 * Risk engine — a deterministic, explainable layer between policy evaluation
 * and the final decision.
 *
 * The engine computes a risk level from configurable rules and then applies a
 * level→decision mapping. It can ONLY make a decision more restrictive:
 *
 *   finalSeverity = max(policySeverity, mappedSeverity)
 *
 * A DENY policy is never weakened, and a risk rule can never turn DENY into
 * ALLOW or REQUIRE_APPROVAL. When no rule fires, the configured baseline level
 * (LOW by default) is used and the policy decision passes through unchanged.
 */

import type { SecurityContext } from "../mcp/types.js";
import type { PolicyDecision, PolicyEvaluation } from "../policy/types.js";
import { SEVERITY } from "../policy/defaults.js";
import { RISK_SEVERITY, type RiskAssessment, type RiskFinding, type RiskLevel } from "./types.js";

/** A named rule that recognizes one risk signal from the request. */
export interface RiskRule {
  readonly signal: string;
  readonly detail: string;
  readonly level: RiskLevel;
  /** Pure predicate over the request. Must not throw. */
  test(context: SecurityContext): boolean;
}

/**
 * What each risk level does to the decision. "INHERIT" leaves the policy
 * decision untouched (the engine still records the level).
 */
export type RiskMapping = Record<RiskLevel, PolicyDecision | "INHERIT">;

export const DEFAULT_RISK_MAPPING: RiskMapping = {
  LOW: "INHERIT",
  MEDIUM: "INHERIT",
  HIGH: "REQUIRE_APPROVAL",
  CRITICAL: "DENY",
};

const DESTRUCTIVE = /(delete|destroy|drop|truncate|purge|wipe|remove|rm\b|unlink)/i;
const SHELL = /(shell|exec|spawn|command|bash|sh\b|powershell|subprocess)/i;
const DB_MUTATION = /(insert|update|upsert|mutate|migrate|alter|create[_-]?table|grant|revoke)/i;
const INFRA = /(deploy|provision|terraform|infra|cluster|scale|restart|reboot)/i;
const EXTERNAL = /(send|publish|post|webhook|email|mail|payment|transfer|notify|sms)/i;
const READ_ONLY = /(read|get|list|search|query|fetch|describe|inspect|view|lookup|status)/i;

function targetOf(context: SecurityContext): string {
  return `${context.method} ${context.toolName ?? ""}`;
}

export const DEFAULT_RISK_RULES: readonly RiskRule[] = [
  {
    signal: "shell-execution",
    detail: "Tool appears to execute shell/OS commands",
    level: "CRITICAL",
    test: (c) => SHELL.test(targetOf(c)),
  },
  {
    signal: "destructive-operation",
    detail: "Tool appears to delete or destroy data",
    level: "HIGH",
    test: (c) => DESTRUCTIVE.test(targetOf(c)),
  },
  {
    signal: "database-mutation",
    detail: "Tool appears to mutate a database",
    level: "HIGH",
    test: (c) => DB_MUTATION.test(targetOf(c)),
  },
  {
    signal: "infrastructure-change",
    detail: "Tool appears to change infrastructure",
    level: "HIGH",
    test: (c) => INFRA.test(targetOf(c)),
  },
  {
    signal: "external-side-effect",
    detail: "Tool appears to produce an external side effect",
    level: "MEDIUM",
    test: (c) => EXTERNAL.test(targetOf(c)),
  },
  {
    signal: "read-only",
    detail: "Tool appears read-only",
    level: "LOW",
    test: (c) => READ_ONLY.test(targetOf(c)),
  },
];

export interface RiskEngineOptions {
  readonly baseline?: RiskLevel;
  readonly rules?: readonly RiskRule[];
  readonly mapping?: RiskMapping;
}

export interface RiskDecision {
  readonly evaluation: PolicyEvaluation;
  readonly assessment: RiskAssessment;
}

export class RiskEngine {
  private readonly baseline: RiskLevel;
  private readonly rules: readonly RiskRule[];
  private readonly mapping: RiskMapping;

  constructor(options: RiskEngineOptions = {}) {
    this.baseline = options.baseline ?? "LOW";
    this.rules = options.rules ?? DEFAULT_RISK_RULES;
    this.mapping = options.mapping ?? DEFAULT_RISK_MAPPING;
  }

  /** Compute the risk assessment for a request. Deterministic and pure. */
  assess(context: SecurityContext): RiskAssessment {
    const findings: RiskFinding[] = [];
    for (const rule of this.rules) {
      let matched = false;
      try {
        matched = rule.test(context);
      } catch {
        matched = false;
      }
      if (matched) {
        findings.push({ signal: rule.signal, detail: rule.detail, level: rule.level });
      }
    }

    let level = this.baseline;
    for (const finding of findings) {
      if (RISK_SEVERITY[finding.level] > RISK_SEVERITY[level]) level = finding.level;
    }

    const reason =
      findings.length === 0
        ? `No risk rule matched; baseline ${this.baseline}`
        : findings
            .map((finding) => `${finding.signal}=${finding.level} (${finding.detail})`)
            .join("; ");

    return {
      level,
      findings: Object.freeze(findings),
      reason,
      enhancedAudit: RISK_SEVERITY[level] >= RISK_SEVERITY.MEDIUM,
    };
  }

  /**
   * Combine a policy evaluation with the risk level. Returns an evaluation that
   * is at least as restrictive as the input, plus the assessment for audit.
   */
  apply(context: SecurityContext, evaluation: PolicyEvaluation): RiskDecision {
    const assessment = this.assess(context);
    const mapped = this.mapping[assessment.level];
    if (mapped === "INHERIT") {
      return { evaluation, assessment };
    }

    const mappedSeverity = SEVERITY[mapped];
    const currentSeverity = SEVERITY[evaluation.decision];
    if (mappedSeverity <= currentSeverity) {
      // Never weaken an explicit decision.
      return { evaluation, assessment };
    }

    return {
      evaluation: {
        decision: mapped,
        policyId: evaluation.policyId,
        reason: `${evaluation.reason} (risk ${assessment.level}: ${assessment.reason})`,
      },
      assessment,
    };
  }
}
