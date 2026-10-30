import { describe, expect, it, vi } from "vitest";
import {
  applyDeterministicExfiltrationPolicy,
  evaluateMcpExfiltration
} from "../src/mcp-exfiltration-guard.js";
import { evaluateMcpToolCallShadow } from "../examples/mcp-exfiltration-callout.js";

const observation = (overrides = {}) => ({
  schemaVersion: "1",
  tool: "search_events",
  tenantBoundaryValid: true,
  requestedRecords: 25,
  priorReleasedRecordsInWindow: 100,
  projectedCallsInWindow: 5,
  projectedDistinctResourcesInWindow: 2,
  priorFailedCallsInWindow: 0,
  ...overrides
});

const choice = (selected, choices, confidence = 0.9) => ({
  type: "choice",
  choice: selected,
  probabilities: Object.fromEntries(
    choices.map((value) => [
      value,
      value === selected ? confidence : (1 - confidence) / (choices.length - 1)
    ])
  ),
  confidence
});

const modelResponse = ({
  pattern = "expected",
  risk = "low",
  humanReview = 0.1
} = {}) => ({
  model: "clef",
  answers: {
    pattern: choice(pattern, ["expected", "unusual", "likely_exfiltration"]),
    risk: choice(risk, ["low", "medium", "high", "critical"]),
    humanReview: { type: "noul", noul: humanReview }
  },
  usage: { input_tokens: 40, output_tokens: 10 }
});

describe("MCP exfiltration guard", () => {
  it("denies tenant, tool, and volume boundary violations deterministically", () => {
    expect(
      applyDeterministicExfiltrationPolicy(
        observation({ tenantBoundaryValid: false })
      ).reason
    ).toBe("tenant_boundary_invalid");
    expect(
      applyDeterministicExfiltrationPolicy(
        observation({ tool: "export_all_customers" })
      ).reason
    ).toBe("tool_not_allowed");
    expect(
      applyDeterministicExfiltrationPolicy(
        observation({ requestedRecords: 251 })
      ).reason
    ).toBe("request_size_exceeds_policy");
    expect(
      applyDeterministicExfiltrationPolicy(
        observation({ requestedRecords: 100, priorReleasedRecordsInWindow: 950 })
      ).reason
    ).toBe("projected_release_exceeds_policy");
  });

  it("routes unusual rolling behavior to review", () => {
    expect(
      applyDeterministicExfiltrationPolicy(
        observation({ projectedCallsInWindow: 31 })
      )
        .decision
    ).toBe("review");
    expect(
      applyDeterministicExfiltrationPolicy(
        observation({ projectedDistinctResourcesInWindow: 11 })
      ).decision
    ).toBe("review");
    expect(
      applyDeterministicExfiltrationPolicy(
        observation({ priorFailedCallsInWindow: 6 })
      ).decision
    ).toBe("review");
  });

  it("does not call Clef after a deterministic denial", async () => {
    const ai = { run: vi.fn() };
    const result = await evaluateMcpExfiltration(
      { AI: ai },
      observation({ tenantBoundaryValid: false })
    );
    expect(result.policy.decision).toBe("deny");
    expect(result.modelEvaluated).toBe(false);
    expect(ai.run).not.toHaveBeenCalled();
  });

  it("allows expected activity without executing the MCP tool", async () => {
    const ai = { run: vi.fn().mockResolvedValue(modelResponse()) };
    const result = await evaluateMcpExfiltration({ AI: ai }, observation());
    expect(result.policy.decision).toBe("allow");
    expect(result.classification.risk).toBe("low");
    expect(result.executed).toBe(false);
    expect(ai.run).toHaveBeenCalledWith(
      "@cf/cloudflare/clef",
      expect.objectContaining({ model: "clef" })
    );
  });

  it("keeps deterministic review even when Clef reports expected activity", async () => {
    const result = await evaluateMcpExfiltration(
      { AI: { run: vi.fn().mockResolvedValue(modelResponse()) } },
      observation({ projectedCallsInWindow: 31 })
    );
    expect(result.policy.decision).toBe("review");
  });

  it("lets Clef narrow an allow decision but never widen policy", async () => {
    const result = await evaluateMcpExfiltration(
      {
        AI: {
          run: vi.fn().mockResolvedValue(
            modelResponse({ pattern: "likely_exfiltration", risk: "high" })
          )
        }
      },
      observation()
    );
    expect(result.policy.decision).toBe("deny");
    expect(result.policy.reason).toBe("model_classification_requires_denial");
  });

  it("fails closed when the model output is unavailable or malformed", async () => {
    const unavailable = await evaluateMcpExfiltration(
      { AI: { run: vi.fn().mockRejectedValue(new Error("down")) } },
      observation()
    );
    const malformed = modelResponse();
    malformed.answers.risk.probabilities.low = Number.NaN;
    const invalid = await evaluateMcpExfiltration(
      { AI: { run: vi.fn().mockResolvedValue(malformed) } },
      observation()
    );
    expect(unavailable.policy.decision).toBe("deny");
    expect(invalid.policy.decision).toBe("deny");
  });

  it("requires a model identifier and valid confidence", async () => {
    const missingModel = modelResponse();
    delete missingModel.model;
    const conflictingConfidence = modelResponse();
    conflictingConfidence.answers.pattern.confidence = 0.2;

    for (const response of [missingModel, conflictingConfidence]) {
      const result = await evaluateMcpExfiltration(
        { AI: { run: vi.fn().mockResolvedValue(response) } },
        observation()
      );
      expect(result.policy.decision).toBe("deny");
    }
  });

  it("uses projected counters at the exact policy boundary", () => {
    expect(
      applyDeterministicExfiltrationPolicy(
        observation({ projectedCallsInWindow: 30 })
      ).decision
    ).toBe("allow");
    expect(
      applyDeterministicExfiltrationPolicy(
        observation({ projectedCallsInWindow: 31 })
      ).decision
    ).toBe("review");
  });

  it("passes only normalized metrics to Clef", async () => {
    const ai = { run: vi.fn().mockResolvedValue(modelResponse()) };
    await evaluateMcpExfiltration({ AI: ai }, observation());
    const state = ai.run.mock.calls[0][1].state;
    expect(Object.keys(state).sort()).toEqual(
      [
        "schemaVersion",
        "tool",
        "requestedRecords",
        "priorReleasedRecordsInWindow",
        "projectedCallsInWindow",
        "projectedDistinctResourcesInWindow",
        "priorFailedCallsInWindow",
        "customerPolicy"
      ].sort()
    );
    expect(JSON.stringify(state)).not.toContain("customer data");
  });

  it("keeps the router wrapper in shadow mode", async () => {
    const { schemaVersion, ...routerMetrics } = observation();
    const result = await evaluateMcpToolCallShadow(
      { AI: { run: vi.fn().mockResolvedValue(modelResponse()) } },
      routerMetrics
    );
    expect(result).toMatchObject({
      recommendedAction: "allow",
      shadowOnly: true
    });
    expect(result.allowed).toBeUndefined();
    expect(schemaVersion).toBe("1");
  });

  it("rejects extra fields at the router wrapper boundary", async () => {
    const { schemaVersion, ...routerMetrics } = observation();
    await expect(
      evaluateMcpToolCallShadow(
        { AI: { run: vi.fn().mockResolvedValue(modelResponse()) } },
        { ...routerMetrics, rawResponse: "customer data" }
      )
    ).rejects.toThrow("invalid_router_metrics");
    expect(schemaVersion).toBe("1");
  });

  it("rejects caller-controlled fields outside the normalized schema", () => {
    expect(() =>
      applyDeterministicExfiltrationPolicy(
        observation({ rawResponse: "customer data" })
      )
    ).toThrow("invalid_observation");
  });
});
