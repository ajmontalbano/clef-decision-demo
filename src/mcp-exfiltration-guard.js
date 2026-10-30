const MODEL = "@cf/cloudflare/clef";
const MAX_METRIC_VALUE = 1_000_000_000;

export const SYNTHETIC_EXFILTRATION_POLICY = Object.freeze({
  id: "synthetic-customer-read-policy-v1",
  allowedTools: Object.freeze(["search_events", "get_event_summary"]),
  maxRequestedRecords: 250,
  maxReleasedRecordsPerWindow: 1_000,
  maxCallsPerWindow: 30,
  maxDistinctResourcesPerWindow: 10,
  maxFailedCallsPerWindow: 5
});

const QUESTIONS = Object.freeze({
  pattern: {
    type: "choice",
    instructions:
      "Does this normalized MCP activity look expected, unusual, or like likely data exfiltration?",
    criteria: {
      expected: "Consistent with the supplied policy and ordinary read activity",
      unusual: "Atypical activity that should be reviewed before data is returned",
      likely_exfiltration:
        "A pattern consistent with bulk extraction, enumeration, or unauthorized data collection"
    }
  },
  risk: {
    type: "choice",
    instructions: "What is the data-exfiltration risk of this normalized activity?",
    criteria: {
      low: "Expected activity within the supplied customer policy",
      medium: "Unusual activity with limited potential exposure",
      high: "Likely extraction of more data than the customer normally requires",
      critical: "Cross-tenant or broad data exposure requiring immediate denial"
    }
  },
  humanReview: {
    type: "noul",
    instructions: "Should a human review this activity before any data is returned?"
  }
});

const isProbability = (value) =>
  Number.isFinite(value) && value >= 0 && value <= 1;

function requireExactKeys(value, expectedKeys, errorCode) {
  if (!value || Array.isArray(value) || typeof value !== "object") {
    throw new Error(errorCode);
  }
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(errorCode);
  }
}

function requireMetric(value, field) {
  if (!Number.isInteger(value) || value < 0 || value > MAX_METRIC_VALUE) {
    throw new Error(`invalid_${field}`);
  }
}

function validatePolicy(policy) {
  requireExactKeys(
    policy,
    [
      "id",
      "allowedTools",
      "maxRequestedRecords",
      "maxReleasedRecordsPerWindow",
      "maxCallsPerWindow",
      "maxDistinctResourcesPerWindow",
      "maxFailedCallsPerWindow"
    ],
    "invalid_policy"
  );
  if (
    typeof policy.id !== "string" ||
    !policy.id ||
    !Array.isArray(policy.allowedTools) ||
    policy.allowedTools.length === 0 ||
    !policy.allowedTools.every(
      (tool) => typeof tool === "string" && /^[a-z0-9_-]{1,80}$/.test(tool)
    )
  ) {
    throw new Error("invalid_policy");
  }
  for (const field of [
    "maxRequestedRecords",
    "maxReleasedRecordsPerWindow",
    "maxCallsPerWindow",
    "maxDistinctResourcesPerWindow",
    "maxFailedCallsPerWindow"
  ]) {
    requireMetric(policy[field], field);
  }
}

function validateObservation(observation) {
  requireExactKeys(
    observation,
    [
      "schemaVersion",
      "tool",
      "tenantBoundaryValid",
      "requestedRecords",
      "priorReleasedRecordsInWindow",
      "projectedCallsInWindow",
      "projectedDistinctResourcesInWindow",
      "priorFailedCallsInWindow"
    ],
    "invalid_observation"
  );
  if (
    observation.schemaVersion !== "1" ||
    typeof observation.tool !== "string" ||
    !/^[a-z0-9_-]{1,80}$/.test(observation.tool) ||
    typeof observation.tenantBoundaryValid !== "boolean"
  ) {
    throw new Error("invalid_observation");
  }
  for (const field of [
    "requestedRecords",
    "priorReleasedRecordsInWindow",
    "projectedCallsInWindow",
    "projectedDistinctResourcesInWindow",
    "priorFailedCallsInWindow"
  ]) {
    requireMetric(observation[field], field);
  }
}

const policyResult = (decision, policy, reason) => ({
  decision,
  policyId: policy.id,
  reason
});

export function applyDeterministicExfiltrationPolicy(
  observation,
  policy = SYNTHETIC_EXFILTRATION_POLICY
) {
  validatePolicy(policy);
  validateObservation(observation);

  if (!observation.tenantBoundaryValid) {
    return policyResult("deny", policy, "tenant_boundary_invalid");
  }
  if (!policy.allowedTools.includes(observation.tool)) {
    return policyResult("deny", policy, "tool_not_allowed");
  }
  if (observation.requestedRecords > policy.maxRequestedRecords) {
    return policyResult("deny", policy, "request_size_exceeds_policy");
  }
  if (
    observation.priorReleasedRecordsInWindow + observation.requestedRecords >
    policy.maxReleasedRecordsPerWindow
  ) {
    return policyResult("deny", policy, "projected_release_exceeds_policy");
  }
  if (observation.projectedCallsInWindow > policy.maxCallsPerWindow) {
    return policyResult("review", policy, "call_volume_is_unusual");
  }
  if (
    observation.projectedDistinctResourcesInWindow >
    policy.maxDistinctResourcesPerWindow
  ) {
    return policyResult("review", policy, "resource_breadth_is_unusual");
  }
  if (observation.priorFailedCallsInWindow > policy.maxFailedCallsPerWindow) {
    return policyResult("review", policy, "failure_volume_is_unusual");
  }
  return policyResult("allow", policy, "within_customer_policy");
}

function validateChoice(answer, choices) {
  if (
    answer?.type !== "choice" ||
    !choices.includes(answer.choice) ||
    !isProbability(answer.confidence) ||
    !answer.probabilities ||
    typeof answer.probabilities !== "object"
  ) {
    throw new Error("invalid_choice");
  }
  requireExactKeys(answer.probabilities, choices, "invalid_probabilities");
  const total = choices.reduce((sum, choice) => {
    const probability = answer.probabilities[choice];
    if (!isProbability(probability)) throw new Error("invalid_probabilities");
    return sum + probability;
  }, 0);
  const selected = answer.probabilities[answer.choice];
  const highest = Math.max(...choices.map((choice) => answer.probabilities[choice]));
  if (
    Math.abs(total - 1) > 0.01 ||
    Math.abs(answer.confidence - selected) > 0.01 ||
    selected !== highest
  ) {
    throw new Error("invalid_probabilities");
  }
  return { choice: answer.choice, confidence: selected };
}

function normalizeClassification(response) {
  if (
    !response?.answers ||
    typeof response.answers !== "object" ||
    typeof response.model !== "string" ||
    !response.model.trim() ||
    !response.usage ||
    !Number.isInteger(response.usage.input_tokens) ||
    response.usage.input_tokens < 0 ||
    !Number.isInteger(response.usage.output_tokens) ||
    response.usage.output_tokens < 0
  ) {
    throw new Error("invalid_model_response");
  }
  requireExactKeys(
    response.answers,
    ["pattern", "risk", "humanReview"],
    "invalid_model_response"
  );
  const pattern = validateChoice(response.answers.pattern, [
    "expected",
    "unusual",
    "likely_exfiltration"
  ]);
  const risk = validateChoice(response.answers.risk, [
    "low",
    "medium",
    "high",
    "critical"
  ]);
  const humanReview = response.answers.humanReview;
  if (humanReview?.type !== "noul" || !isProbability(humanReview.noul)) {
    throw new Error("invalid_human_review");
  }
  return {
    pattern: pattern.choice,
    risk: risk.choice,
    humanReview: humanReview.noul >= 0.5,
    confidence: Math.min(
      pattern.confidence,
      risk.confidence,
      Math.max(humanReview.noul, 1 - humanReview.noul)
    )
  };
}

function narrowDecision(base, classification, policy) {
  if (
    classification.pattern === "likely_exfiltration" ||
    classification.risk === "high" ||
    classification.risk === "critical"
  ) {
    return policyResult("deny", policy, "model_classification_requires_denial");
  }
  if (
    base.decision === "review" ||
    classification.pattern === "unusual" ||
    classification.risk === "medium" ||
    classification.humanReview ||
    classification.confidence < 0.75
  ) {
    return policyResult("review", policy, "model_classification_requires_review");
  }
  return base;
}

export async function evaluateMcpExfiltration(
  env,
  observation,
  policy = SYNTHETIC_EXFILTRATION_POLICY
) {
  const deterministic = applyDeterministicExfiltrationPolicy(observation, policy);
  if (deterministic.decision === "deny") {
    return {
      policy: deterministic,
      classification: null,
      modelEvaluated: false,
      executed: false
    };
  }

  let modelResponse;
  let classification;
  try {
    modelResponse = await env.AI.run(MODEL, {
      model: "clef",
      state: {
        schemaVersion: observation.schemaVersion,
        tool: observation.tool,
        requestedRecords: observation.requestedRecords,
        priorReleasedRecordsInWindow: observation.priorReleasedRecordsInWindow,
        projectedCallsInWindow: observation.projectedCallsInWindow,
        projectedDistinctResourcesInWindow:
          observation.projectedDistinctResourcesInWindow,
        priorFailedCallsInWindow: observation.priorFailedCallsInWindow,
        customerPolicy: {
          maxRequestedRecords: policy.maxRequestedRecords,
          maxReleasedRecordsPerWindow: policy.maxReleasedRecordsPerWindow,
          maxCallsPerWindow: policy.maxCallsPerWindow,
          maxDistinctResourcesPerWindow: policy.maxDistinctResourcesPerWindow,
          maxFailedCallsPerWindow: policy.maxFailedCallsPerWindow
        }
      },
      questions: QUESTIONS
    });
    classification = normalizeClassification(modelResponse);
  } catch {
    return {
      policy: policyResult("deny", policy, "model_result_unavailable"),
      classification: null,
      modelEvaluated: true,
      executed: false
    };
  }

  return {
    policy: narrowDecision(deterministic, classification, policy),
    classification,
    modelEvaluated: true,
    executed: false,
    usage: {
      input_tokens: modelResponse.usage.input_tokens,
      output_tokens: modelResponse.usage.output_tokens
    }
  };
}
