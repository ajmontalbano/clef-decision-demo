import {
  evaluateMcpExfiltration,
  SYNTHETIC_EXFILTRATION_POLICY
} from "../src/mcp-exfiltration-guard.js";

const EXPECTED_METRICS = [
  "tool",
  "tenantBoundaryValid",
  "requestedRecords",
  "priorReleasedRecordsInWindow",
  "projectedCallsInWindow",
  "projectedDistinctResourcesInWindow",
  "priorFailedCallsInWindow"
].sort();

// Call this before invoking the MCP tool. Build these counters in trusted router
// code; never accept them directly from the MCP client being evaluated.
export async function evaluateMcpToolCallShadow(env, routerMetrics) {
  const actualMetrics =
    routerMetrics && !Array.isArray(routerMetrics) && typeof routerMetrics === "object"
      ? Object.keys(routerMetrics).sort()
      : [];
  if (
    actualMetrics.length !== EXPECTED_METRICS.length ||
    actualMetrics.some((key, index) => key !== EXPECTED_METRICS[index])
  ) {
    throw new Error("invalid_router_metrics");
  }

  const result = await evaluateMcpExfiltration(
    env,
    {
      schemaVersion: "1",
      tool: routerMetrics.tool,
      tenantBoundaryValid: routerMetrics.tenantBoundaryValid,
      requestedRecords: routerMetrics.requestedRecords,
      priorReleasedRecordsInWindow: routerMetrics.priorReleasedRecordsInWindow,
      projectedCallsInWindow: routerMetrics.projectedCallsInWindow,
      projectedDistinctResourcesInWindow:
        routerMetrics.projectedDistinctResourcesInWindow,
      priorFailedCallsInWindow: routerMetrics.priorFailedCallsInWindow
    },
    SYNTHETIC_EXFILTRATION_POLICY
  );

  if (result.policy.decision !== "allow") {
    return {
      recommendedAction: result.policy.decision,
      reason: result.policy.reason,
      shadowOnly: true
    };
  }

  return {
    recommendedAction: "allow",
    reason: result.policy.reason,
    shadowOnly: true
  };
}
