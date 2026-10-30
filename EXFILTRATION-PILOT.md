# MCP Data Exfiltration Pilot

This sample extends the Clef reference package with a shadow-only decision
point for MCP data exfiltration. It does not proxy MCP traffic, store activity,
invoke an MCP tool, or return customer records.

## Control Split

Use Cloudflare's existing controls for the boundaries they already cover:

- MCP server portals: Access identity, per-server policies, curated tool and
  prompt allowlists, tool-call visibility, and service-token authentication.
- Gateway routing: richer HTTP logs and standard DLP scanning of tool-call
  requests and responses.
- Access, WAF, Managed Rules, and rate limiting: inbound protection when the
  MCP server itself is Internet-facing.
- The application router: tenant authorization, customer-specific baselines,
  rolling behavior, and the final allow, review, throttle, or deny decision.

Standard DLP is useful when the data matches a known sensitive-data profile.
It does not decide whether otherwise valid data is unusual for one customer.
AI prompt DLP profiles do not apply to MCP portal traffic.

## Sample Flow

```text
authenticated MCP actor
  -> trusted router resolves customer and tool authorization
  -> router reads rolling counters for that actor and customer
  -> deterministic tenant, tool, and volume policy
  -> Clef evaluates normalized metrics only when hard boundaries pass
  -> shadow decision is logged and compared with the real outcome
  -> MCP tool remains unchanged during the pilot
```

`src/mcp-exfiltration-guard.js` contains the policy and Clef call.
`examples/mcp-exfiltration-callout.js` shows where a trusted router calls it.

The example accepts only:

- Tool identifier.
- Whether the router already validated the tenant boundary.
- Requested record count.
- Records released before the proposed call in the current window.
- Projected calls and distinct resources, including the proposed call.
- Failed calls observed before the proposed call.

It rejects extra fields so raw prompts, query text, tool results, customer
records, tokens, and identity values cannot accidentally reach the model.

## Deterministic Boundaries

The committed policy is synthetic. Replace it with a versioned policy loaded
server-side for each customer. Never accept limits or counters from the MCP
client being evaluated.

The sample denies before calling Clef when:

- The tenant boundary is invalid.
- The tool is not allowlisted.
- One request exceeds the customer limit.
- The projected release exceeds the customer's rolling-window limit.

High call, resource, or failure counts require review. Clef can narrow an
allow decision to review or deny, but it cannot override a deterministic deny.
Malformed output and model failures fail closed.

## Router Callout

```js
import { evaluateMcpToolCallShadow } from "./examples/mcp-exfiltration-callout.js";

const guard = await evaluateMcpToolCallShadow(env, {
  tool: "search_events",
  tenantBoundaryValid: true,
  requestedRecords: 100,
  priorReleasedRecordsInWindow: 850,
  projectedCallsInWindow: 12,
  projectedDistinctResourcesInWindow: 4,
  priorFailedCallsInWindow: 1
});

// Shadow mode: record the recommendation without changing the real tool call.
console.log(JSON.stringify({
  event: "mcp_exfiltration_shadow_decision",
  action: guard.recommendedAction,
  reason: guard.reason
}));
```

Call the module through a service binding or import it into the router. Do not
expose an unauthenticated public endpoint that accepts caller-supplied metrics.
The shadow wrapper intentionally returns no `allowed` boolean so a caller cannot
mistake the recommendation for an enforcement result.

## Rolling State

The sample deliberately does not prescribe a customer storage design. Its
counter input is advisory and is not sufficient for concurrent enforcement.
The router must first define the correlation key and window:

- Key by authenticated customer plus actor or service identity, not IP alone.
- Count data units meaningful to the tool, such as records, resources, bytes,
  or export jobs.
- Keep tenant authorization and absolute export caps deterministic.
- Require the MCP adapter to enforce the requested limit. If an upstream tool
  can return more than requested, validate its actual record or byte count in a
  second deterministic check before releasing the response to the MCP client.
- Use a Durable Object per correlation key if the limit must be strict across
  Cloudflare locations. Atomically check and reserve the proposed release before
  invoking the tool so concurrent requests cannot reuse the same counter
  snapshot. The Workers Rate Limiting API is approximate and is not sufficient
  for strict exfiltration accounting.

## Pilot Sequence

1. Define expected tools and data units for one customer and read-only tool.
2. Compute counters in the trusted router and run the guard in shadow mode.
3. Compare recommendations with reviewed activity and tune false positives.
4. Enforce tenant and absolute volume boundaries first.
5. Add review or throttling for behavioral signals only after thresholds are
   validated.
6. Treat automatic blocking based on model classification as a separate change
   with rollback and incident ownership.
