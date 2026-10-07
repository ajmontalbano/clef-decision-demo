# From Reference Demo to Real Pilot

The committed Worker is a deployable synthetic reference, not a production
ticketing or booking integration. Its fixed scenarios prove the security and
decision boundaries before a team introduces production data, credentials, or
side effects.

## Recommended Starting Use Case

Choose one read-only workflow with labeled human outcomes, such as:

- Classify ticket urgency, team, severity, and need for human review.
- Classify a proposed booking lookup without reserving or changing inventory.

Start with a small historical or staging sample. Do not begin with booking
confirmation, cancellation, refunds, discounts, or other state-changing actions.

## Target Flow

```text
Access-authenticated reviewer
  -> Clef Worker
  -> narrow ticketing or booking adapter
  -> allowlisted normalized record
  -> Clef classification
  -> strict output validation
  -> deterministic application policy
  -> shadow result and human comparison
```

The adapter may be another Worker reached through a service binding or a small
function inside this Worker. It should retrieve a record by opaque ID using a
server-side credential. Do not expose the upstream credential to the browser or
accept arbitrary customer text directly from callers.

## Iteration Stages

### 1. Deploy the Synthetic Baseline

Configure Cloudflare Access, the allowed hostname, route, and rate limiter.
Run the five committed scenarios and confirm the allow, review, deny, failure,
logging, and rollback behavior before changing the input boundary.

### 2. Add a Read-Only Adapter

Replace direct lookup in the fixed `SCENARIOS` object with a resolver that:

1. Accepts only an opaque record ID and an allowlisted workflow name.
2. Retrieves the record from a staging or read-only API.
3. Selects only fields approved for Workers AI processing.
4. Normalizes those fields into a versioned state object.
5. Rejects missing, oversized, unexpected, or disallowed data.

Store upstream API credentials with Wrangler secrets or a secrets binding. Do
not commit credentials, account identifiers, customer records, or Access values.

### 3. Run in Shadow Mode

Keep `executed: false`. Compare the model recommendation with the final human
decision without writing back to the ticketing or booking system.

Measure:

- Agreement by class, team, severity, and review decision.
- False-allow and false-deny rates for policy decisions.
- Confidence calibration and human-review volume.
- End-to-end latency, Neuron usage, and cost per evaluated record.
- Missing-data, malformed-output, adapter, and model failure rates.

Define acceptance thresholds before expanding the sample or workflow scope.

### 4. Add Human-Reviewed Proposals

After shadow-mode thresholds are met, the Worker may create a proposed action
for a human to approve. Keep the actual write in a separate execution service
with its own authorization, idempotency, audit trail, and rollback controls.
Clef may narrow or route a request, but it must not grant permission.

### 5. Consider Limited Execution Separately

Do not add state-changing execution merely by changing `executed` to `true`.
Treat execution as a separate design review. Validate ownership, tenant and
object scope, replay protection, concurrency, financial or inventory impact,
approval requirements, and recovery behavior for each action.

## Code Boundaries to Preserve

- Keep Access JWT verification and hostname/path restrictions fail closed.
- Keep model-output validation separate from deterministic authorization.
- Keep question labels and normalized input schemas allowlisted and versioned.
- Keep rate limiting as abuse protection, not authorization or quota accounting.
- Keep logs free of identity, tokens, raw records, and model response text.
- Keep unknown workflows, fields, output labels, and policy inputs denied or
  routed to human review.

## Decisions Needed Before Real Data

- Which ticket queue or read-only booking lookup is the first workflow?
- Which exact fields may leave the source system for Workers AI processing?
- Who owns the normalized schema, labels, and acceptance thresholds?
- Where will shadow outcomes be stored and reviewed?
- Which team owns the adapter credential, rotation, audit, and rollback?
