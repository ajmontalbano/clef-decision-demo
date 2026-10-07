# Clef Decision Demo Worker

An Access-gated, synthetic-only Cloudflare Worker that demonstrates two uses of
Cloudflare's Clef decision model:

- Classify a fixed fictional support ticket for urgency, team, severity, and
  human review.
- Classify a proposed fictional booking-agent action, then pass the result to a
  deterministic authorization policy.

The model never authorizes or executes an action. The Worker has no booking,
database, payment, webhook, or messaging binding, and every response reports
`executed: false`.

## Decision boundary

`POST /clef-demo/evaluate` accepts one field:

```json
{
  "scenario": "booking-agent-lookup-availability"
}
```

Only the scenario IDs returned by `GET /clef-demo` are accepted. The Worker
looks up fictional state internally, so callers cannot submit real ticket text,
booking details, or customer data to the model through this endpoint.

Clef returns typed probabilities. `src/index.js` validates their types, ranges,
allowed labels, selected choices, and probability sums.
`src/authorization-policy.js` then applies this fail-closed policy:

| Proposed action | Result |
| --- | --- |
| Look up synthetic availability | Allow only when Clef also reports a confident, low-risk, read-only action |
| Produce a synthetic quote | Same read-only policy |
| Create a temporary synthetic hold | Human review |
| Confirm/change/cancel/refund/discount | Deny |
| Unknown action, scope, role, malformed output, or model failure | Deny or human review; never allow |

## Security controls

- A deployment-specific allowed hostname and base path.
- Cloudflare Access JWT signature, issuer, audience, expiry, and subject checks.
- `workers_dev: false`; the committed template has no public route.
- Same-origin browser POSTs, JSON-only input, a 1 KiB body cap, and six
  evaluations per identity per minute and Cloudflare location.
- Hashed rate-limit keys and privacy-minimized structured logs.
- Fixed synthetic scenarios, with no arbitrary text input or side-effecting
  bindings.
- Missing deployment settings, Access errors, rate-limiter errors, malformed
  model output, and inference failures all fail closed.

The Workers Rate Limiting API is intentionally permissive and eventually
consistent. It is an abuse control, not an accounting or authorization system.

## Validate locally

From the repository root:

```bash
npm install
npm test
npm run check
```

The dry run validates packaging without deploying or invoking Workers AI.

## Configure a deployment

The committed `wrangler.jsonc` is a safe template: it omits `account_id`, public
routes, and Access values. The Worker returns `503` if its allowed hostname is
missing, and `workers_dev` is disabled.

Before deploying:

1. Choose a hostname in an active Cloudflare zone. Use a path route when an
   existing origin owns the hostname, or a Custom Domain when this Worker is the
   origin for the entire hostname.
2. Create a Cloudflare Access self-hosted application that covers the exact
   hostname and `/clef-demo*` path. Add a narrow Allow policy for the demo users.
3. Copy `wrangler.jsonc` to a local deployment config and add the values below.
   Do not commit account-specific values to a reusable package.

```jsonc
{
  "account_id": "YOUR_ACCOUNT_ID",
  "vars": {
    "ALLOWED_HOST": "admin.example.com",
    "BASE_PATH": "/clef-demo",
    "ACCESS_TEAM_DOMAIN": "your-team.cloudflareaccess.com",
    "ACCESS_APPLICATION_AUD": "YOUR_ACCESS_APPLICATION_AUD"
  },
  "ratelimits": [
    {
      "name": "CLEF_DEMO_RATE_LIMITER",
      "namespace_id": "1001",
      "simple": { "limit": 6, "period": 60 }
    }
  ],
  "routes": [
    {
      "pattern": "admin.example.com/clef-demo*",
      "zone_name": "example.com"
    }
  ]
}
```

The rate-limit namespace must be a positive integer unique within the target
account. If you use a dedicated hostname instead of an existing origin, replace
the path route with a Custom Domain:

```jsonc
{
  "routes": [
    { "pattern": "clef-demo.example.com", "custom_domain": true }
  ]
}
```

With the deployment config saved as `wrangler.deploy.jsonc`:

```bash
npx wrangler deploy --config wrangler.deploy.jsonc
```

Add that local filename to `.git/info/exclude` or another local-only ignore
rule. Do not put Access credentials or API tokens in Wrangler configuration;
this Worker does not require either.

Workers AI includes 10,000 Neurons per day at no charge. Usage above that daily
allocation requires Workers Paid and is billed at the current Workers AI rate.
Validate the current model-specific rate before production use. The default
model is `@cf/cloudflare/clef`; `@cf/cloudflare/clef-flash` is a lower-cost,
lower-latency alternative that should be evaluated against the same tests before
changing the model.

## Deployment validation

1. Confirm the endpoint is unavailable on `workers.dev` and preview URLs.
2. Confirm an unauthenticated request and a user outside the Access policy are
   denied.
3. Confirm `GET /clef-demo` lists only the five synthetic scenarios.
4. Submit the read-only lookup scenario and verify `authorization.decision` is
   `allow` while `executed` remains `false`.
5. Submit the hold and confirmation scenarios and verify `review` and `deny`.
6. Exceed six evaluations in one minute and verify a `429` response.
7. Review Workers logs and confirm they contain no identity, JWT, request body,
   customer data, or model response text.

## Rollback

Use `wrangler rollback --config wrangler.deploy.jsonc`
to restore a previous version, or remove the dedicated route or Custom Domain.
Because the package and route are isolated, rollback does not affect any other
deployed Worker.
