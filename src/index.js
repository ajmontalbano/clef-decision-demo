import {
  authorizeBookingAction,
  BOOKING_POLICY_ID
} from "./authorization-policy.js";

const DEFAULT_BASE_PATH = "/clef-demo";
const MODEL = "@cf/cloudflare/clef";
const MAX_BODY_BYTES = 1024;
const PROBABILITY_TOLERANCE = 0.01;

const SCENARIOS = Object.freeze({
  "ticket-checkout-outage": {
    kind: "ticket",
    state: {
      ticketId: "SYN-TKT-1042",
      subject: "Checkout unavailable for all Summit & Stone customers",
      description: "Every checkout attempt has returned an error for 45 minutes.",
      affectedUsers: "all storefront customers",
      environment: "synthetic lab"
    }
  },
  "ticket-plan-question": {
    kind: "ticket",
    state: {
      ticketId: "SYN-TKT-1043",
      subject: "Question about expedition membership tiers",
      description: "A fictional customer wants a comparison before renewing next month.",
      affectedUsers: "one fictional customer",
      environment: "synthetic lab"
    }
  },
  "booking-agent-lookup-availability": {
    kind: "booking",
    actorRole: "booking_agent",
    proposedAction: "lookup_availability",
    resourceScope: "synthetic_booking",
    state: {
      requestId: "SYN-REQ-2041",
      request: "Check availability for a fictional guided hike without reserving inventory.",
      proposedAction: "lookup_availability",
      sideEffects: "none",
      environment: "synthetic lab"
    }
  },
  "booking-agent-create-hold": {
    kind: "booking",
    actorRole: "booking_agent",
    proposedAction: "create_temporary_hold",
    resourceScope: "synthetic_booking",
    state: {
      requestId: "SYN-REQ-2042",
      request: "Create a short-lived hold for a fictional guided hike.",
      proposedAction: "create_temporary_hold",
      sideEffects: "temporarily changes synthetic inventory",
      environment: "synthetic lab"
    }
  },
  "booking-agent-confirm-booking": {
    kind: "booking",
    actorRole: "booking_agent",
    proposedAction: "confirm_booking",
    resourceScope: "synthetic_booking",
    state: {
      requestId: "SYN-REQ-2043",
      request: "Confirm a fictional booking and commit inventory.",
      proposedAction: "confirm_booking",
      sideEffects: "commits synthetic inventory",
      environment: "synthetic lab"
    }
  }
});

const TICKET_QUESTIONS = Object.freeze({
  urgent: {
    type: "noul",
    instructions: "Is this fictional support ticket urgent?"
  },
  team: {
    type: "choice",
    instructions: "Which fictional team should handle this ticket?",
    criteria: {
      billing: "Payments, invoices, and refunds",
      technical: "Outages, errors, and configuration",
      sales: "Plans, membership tiers, and upgrades"
    }
  },
  severity: {
    type: "score",
    instructions: "How severe is the fictional customer impact?",
    criteria: ["No impact", "Minor", "Major", "Critical"]
  },
  humanReview: {
    type: "noul",
    instructions: "Should a human review this routing recommendation?"
  }
});

const BOOKING_QUESTIONS = Object.freeze({
  actionClass: {
    type: "choice",
    instructions: "Does the proposed action only read data or change state?",
    criteria: {
      read_only: "Reads synthetic data and creates no reservation or inventory change",
      state_changing: "Creates, changes, confirms, or cancels synthetic state"
    }
  },
  risk: {
    type: "choice",
    instructions: "What is the risk of allowing this proposed action?",
    criteria: {
      low: "No persistent effect and easily reversible",
      medium: "Limited or temporary effect",
      high: "Commits inventory, identity, policy, or financial state",
      critical: "Irreversible or broad financial, identity, or safety impact"
    }
  },
  stateChanging: {
    type: "noul",
    instructions: "Would this proposed action change application state?"
  },
  humanReview: {
    type: "noul",
    instructions: "Should a human explicitly approve this proposed action?"
  }
});

const json = (body, status = 200, headers = {}) =>
  Response.json(body, {
    status,
    headers: {
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'",
      ...headers
    }
  });

function runtimeConfig(env) {
  const host = String(env.ALLOWED_HOST || "").trim().toLowerCase();
  const basePath = String(env.BASE_PATH || DEFAULT_BASE_PATH).trim();
  if (
    !host ||
    host.includes("://") ||
    host.includes("/") ||
    !basePath.startsWith("/") ||
    (basePath.length > 1 && basePath.endsWith("/"))
  ) {
    throw new Error("runtime_not_configured");
  }
  return { host, basePath };
}

const decodeBase64Url = (value) => {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
};

const parseJwtPart = (value) =>
  JSON.parse(new TextDecoder().decode(decodeBase64Url(value)));

async function verifyAccessIdentity(request, env) {
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_APPLICATION_AUD) {
    throw new Error("access_not_configured");
  }
  const token = request.headers.get("cf-access-jwt-assertion") || "";
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("access_token_missing");

  const header = parseJwtPart(parts[0]);
  const payload = parseJwtPart(parts[1]);
  if (header.alg !== "RS256" || !header.kid) throw new Error("access_header_invalid");

  const teamDomain = String(env.ACCESS_TEAM_DOMAIN)
    .replace(/^https?:\/\//, "")
    .replace(/\/$/, "");
  const certificatesResponse = await fetch(
    `https://${teamDomain}/cdn-cgi/access/certs`,
    { cf: { cacheEverything: true, cacheTtl: 300 } }
  );
  if (!certificatesResponse.ok) throw new Error("access_keys_unavailable");

  const certificates = await certificatesResponse.json();
  const jwk = certificates.keys?.find((key) => key.kid === header.kid);
  if (!jwk) throw new Error("access_key_not_found");

  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const signatureIsValid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    decodeBase64Url(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
  );
  const now = Math.floor(Date.now() / 1000);
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (
    !signatureIsValid ||
    payload.iss !== `https://${teamDomain}` ||
    !audiences.includes(env.ACCESS_APPLICATION_AUD) ||
    !payload.exp ||
    payload.exp <= now ||
    (payload.nbf && payload.nbf > now) ||
    !payload.sub
  ) {
    throw new Error("access_claims_invalid");
  }
  return payload.sub;
}

async function hashIdentity(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

async function readBoundedBody(request) {
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > MAX_BODY_BYTES) throw new Error("body_too_large");
  if (!request.body) return "";

  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      throw new Error("body_too_large");
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

const isProbability = (value) =>
  Number.isFinite(value) && value >= 0 && value <= 1;

function validateNoul(answer) {
  if (answer?.type !== "noul" || !isProbability(answer.noul)) {
    throw new Error("invalid_noul_answer");
  }
  return answer.noul;
}

function validateChoice(answer, allowedChoices) {
  if (
    answer?.type !== "choice" ||
    !allowedChoices.includes(answer.choice) ||
    !isProbability(answer.confidence) ||
    !answer.probabilities ||
    typeof answer.probabilities !== "object"
  ) {
    throw new Error("invalid_choice_answer");
  }
  const keys = Object.keys(answer.probabilities);
  if (
    keys.length !== allowedChoices.length ||
    !allowedChoices.every((choice) =>
      isProbability(answer.probabilities[choice])
    ) ||
    Math.abs(
      allowedChoices.reduce(
        (sum, choice) => sum + answer.probabilities[choice],
        0
      ) - 1
    ) > PROBABILITY_TOLERANCE
  ) {
    throw new Error("invalid_choice_probabilities");
  }
  const selectedProbability = answer.probabilities[answer.choice];
  const highestProbability = Math.max(
    ...allowedChoices.map((choice) => answer.probabilities[choice])
  );
  if (
    selectedProbability !== highestProbability ||
    Math.abs(answer.confidence - selectedProbability) > PROBABILITY_TOLERANCE
  ) {
    throw new Error("choice_probability_conflict");
  }
  return { choice: answer.choice, confidence: selectedProbability };
}

function validateScore(answer, levelCount) {
  const levels = Array.from({ length: levelCount }, (_, index) => String(index));
  if (
    answer?.type !== "score" ||
    !Number.isFinite(answer.score) ||
    answer.score < 0 ||
    answer.score > levelCount - 1 ||
    !isProbability(answer.confidence) ||
    !answer.probabilities ||
    typeof answer.probabilities !== "object" ||
    Object.keys(answer.probabilities).length !== levels.length ||
    !levels.every((level) => isProbability(answer.probabilities[level])) ||
    Math.abs(
      levels.reduce((sum, level) => sum + answer.probabilities[level], 0) - 1
    ) > PROBABILITY_TOLERANCE
  ) {
    throw new Error("invalid_score_answer");
  }
  const highestProbability = Math.max(
    ...levels.map((level) => answer.probabilities[level])
  );
  const weightedScore = levels.reduce(
    (sum, level) => sum + Number(level) * answer.probabilities[level],
    0
  );
  if (
    Math.abs(answer.confidence - highestProbability) > PROBABILITY_TOLERANCE ||
    Math.abs(answer.score - weightedScore) > PROBABILITY_TOLERANCE
  ) {
    throw new Error("score_probability_conflict");
  }
  return {
    score: answer.score,
    confidence: highestProbability
  };
}

function requireExactKeys(value, expectedKeys, errorCode) {
  const actualKeys = Object.keys(value).sort();
  const sortedExpected = [...expectedKeys].sort();
  if (
    actualKeys.length !== sortedExpected.length ||
    actualKeys.some((key, index) => key !== sortedExpected[index])
  ) {
    throw new Error(errorCode);
  }
}

function normalizeClassification(kind, response) {
  if (
    !response?.answers ||
    typeof response.answers !== "object" ||
    !response.usage ||
    !Number.isInteger(response.usage.input_tokens) ||
    response.usage.input_tokens < 0 ||
    !Number.isInteger(response.usage.output_tokens) ||
    response.usage.output_tokens < 0 ||
    typeof response.model !== "string" ||
    !response.model.trim()
  ) {
    throw new Error("answers_missing");
  }
  if (kind === "ticket") {
    requireExactKeys(
      response.answers,
      ["urgent", "team", "severity", "humanReview"],
      "ticket_answers_invalid"
    );
    const urgent = validateNoul(response.answers.urgent);
    const team = validateChoice(response.answers.team, [
      "billing",
      "technical",
      "sales"
    ]);
    const severity = validateScore(response.answers.severity, 4);
    const humanReview = validateNoul(response.answers.humanReview);
    return {
      urgentProbability: urgent,
      team: team.choice,
      severityScore: severity.score,
      humanReview: humanReview >= 0.5,
      confidence: Math.min(
        Math.max(urgent, 1 - urgent),
        team.confidence,
        severity.confidence,
        Math.max(humanReview, 1 - humanReview)
      )
    };
  }

  requireExactKeys(
    response.answers,
    ["actionClass", "risk", "stateChanging", "humanReview"],
    "booking_answers_invalid"
  );
  const actionClass = validateChoice(response.answers.actionClass, [
    "read_only",
    "state_changing"
  ]);
  const risk = validateChoice(response.answers.risk, [
    "low",
    "medium",
    "high",
    "critical"
  ]);
  const stateChanging = validateNoul(response.answers.stateChanging);
  const humanReview = validateNoul(response.answers.humanReview);
  return {
    actionClass: actionClass.choice,
    risk: risk.choice,
    stateChanging: stateChanging >= 0.5,
    humanReview: humanReview >= 0.5,
    confidence: Math.min(
      actionClass.confidence,
      risk.confidence,
      Math.max(stateChanging, 1 - stateChanging),
      Math.max(humanReview, 1 - humanReview)
    )
  };
}

function modelFailure(scenarioId, scenario, requestId) {
  return json(
    {
      ok: false,
      synthetic: true,
      scenario: scenarioId,
      requestId,
      ...(scenario.kind === "booking"
        ? {
            authorization: {
              decision: "deny",
              policyId: BOOKING_POLICY_ID,
              reason: "model_result_unavailable"
            }
          }
        : {}),
      executed: false,
      error: "Decision model result was unavailable"
    },
    502
  );
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    let config;
    try {
      config = runtimeConfig(env);
    } catch {
      return json({ error: "Service unavailable" }, 503);
    }
    if (
      url.hostname.toLowerCase() !== config.host ||
      !url.pathname.startsWith(config.basePath)
    ) {
      return json({ error: "Not found" }, 404);
    }

    let subject;
    try {
      subject = await verifyAccessIdentity(request, env);
    } catch {
      return json({ error: "Forbidden" }, 403);
    }

    if (request.method === "GET" && url.pathname === config.basePath) {
      return json({
        name: "Summit & Stone Clef decision demo",
        synthetic: true,
        model: MODEL,
        scenarios: Object.entries(SCENARIOS).map(([id, scenario]) => ({
          id,
          kind: scenario.kind
        })),
        endpoint: `${config.basePath}/evaluate`,
        sideEffects: false
      });
    }
    if (url.pathname !== `${config.basePath}/evaluate`) {
      return json({ error: "Not found" }, 404);
    }
    if (request.method !== "POST") {
      return json({ error: "Method not allowed" }, 405, { allow: "POST" });
    }
    if (request.headers.get("content-type")?.split(";", 1)[0] !== "application/json") {
      return json({ error: "Content-Type must be application/json" }, 415);
    }
    const origin = request.headers.get("origin");
    if (origin && origin !== `https://${config.host}`) {
      return json({ error: "Forbidden" }, 403);
    }

    let payload;
    try {
      payload = JSON.parse(await readBoundedBody(request));
    } catch (error) {
      return json(
        { error: error?.message === "body_too_large" ? "Request body too large" : "Invalid JSON" },
        error?.message === "body_too_large" ? 413 : 400
      );
    }
    if (!payload || Array.isArray(payload) || typeof payload !== "object") {
      return json({ error: "JSON body must be an object" }, 400);
    }
    const scenarioId = payload.scenario;
    const scenario = SCENARIOS[scenarioId];
    if (typeof scenarioId !== "string" || !scenario) {
      return json({ error: "Unknown synthetic scenario" }, 400);
    }

    try {
      const rateLimit = await env.CLEF_DEMO_RATE_LIMITER.limit({
        key: await hashIdentity(subject)
      });
      if (!rateLimit.success) {
        return json({ error: "Rate limit exceeded" }, 429, {
          "retry-after": "60"
        });
      }
    } catch {
      return json({ error: "Rate limiter unavailable" }, 503);
    }

    const requestId = crypto.randomUUID();
    const startedAt = Date.now();
    let modelResponse;
    let classification;
    try {
      modelResponse = await env.AI.run(MODEL, {
        model: "clef",
        state: scenario.state,
        questions:
          scenario.kind === "ticket" ? TICKET_QUESTIONS : BOOKING_QUESTIONS
      });
      classification = normalizeClassification(scenario.kind, modelResponse);
    } catch (error) {
      console.error(
        JSON.stringify({
          event: "clef_decision_failed",
          requestId,
          scenario: scenarioId,
          errorType: error instanceof Error ? error.name : "UnknownError",
          durationMs: Date.now() - startedAt
        })
      );
      return modelFailure(scenarioId, scenario, requestId);
    }

    const authorization =
      scenario.kind === "booking"
        ? authorizeBookingAction({
            actorRole: scenario.actorRole,
            proposedAction: scenario.proposedAction,
            resourceScope: scenario.resourceScope,
            classification
          })
        : undefined;

    console.log(
      JSON.stringify({
        event: "clef_decision_completed",
        requestId,
        scenario: scenarioId,
        kind: scenario.kind,
        confidence: Number(classification.confidence.toFixed(4)),
        decision: authorization?.decision || "route_only",
        reason: authorization?.reason || "classification_only",
        policyId: authorization?.policyId,
        model: MODEL,
        durationMs: Date.now() - startedAt
      })
    );

    return json({
      ok: true,
      synthetic: true,
      scenario: scenarioId,
      requestId,
      model: MODEL,
      classification,
      ...(authorization ? { authorization } : {}),
      executed: false,
      usage: {
        input_tokens: modelResponse.usage.input_tokens,
        output_tokens: modelResponse.usage.output_tokens
      }
    });
  }
};
