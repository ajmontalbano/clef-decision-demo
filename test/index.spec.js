import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import worker from "../src/index.js";
import { authorizeBookingAction } from "../src/authorization-policy.js";

const teamDomain = "summitstone.cloudflareaccess.com";
const audience = "test-access-audience";
const allowedHost = "admin.example.com";
let signingKey;
let publicJwk;

const encode = (value) =>
  btoa(typeof value === "string" ? value : JSON.stringify(value))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");

const createAccessToken = async (claims = {}, headerClaims = {}) => {
  const header = encode({
    alg: "RS256",
    kid: "test-key",
    typ: "JWT",
    ...headerClaims
  });
  const payload = encode({
    iss: `https://${teamDomain}`,
    aud: audience,
    sub: "synthetic-user",
    exp: Math.floor(Date.now() / 1000) + 300,
    ...claims
  });
  const signed = `${header}.${payload}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    signingKey.privateKey,
    new TextEncoder().encode(signed)
  );
  return `${signed}.${encode(String.fromCharCode(...new Uint8Array(signature)))}`;
};

const bookingAnswers = ({
  actionClass = "read_only",
  actionConfidence = 0.94,
  risk = "low",
  riskConfidence = 0.85,
  stateChanging = 0.05,
  humanReview = 0.1
} = {}) => ({
  model: "clef",
  answers: {
    actionClass: {
      type: "choice",
      choice: actionClass,
      probabilities:
        actionClass === "read_only"
          ? { read_only: 0.94, state_changing: 0.06 }
          : { read_only: 0.06, state_changing: 0.94 },
      confidence: actionConfidence
    },
    risk: {
      type: "choice",
      choice: risk,
      probabilities: {
        low: risk === "low" ? 0.85 : 0.05,
        medium: risk === "medium" ? 0.85 : 0.05,
        high: risk === "high" ? 0.85 : 0.05,
        critical: risk === "critical" ? 0.85 : 0.05
      },
      confidence: riskConfidence
    },
    stateChanging: { type: "noul", noul: stateChanging },
    humanReview: { type: "noul", noul: humanReview }
  },
  usage: { input_tokens: 100, output_tokens: 20 }
});

const ticketAnswers = () => ({
  model: "clef",
  answers: {
    urgent: { type: "noul", noul: 0.97 },
    team: {
      type: "choice",
      choice: "technical",
      probabilities: { billing: 0.01, technical: 0.98, sales: 0.01 },
      confidence: 0.98
    },
    severity: {
      type: "score",
      score: 2.9,
      legend: { 0: "No impact", 1: "Minor", 2: "Major", 3: "Critical" },
      probabilities: { 0: 0, 1: 0.01, 2: 0.08, 3: 0.91 },
      confidence: 0.91
    },
    humanReview: { type: "noul", noul: 0.8 }
  },
  usage: { input_tokens: 90, output_tokens: 20 }
});

const makeEnv = (overrides = {}) => ({
  ALLOWED_HOST: allowedHost,
  BASE_PATH: "/clef-demo",
  ACCESS_TEAM_DOMAIN: teamDomain,
  ACCESS_APPLICATION_AUD: audience,
  CLEF_DEMO_RATE_LIMITER: {
    limit: vi.fn().mockResolvedValue({ success: true })
  },
  AI: {
    run: vi.fn().mockResolvedValue(bookingAnswers())
  },
  ...overrides
});

const makeRequest = async ({
  host = allowedHost,
  path = "/clef-demo/evaluate",
  method = "POST",
  accessToken,
  body = JSON.stringify({ scenario: "booking-agent-lookup-availability" }),
  contentType = "application/json",
  origin
} = {}) =>
  new Request(`https://${host}${path}`, {
    method,
    headers: {
      ...(accessToken === null
        ? {}
        : { "cf-access-jwt-assertion": accessToken || (await createAccessToken()) }),
      ...(contentType === null ? {} : { "content-type": contentType }),
      ...(origin ? { origin } : {})
    },
    ...(method === "GET" || method === "HEAD" ? {} : { body })
  });

beforeAll(async () => {
  signingKey = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["sign", "verify"]
  );
  publicJwk = await crypto.subtle.exportKey("jwk", signingKey.publicKey);
  publicJwk.kid = "test-key";
});

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url === `https://${teamDomain}/cdn-cgi/access/certs`) {
        return Response.json({ keys: [publicJwk] });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    })
  );
});

describe("request boundary", () => {
  it("fails closed when deployment settings are missing", async () => {
    const response = await worker.fetch(
      await makeRequest(),
      makeEnv({ ALLOWED_HOST: "" })
    );
    expect(response.status).toBe(503);
  });

  it("rejects the wrong host and invalid Access identities", async () => {
    const wrongHost = await worker.fetch(
      await makeRequest({ host: "other.example.com" }),
      makeEnv()
    );
    const missing = await worker.fetch(
      await makeRequest({ accessToken: null }),
      makeEnv()
    );
    const wrongAudience = await worker.fetch(
      await makeRequest({ accessToken: await createAccessToken({ aud: "wrong" }) }),
      makeEnv()
    );
    expect(wrongHost.status).toBe(404);
    expect(missing.status).toBe(403);
    expect(wrongAudience.status).toBe(403);
  });

  it("validates every security-critical Access header and claim", async () => {
    const now = Math.floor(Date.now() / 1000);
    const validToken = await createAccessToken({ aud: ["another-audience", audience] });
    const cases = [
      `${validToken.split(".").slice(0, 2).join(".")}.invalid`,
      await createAccessToken({ exp: now - 1 }),
      await createAccessToken({ nbf: now + 60 }),
      await createAccessToken({ iss: "https://wrong.cloudflareaccess.com" }),
      await createAccessToken({}, { alg: "HS256" }),
      await createAccessToken({}, { kid: "unknown-key" }),
      await createAccessToken({ sub: "" })
    ];
    for (const accessToken of cases) {
      const response = await worker.fetch(
        await makeRequest({ accessToken }),
        makeEnv()
      );
      expect(response.status).toBe(403);
    }

    const validResponse = await worker.fetch(
      await makeRequest({ accessToken: validToken }),
      makeEnv()
    );
    expect(validResponse.status).toBe(200);
  });

  it("fails closed when Access signing keys are unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("down", { status: 503 })));
    const response = await worker.fetch(await makeRequest(), makeEnv());
    expect(response.status).toBe(403);
  });

  it("lists only fixed synthetic scenarios", async () => {
    const response = await worker.fetch(
      await makeRequest({ path: "/clef-demo", method: "GET" }),
      makeEnv()
    );
    const payload = await response.json();
    expect(response.status).toBe(200);
    expect(payload.synthetic).toBe(true);
    expect(payload.sideEffects).toBe(false);
    expect(payload.scenarios).toHaveLength(5);
  });

  it("validates method, origin, content type, size, JSON shape, and scenario", async () => {
    const env = makeEnv();
    const wrongMethod = await worker.fetch(
      await makeRequest({ method: "GET" }),
      env
    );
    const wrongOrigin = await worker.fetch(
      await makeRequest({ origin: "https://example.test" }),
      env
    );
    const wrongType = await worker.fetch(
      await makeRequest({ contentType: "text/plain" }),
      env
    );
    const oversized = await worker.fetch(
      await makeRequest({ body: JSON.stringify({ scenario: "x", padding: "x".repeat(1100) }) }),
      env
    );
    const array = await worker.fetch(await makeRequest({ body: "[]" }), env);
    const unknown = await worker.fetch(
      await makeRequest({ body: JSON.stringify({ scenario: "unknown" }) }),
      env
    );
    expect(wrongMethod.status).toBe(405);
    expect(wrongOrigin.status).toBe(403);
    expect(wrongType.status).toBe(415);
    expect(oversized.status).toBe(413);
    expect(array.status).toBe(400);
    expect(unknown.status).toBe(400);
  });

  it("fails closed when rate limiting is exhausted or unavailable", async () => {
    const exhausted = await worker.fetch(
      await makeRequest(),
      makeEnv({
        CLEF_DEMO_RATE_LIMITER: {
          limit: vi.fn().mockResolvedValue({ success: false })
        }
      })
    );
    const unavailable = await worker.fetch(
      await makeRequest(),
      makeEnv({
        CLEF_DEMO_RATE_LIMITER: { limit: vi.fn().mockRejectedValue(new Error("down")) }
      })
    );
    expect(exhausted.status).toBe(429);
    expect(exhausted.headers.get("retry-after")).toBe("60");
    expect(unavailable.status).toBe(503);
  });
});

describe("Clef and deterministic policy", () => {
  it("returns a ticket routing recommendation without executing an action", async () => {
    const ai = { run: vi.fn().mockResolvedValue(ticketAnswers()) };
    const response = await worker.fetch(
      await makeRequest({
        body: JSON.stringify({ scenario: "ticket-checkout-outage" })
      }),
      makeEnv({ AI: ai })
    );
    const payload = await response.json();
    expect(response.status).toBe(200);
    expect(payload.classification).toMatchObject({
      team: "technical",
      humanReview: true
    });
    expect(payload.authorization).toBeUndefined();
    expect(payload.executed).toBe(false);
    expect(ai.run).toHaveBeenCalledWith(
      "@cf/cloudflare/clef",
      expect.objectContaining({ model: "clef" })
    );
  });

  it("allows a high-confidence read-only lookup", async () => {
    const response = await worker.fetch(await makeRequest(), makeEnv());
    const payload = await response.json();
    expect(response.status).toBe(200);
    expect(payload.authorization).toMatchObject({
      decision: "allow",
      reason: "read_only_action_allowed"
    });
    expect(payload.executed).toBe(false);
  });

  it("requires review for a hold and denies booking confirmation", async () => {
    const reviewResponse = await worker.fetch(
      await makeRequest({
        body: JSON.stringify({ scenario: "booking-agent-create-hold" })
      }),
      makeEnv({ AI: { run: vi.fn().mockResolvedValue(bookingAnswers({ actionClass: "state_changing", risk: "medium", stateChanging: 0.95, humanReview: 0.9 })) } })
    );
    const denyResponse = await worker.fetch(
      await makeRequest({
        body: JSON.stringify({ scenario: "booking-agent-confirm-booking" })
      }),
      makeEnv({ AI: { run: vi.fn().mockResolvedValue(bookingAnswers({ actionClass: "state_changing", risk: "high", stateChanging: 0.98, humanReview: 0.99 })) } })
    );
    expect((await reviewResponse.json()).authorization.decision).toBe("review");
    expect((await denyResponse.json()).authorization.decision).toBe("deny");
  });

  it("fails closed on malformed model output or model failure", async () => {
    const malformed = bookingAnswers();
    malformed.answers.risk.probabilities.low = Number.NaN;
    const malformedResponse = await worker.fetch(
      await makeRequest(),
      makeEnv({ AI: { run: vi.fn().mockResolvedValue(malformed) } })
    );
    const failedResponse = await worker.fetch(
      await makeRequest(),
      makeEnv({ AI: { run: vi.fn().mockRejectedValue(new Error("secret model detail")) } })
    );
    for (const response of [malformedResponse, failedResponse]) {
      const payload = await response.json();
      expect(response.status).toBe(502);
      expect(payload.authorization.decision).toBe("deny");
      expect(payload.executed).toBe(false);
      expect(JSON.stringify(payload)).not.toContain("secret model detail");
    }
  });

  it("rejects a choice that conflicts with its probability distribution", async () => {
    const contradictory = bookingAnswers();
    contradictory.answers.risk.choice = "low";
    contradictory.answers.risk.probabilities = {
      low: 0.01,
      medium: 0.01,
      high: 0.97,
      critical: 0.01
    };
    const response = await worker.fetch(
      await makeRequest(),
      makeEnv({ AI: { run: vi.fn().mockResolvedValue(contradictory) } })
    );
    const payload = await response.json();
    expect(response.status).toBe(502);
    expect(payload.authorization.decision).toBe("deny");
  });

  it("rejects confidence and score values that conflict with probabilities", async () => {
    const choiceConflict = bookingAnswers({ riskConfidence: 0.1 });
    const scoreConflict = ticketAnswers();
    scoreConflict.answers.severity.score = 1;

    for (const [body, modelResponse] of [
      [JSON.stringify({ scenario: "booking-agent-lookup-availability" }), choiceConflict],
      [JSON.stringify({ scenario: "ticket-checkout-outage" }), scoreConflict]
    ]) {
      const response = await worker.fetch(
        await makeRequest({ body }),
        makeEnv({ AI: { run: vi.fn().mockResolvedValue(modelResponse) } })
      );
      expect(response.status).toBe(502);
    }
  });

  it("never widens policy when the model reports risk or low confidence", () => {
    const base = {
      actorRole: "booking_agent",
      proposedAction: "lookup_availability",
      resourceScope: "synthetic_booking"
    };
    expect(
      authorizeBookingAction({
        ...base,
        classification: {
          actionClass: "read_only",
          risk: "high",
          stateChanging: false,
          humanReview: false,
          confidence: 0.95
        }
      }).decision
    ).toBe("review");
    expect(
      authorizeBookingAction({
        ...base,
        classification: {
          actionClass: "read_only",
          risk: "low",
          stateChanging: false,
          humanReview: false,
          confidence: 0.5
        }
      }).decision
    ).toBe("review");
    expect(
      authorizeBookingAction({
        ...base,
        classification: {
          actionClass: "read_only",
          risk: "medium",
          stateChanging: false,
          humanReview: false,
          confidence: 0.95
        }
      }).decision
    ).toBe("review");
  });

  it("covers every deterministic policy branch and threshold", () => {
    const safeClassification = {
      actionClass: "read_only",
      risk: "low",
      stateChanging: false,
      humanReview: false,
      confidence: 0.75
    };
    const evaluate = (overrides = {}) =>
      authorizeBookingAction({
        actorRole: "booking_agent",
        proposedAction: "lookup_availability",
        resourceScope: "synthetic_booking",
        classification: safeClassification,
        ...overrides
      }).decision;

    expect(evaluate()).toBe("allow");
    expect(evaluate({ proposedAction: "quote_itinerary" })).toBe("allow");
    expect(evaluate({ actorRole: "visitor" })).toBe("deny");
    expect(evaluate({ resourceScope: "production_booking" })).toBe("deny");
    expect(evaluate({ proposedAction: "create_temporary_hold" })).toBe("review");
    expect(evaluate({ proposedAction: "confirm_booking" })).toBe("deny");
    expect(evaluate({ proposedAction: "unknown" })).toBe("deny");
    expect(evaluate({ classification: null })).toBe("review");
  });
});
