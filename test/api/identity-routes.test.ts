import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import type { FastifyInstance } from "fastify";
import type { Response as InjectResponse } from "light-my-request";

import { buildApp } from "../../src/api/app.js";
import { buildTestServices } from "../operational/test-doubles.js";

describe("operational identity HTTP API", () => {
  let app: FastifyInstance | undefined;
  afterEach(async () => app?.close());

  it("supports register, validate, logout, and revoked validation", async () => {
    const { services } = buildTestServices();
    app = buildApp(services);
    const registration = await app.inject({
      method: "POST",
      url: "/register",
      payload: {
        email: "retail@example.com",
        password: "correct-password",
      },
    });
    assert.equal(registration.statusCode, 201);
    const sessionId = registration.json().session.sessionId as string;

    const validation = await app.inject({
      method: "GET",
      url: "/session",
      headers: { authorization: `Bearer ${sessionId}` },
    });
    assert.equal(validation.statusCode, 200);
    assert.equal(validation.json().outcome, "authenticated");

    const logout = await app.inject({
      method: "POST",
      url: "/logout",
      headers: { authorization: `Bearer ${sessionId}` },
    });
    assert.equal(logout.statusCode, 204);

    const revoked = await app.inject({
      method: "GET",
      url: "/session",
      headers: { authorization: `Bearer ${sessionId}` },
    });
    assert.equal(revoked.statusCode, 401);
    assert.equal(revoked.json().error.code, "SESSION_REVOKED");
  });

  it("renews an expired bearer once using a rotating renewal credential", async () => {
    const { services, clock } = buildTestServices();
    app = buildApp(services);
    const registration = await app.inject({
      method: "POST",
      url: "/register",
      payload: { email: "renew@example.com", password: "correct-password" },
    });
    const original = registration.json().session as {
      sessionId: string;
      renewalToken: string;
    };
    assert.ok(original.renewalToken);

    clock.set(new Date("2026-01-01T02:00:00Z"));
    const expired = await app.inject({
      method: "GET",
      url: "/session",
      headers: { authorization: `Bearer ${original.sessionId}` },
    });
    assert.equal(expired.statusCode, 401);
    assert.equal(expired.json().error.code, "SESSION_EXPIRED");

    const refresh = await app.inject({
      method: "POST",
      url: "/session/refresh",
      payload: { renewalToken: original.renewalToken },
    });
    assert.equal(refresh.statusCode, 200);
    assert.notEqual(refresh.json().session.sessionId, original.sessionId);
    assert.notEqual(refresh.json().session.renewalToken, original.renewalToken);

    const replay = await app.inject({
      method: "POST",
      url: "/session/refresh",
      payload: { renewalToken: original.renewalToken },
    });
    assert.equal(replay.statusCode, 401);
    assert.equal(replay.json().error.code, "SESSION_RENEWAL_REVOKED");
  });

  it("rejects malformed renewal requests without session disclosure", async () => {
    const { services } = buildTestServices();
    app = buildApp(services);
    const response = await app.inject({
      method: "POST",
      url: "/session/refresh",
      payload: { renewalToken: "short", humanIdentityId: "caller-supplied" },
    });
    assert.equal(response.statusCode, 400);
    assert.deepEqual(response.json(), {
      error: { code: "INVALID_REQUEST", message: "Invalid request body" },
    });
  });

  it("supports login and uses a uniform response for authentication failures", async () => {
    const { services } = buildTestServices();
    app = buildApp(services);
    await app.inject({
      method: "POST",
      url: "/register",
      payload: {
        email: "retail@example.com",
        password: "correct-password",
      },
    });

    const login = await app.inject({
      method: "POST",
      url: "/login",
      payload: {
        email: "retail@example.com",
        password: "correct-password",
      },
    });
    assert.equal(login.statusCode, 200);
    assert.equal(login.json().session.sessionId, "session-2");

    for (const email of ["retail@example.com", "missing@example.com"]) {
      const failure: InjectResponse = await app.inject({
        method: "POST",
        url: "/login",
        payload: { email, password: "wrong-password" },
      });
      assert.equal(failure.statusCode, 401);
      assert.deepEqual(failure.json(), {
        error: {
          code: "INVALID_CREDENTIALS",
          message: "Invalid email or password",
        },
      });
    }
  });

  it("verifies a new password account with an opaque single-use token", async () => {
    const fixture = buildTestServices();
    app = buildApp(fixture.services);
    const registration = await app.inject({
      method: "POST",
      url: "/register",
      payload: { email: "verify@example.com", password: "correct-password", appId: "coco-web" },
    });
    assert.equal(registration.statusCode, 201);
    assert.deepEqual(registration.json().emailVerification, { required: true, delivery: "sent" });
    assert.equal(fixture.emails.messages.length, 1);
    const sessionId = registration.json().session.sessionId as string;

    const pending = await app.inject({
      method: "GET",
      url: "/authentication/email-password",
      headers: { authorization: `Bearer ${sessionId}` },
    });
    assert.deepEqual(pending.json(), {
      emailPassword: { email: "verify@example.com", verified: false },
    });

    const token = emailToken(fixture.emails.messages[0]!.text);
    const verification = await app.inject({
      method: "POST",
      url: "/email-verification/verify",
      payload: { token },
    });
    assert.equal(verification.statusCode, 204);

    const verified = await app.inject({
      method: "GET",
      url: "/authentication/email-password",
      headers: { authorization: `Bearer ${sessionId}` },
    });
    assert.equal(verified.json().emailPassword.verified, true);

    const replay = await app.inject({
      method: "POST",
      url: "/email-verification/verify",
      payload: { token },
    });
    assert.equal(replay.statusCode, 400);
    assert.equal(replay.json().error.code, "EMAIL_ACTION_TOKEN_INVALID");
  });

  it("invalidates an older verification token when resending", async () => {
    const fixture = buildTestServices();
    app = buildApp(fixture.services);
    const registration = await app.inject({
      method: "POST",
      url: "/register",
      payload: { email: "resend@example.com", password: "correct-password" },
    });
    const sessionId = registration.json().session.sessionId as string;
    const firstToken = emailToken(fixture.emails.messages[0]!.text);

    const resend = await app.inject({
      method: "POST",
      url: "/email-verification/resend",
      headers: { authorization: `Bearer ${sessionId}` },
      payload: { appId: "coco-web" },
    });
    assert.equal(resend.statusCode, 202);
    assert.equal(fixture.emails.messages.length, 2);
    const secondToken = emailToken(fixture.emails.messages[1]!.text);
    assert.notEqual(secondToken, firstToken);

    const oldLink = await app.inject({
      method: "POST",
      url: "/email-verification/verify",
      payload: { token: firstToken },
    });
    assert.equal(oldLink.statusCode, 400);

    const newLink = await app.inject({
      method: "POST",
      url: "/email-verification/verify",
      payload: { token: secondToken },
    });
    assert.equal(newLink.statusCode, 204);
  });

  it("uses the same forgot-password response for existing and unknown accounts", async () => {
    const fixture = buildTestServices();
    app = buildApp(fixture.services);
    await app.inject({
      method: "POST",
      url: "/register",
      payload: { email: "recover@example.com", password: "correct-password" },
    });
    fixture.emails.messages.splice(0);

    const responses = [];
    for (const email of ["recover@example.com", "missing@example.com"]) {
      responses.push(await app.inject({
        method: "POST",
        url: "/password/forgot",
        payload: { email, appId: "coco-web" },
      }));
    }
    assert.equal(responses[0]!.statusCode, 202);
    assert.equal(responses[1]!.statusCode, 202);
    assert.deepEqual(responses[0]!.json(), responses[1]!.json());
    assert.equal(fixture.emails.messages.length, 1);
  });

  it("resets the password without creating a session and revokes every existing session", async () => {
    const fixture = buildTestServices();
    app = buildApp(fixture.services);
    const registration = await app.inject({
      method: "POST",
      url: "/register",
      payload: { email: "reset@example.com", password: "correct-password" },
    });
    const firstSession = registration.json().session.sessionId as string;
    const secondLogin = await app.inject({
      method: "POST",
      url: "/login",
      payload: { email: "reset@example.com", password: "correct-password" },
    });
    const secondSession = secondLogin.json().session.sessionId as string;

    await app.inject({
      method: "POST",
      url: "/password/forgot",
      payload: { email: "reset@example.com" },
    });
    const token = emailToken(fixture.emails.messages.at(-1)!.text);
    const reset = await app.inject({
      method: "POST",
      url: "/password/reset",
      payload: { token, password: "a-new-secure-password" },
    });
    assert.equal(reset.statusCode, 204);
    assert.equal(reset.body, "");

    for (const sessionId of [firstSession, secondSession]) {
      const validation: InjectResponse = await app.inject({
        method: "GET",
        url: "/session",
        headers: { authorization: `Bearer ${sessionId}` },
      });
      assert.equal(validation.statusCode, 401);
      assert.equal(validation.json().error.code, "SESSION_REVOKED");
    }

    const oldPassword = await app.inject({
      method: "POST",
      url: "/login",
      payload: { email: "reset@example.com", password: "correct-password" },
    });
    assert.equal(oldPassword.statusCode, 401);
    const newPassword = await app.inject({
      method: "POST",
      url: "/login",
      payload: { email: "reset@example.com", password: "a-new-secure-password" },
    });
    assert.equal(newPassword.statusCode, 200);

    const replay = await app.inject({
      method: "POST",
      url: "/password/reset",
      payload: { token, password: "another-secure-password" },
    });
    assert.equal(replay.statusCode, 400);
  });

  it("expires email action links and throttles repeated registration attempts", async () => {
    const fixture = buildTestServices();
    app = buildApp(fixture.services);
    await app.inject({
      method: "POST",
      url: "/register",
      payload: { email: "expires@example.com", password: "correct-password" },
    });
    const token = emailToken(fixture.emails.messages[0]!.text);
    fixture.clock.set(new Date("2026-01-03T00:00:00Z"));
    const expired = await app.inject({
      method: "POST",
      url: "/email-verification/verify",
      payload: { token },
    });
    assert.equal(expired.statusCode, 400);

    const limitedFixture = buildTestServices();
    await app.close();
    app = buildApp(limitedFixture.services);
    for (let index = 0; index < 5; index += 1) {
      const accepted: InjectResponse = await app.inject({
        method: "POST",
        url: "/register",
        payload: { email: `limited-${index}@example.com`, password: "correct-password" },
      });
      assert.equal(accepted.statusCode, 201);
    }
    const limited = await app.inject({
      method: "POST",
      url: "/register",
      payload: { email: "limited-final@example.com", password: "correct-password" },
    });
    assert.equal(limited.statusCode, 429);
    assert.equal(limited.json().error.code, "RATE_LIMITED");
  });

  it("exposes both Railway health paths and rejects missing sessions", async () => {
    const { services } = buildTestServices();
    app = buildApp(services);
    for (const url of ["/", "/health"]) {
      const response: InjectResponse = await app.inject({ method: "GET", url });
      assert.equal(response.statusCode, 200);
      assert.equal(response.json().status, "running");
      assert.equal(response.json().database.status, "not_configured");
    }
    const missing = await app.inject({ method: "GET", url: "/session" });
    assert.equal(missing.statusCode, 401);
    assert.equal(missing.json().error.code, "SESSION_INVALID");
  });

  it("returns degraded health without leaking database errors", async () => {
    const { services } = buildTestServices();
    app = buildApp(services, {
      async check(): Promise<"connected"> {
        throw new Error(
          "postgresql://user:secret-password@private-host/database",
        );
      },
    });
    const response = await app.inject({ method: "GET", url: "/health" });
    assert.equal(response.statusCode, 503);
    assert.deepEqual(response.json(), {
      service: "gama-identity",
      version: "1.1.0",
      status: "degraded",
      database: { status: "unavailable" },
    });
    assert.doesNotMatch(response.body, /secret-password|private-host/);
  });
});

function emailToken(message: string): string {
  const token = /#token=([A-Za-z0-9_-]{43})/u.exec(message)?.[1];
  assert.ok(token);
  return token;
}
