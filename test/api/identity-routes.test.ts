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

  it("exposes both Railway health paths and rejects missing sessions", async () => {
    const { services } = buildTestServices();
    app = buildApp(services);
    for (const url of ["/", "/health"]) {
      const response: InjectResponse = await app.inject({ method: "GET", url });
      assert.equal(response.statusCode, 200);
      assert.equal(response.json().status, "running");
    }
    const missing = await app.inject({ method: "GET", url: "/session" });
    assert.equal(missing.statusCode, 401);
    assert.equal(missing.json().error.code, "SESSION_INVALID");
  });
});
