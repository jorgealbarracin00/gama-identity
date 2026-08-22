import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { buildApp } from "../../src/api/app.js";
import { buildTestServices } from "../operational/test-doubles.js";

const nonce = "route_nonce_that_is_at_least_thirty_two_characters_123";

describe("federated identity HTTP boundary", () => {
  it("exchanges a verified Apple credential for the ordinary GAMA session envelope", async () => {
    const fixture = buildTestServices();
    fixture.appleVerifier.accept("valid-apple-token", {
      subject: "apple-subject",
      email: "relay@privaterelay.appleid.com",
      emailVerified: true,
      emailPrivate: true,
    });
    const app = buildApp(fixture.services);
    const response = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple",
      payload: { identityToken: "valid-apple-token", nonce },
    });
    assert.equal(response.statusCode, 200);
    assert.equal(response.json().session.humanIdentityId, "identity-1");
    assert.equal(response.json().session.sessionId, "session-1");
    assert.equal(response.json().account.email, "relay@privaterelay.appleid.com");
    assert.equal(response.body.includes("valid-apple-token"), false);
    await app.close();
  });

  it("does not accept caller-supplied subject, email or Human Identity", async () => {
    const fixture = buildTestServices();
    fixture.appleVerifier.accept("valid-token", { subject: "verified-subject" });
    const app = buildApp(fixture.services);
    const response = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple",
      payload: {
        identityToken: "valid-token",
        nonce,
        subject: "fake-subject",
        email: "fake@example.com",
        humanIdentityId: "platform-admin",
      },
    });
    assert.equal(response.statusCode, 400);
    assert.equal(response.json().error.code, "INVALID_REQUEST");
    assert.equal(fixture.federatedIdentities.count, 0);
    await app.close();
  });

  it("returns safe typed errors without echoing tokens or nonce values", async () => {
    const fixture = buildTestServices();
    const app = buildApp(fixture.services);
    const invalid = await app.inject({
      method: "POST",
      url: "/authentication/federated/apple",
      payload: { identityToken: "sensitive-invalid-token", nonce },
    });
    assert.equal(invalid.statusCode, 401);
    assert.equal(invalid.json().error.code, "FEDERATED_CREDENTIAL_INVALID");
    assert.equal(invalid.body.includes("sensitive-invalid-token"), false);
    assert.equal(invalid.body.includes(nonce), false);

    const unsupported = await app.inject({
      method: "POST",
      url: "/authentication/federated/google",
      payload: { identityToken: "unused-token", nonce },
    });
    assert.equal(unsupported.statusCode, 400);
    assert.equal(unsupported.json().error.code, "FEDERATED_PROVIDER_UNSUPPORTED");
    await app.close();
  });
});
