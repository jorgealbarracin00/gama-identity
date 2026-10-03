import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { exportPKCS8, generateKeyPair, jwtVerify } from "jose";

import {
  AppleAuthorizationCodeExchangeError,
  AppleWebAuthorizationCodeExchanger,
} from "../../../src/authentication/federated/adapters/apple-authorization-code-exchanger.js";
import { MutableClock } from "../../operational/test-doubles.js";

const clientId = "com.gamadynamics.cocothellama.web";
const teamId = "33VYKC5J83";
const keyId = "ABC123DEFG";
const redirectUri = "https://cocothellama.com/api/auth/apple/callback";
const clock = new MutableClock(new Date("2026-10-03T08:00:00.000Z"));

describe("Apple web authorization-code exchange", () => {
  it("signs a short-lived server credential and exchanges the code without exposing it", async () => {
    const keys = await generateKeyPair("ES256", { extractable: true });
    const privateKey = await exportPKCS8(keys.privateKey);
    let sentBody = "";
    const exchanger = new AppleWebAuthorizationCodeExchanger({
      clientId,
      teamId,
      keyId,
      redirectUri,
      privateKey,
      clock,
      request: async (input, init) => {
        assert.equal(String(input), "https://appleid.apple.com/auth/token");
        assert.equal(init?.method, "POST");
        sentBody = String(init?.body);
        return new Response(JSON.stringify({ id_token: "signed-apple-identity-token" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    });

    assert.equal(
      await exchanger.exchange({ authorizationCode: "single-use-code" }),
      "signed-apple-identity-token",
    );
    const form = new URLSearchParams(sentBody);
    assert.equal(form.get("client_id"), clientId);
    assert.equal(form.get("code"), "single-use-code");
    assert.equal(form.get("grant_type"), "authorization_code");
    assert.equal(form.get("redirect_uri"), redirectUri);
    const clientSecret = form.get("client_secret");
    assert.ok(clientSecret);
    const verified = await jwtVerify(clientSecret, keys.publicKey, {
      algorithms: ["ES256"],
      issuer: teamId,
      audience: "https://appleid.apple.com",
      subject: clientId,
      currentDate: clock.now(),
    });
    assert.equal(verified.protectedHeader.kid, keyId);
    assert.equal(verified.payload.exp! - verified.payload.iat!, 300);
  });

  it("classifies rejected grants separately from provider/configuration failures", async () => {
    const keys = await generateKeyPair("ES256", { extractable: true });
    const privateKey = await exportPKCS8(keys.privateKey);
    const rejected = new AppleWebAuthorizationCodeExchanger({
      clientId, teamId, keyId, redirectUri, privateKey, clock,
      request: async () => new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 }),
    });
    await assert.rejects(
      rejected.exchange({ authorizationCode: "expired-code" }),
      (error: unknown) => error instanceof AppleAuthorizationCodeExchangeError && error.code === "AUTHORIZATION_CODE_REJECTED",
    );

    const unavailable = new AppleWebAuthorizationCodeExchanger({
      clientId, teamId, keyId, redirectUri, privateKey, clock,
      request: async () => new Response(JSON.stringify({ error: "invalid_client" }), { status: 400 }),
    });
    await assert.rejects(
      unavailable.exchange({ authorizationCode: "valid-shape-code" }),
      (error: unknown) => error instanceof AppleAuthorizationCodeExchangeError && error.code === "TOKEN_EXCHANGE_UNAVAILABLE",
    );
  });
});
