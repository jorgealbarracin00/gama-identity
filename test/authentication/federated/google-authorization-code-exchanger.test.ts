import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  GoogleAuthorizationCodeExchangeError,
  GoogleWebAuthorizationCodeExchanger,
} from "../../../src/authentication/federated/adapters/google-authorization-code-exchanger.js";

const clientId = "123456789.apps.googleusercontent.com";
const clientSecret = "server-only-client-secret";
const redirectUri = "https://cocothellama.com/api/auth/google/callback";
const codeVerifier = "a".repeat(43);

describe("Google web authorization-code exchange", () => {
  it("exchanges a one-time code with PKCE entirely server-side", async () => {
    let sentBody = "";
    const exchanger = new GoogleWebAuthorizationCodeExchanger({
      clientId,
      clientSecret,
      redirectUri,
      request: async (input, init) => {
        assert.equal(String(input), "https://oauth2.googleapis.com/token");
        assert.equal(init?.method, "POST");
        assert.equal(new Headers(init?.headers).get("content-type"), "application/x-www-form-urlencoded");
        sentBody = String(init?.body);
        return new Response(JSON.stringify({
          access_token: "must-never-be-returned",
          id_token: "signed-google-identity-token",
        }), { status: 200, headers: { "content-type": "application/json" } });
      },
    });
    assert.equal(
      await exchanger.exchange({ authorizationCode: "single-use-code", codeVerifier }),
      "signed-google-identity-token",
    );
    const form = new URLSearchParams(sentBody);
    assert.equal(form.get("client_id"), clientId);
    assert.equal(form.get("client_secret"), clientSecret);
    assert.equal(form.get("code"), "single-use-code");
    assert.equal(form.get("code_verifier"), codeVerifier);
    assert.equal(form.get("grant_type"), "authorization_code");
    assert.equal(form.get("redirect_uri"), redirectUri);
  });

  it("classifies invalid grants separately from provider and client failures", async () => {
    const rejected = exchanger(async () => new Response(JSON.stringify({ error: "invalid_grant" }), { status: 400 }));
    await assert.rejects(
      rejected.exchange({ authorizationCode: "expired-code", codeVerifier }),
      isExchangeError("AUTHORIZATION_CODE_REJECTED"),
    );
    const unavailable = exchanger(async () => new Response(JSON.stringify({ error: "invalid_client" }), { status: 401 }));
    await assert.rejects(
      unavailable.exchange({ authorizationCode: "valid-shape-code", codeVerifier }),
      isExchangeError("TOKEN_EXCHANGE_UNAVAILABLE"),
    );
  });

  it("requires an RFC 7636 verifier and rejects malformed success responses", async () => {
    const validResponse = exchanger(async () => new Response(JSON.stringify({ id_token: "unused" }), { status: 200 }));
    await assert.rejects(
      validResponse.exchange({ authorizationCode: "code" }),
      isExchangeError("AUTHORIZATION_CODE_REJECTED"),
    );
    await assert.rejects(
      validResponse.exchange({ authorizationCode: "code", codeVerifier: "too-short" }),
      isExchangeError("AUTHORIZATION_CODE_REJECTED"),
    );
    const missingToken = exchanger(async () => new Response(JSON.stringify({ access_token: "not-an-id-token" }), { status: 200 }));
    await assert.rejects(
      missingToken.exchange({ authorizationCode: "code", codeVerifier }),
      isExchangeError("TOKEN_EXCHANGE_UNAVAILABLE"),
    );
  });
});

function exchanger(request: typeof fetch): GoogleWebAuthorizationCodeExchanger {
  return new GoogleWebAuthorizationCodeExchanger({ clientId, clientSecret, redirectUri, request });
}

function isExchangeError(code: GoogleAuthorizationCodeExchangeError["code"]) {
  return (error: unknown) => error instanceof GoogleAuthorizationCodeExchangeError && error.code === code;
}
