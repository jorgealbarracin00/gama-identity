import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../src/api/app.js";
import { AuthenticateGoogleWeb } from "../../src/authentication/federated/application/authenticate-google-web.js";
import { AuthenticateFederated } from "../../src/authentication/federated/application/authenticate-federated.js";
import { LinkGoogleWeb } from "../../src/authentication/federated/application/link-google-web.js";
import { ManageFederatedAuthenticationMethods } from "../../src/authentication/federated/application/manage-federated-authentication-methods.js";
import { FederatedIdentityTokenVerifiers } from "../../src/authentication/federated/application/token-verifier.js";
import { GoogleAuthorizationCodeExchangeError } from "../../src/authentication/federated/adapters/google-authorization-code-exchanger.js";
import { FederatedIdentity, FederatedIdentityProvider, FederatedProviderSubject } from "../../src/authentication/federated/domain/federated-identity.js";
import { HumanIdentity } from "../../src/identity/domain/human-identity.js";
import { HumanIdentityId } from "../../src/identity/domain/human-identity-id.js";
import { SessionId } from "../../src/sessions/domain/session-id.js";
import { Session } from "../../src/sessions/domain/session.js";
import { CreateSession } from "../../src/sessions/application/use-cases.js";
import { UuidFederatedIdentityIdGenerator, UuidHumanIdentityIdGenerator, UuidSessionIdGenerator } from "../../src/shared/identifiers.js";
import { SerialExecutor } from "../../src/shared/serial-executor.js";
import { buildTestServices } from "../operational/test-doubles.js";

const path = "/authentication/federated/google/web/link";
const codeVerifier = "v".repeat(43);
const nonce = (value: string) => `google_web_link_nonce_at_least_thirty_two_chars_${value}`;
const bearer = (value: string) => ({ authorization: `Bearer ${value}` });
const payload = (suffix = "first") => ({
  appId: "cashcast-preview", authorizationCode: "private-fixture-code",
  codeVerifier, nonce: nonce(suffix),
});
const apps: FastifyInstance[] = [];
afterEach(async () => { while (apps.length) await apps.pop()!.close(); });

async function fixture(options: {
  allow?: string[];
  exchangeHook?: (data: ReturnType<typeof buildTestServices>, sessionId: string) => Promise<void>;
  exchangeError?: GoogleAuthorizationCodeExchangeError;
  invalidToken?: boolean;
} = {}) {
  const data = buildTestServices();
  const owner = await data.services.register.execute({ email: "owner@example.test", password: "Synthetic-password-123" });
  const sessionId = owner.session.sessionId;
  const principal = owner.humanIdentityId;
  data.appleVerifier.accept("existing-apple-proof", { subject: "existing-apple-subject" });
  await data.services.federatedAuthenticationMethods.link(SessionId.from(sessionId), {
    provider: "apple", identityToken: "existing-apple-proof", nonce: nonce("existing-apple"),
  });
  data.googleVerifier.accept("registered-google-proof", { subject: "new-google-subject", email: "owner@example.test" });
  const allowed = new Set(options.allow ?? [principal]);
  const serial = new SerialExecutor();
  const methods = new ManageFederatedAuthenticationMethods(
    new FederatedIdentityTokenVerifiers([data.googleVerifier]), data.federatedIdentities, data.federatedNonces,
    data.identities, data.credentials, data.sessions, data.controlPlaneRepository,
    new UuidFederatedIdentityIdGenerator(), data.clock, work => serial.execute(work),
    { allowedPrincipalIds: allowed, allowReconciliation: false },
  );
  const calls: { authorizationCode: string; codeVerifier?: string }[] = [];
  const exchanger = { async exchange(input: { authorizationCode: string; codeVerifier?: string }) {
    calls.push(input);
    if (options.exchangeHook) await options.exchangeHook(data, sessionId);
    if (options.exchangeError) throw options.exchangeError;
    return options.invalidToken ? "bad-token" : "registered-google-proof";
  } };
  const scopedSignIn = new AuthenticateFederated(
    new FederatedIdentityTokenVerifiers([data.googleVerifier]), data.federatedIdentities, data.federatedNonces,
    data.identities, new UuidHumanIdentityIdGenerator(), new UuidFederatedIdentityIdGenerator(),
    new CreateSession(data.sessions, new UuidSessionIdGenerator(), data.clock, 3600),
    data.clock, work => serial.execute(work), allowed,
  );
  const app = buildApp({ ...data.services, webAuthenticationApps: new Map([
    ["cashcast-preview", { googleLink: new LinkGoogleWeb(exchanger, methods), google: new AuthenticateGoogleWeb(exchanger, scopedSignIn) }],
    ["other-product", { google: new AuthenticateGoogleWeb(exchanger, scopedSignIn) }],
  ]) });
  apps.push(app);
  const request = (body: Record<string, unknown> = payload(), session = sessionId) =>
    app.inject({ method: "POST", url: path, headers: bearer(session), payload: body });
  const relationship = () => data.federatedIdentities.findByProviderSubject(
    FederatedIdentityProvider.from("google"), FederatedProviderSubject.from("new-google-subject"),
  );
  return { data, app, principal, sessionId, calls, request, relationship };
}

describe("CashCast registered Google web linking security boundary", () => {
  it("links only the authenticated existing Human, preserves Apple/Email/session, then supports scoped Google sign-in", async () => {
    const f = await fixture();
    const before = (await f.data.sessions.findById(SessionId.from(f.sessionId)))!.snapshot();
    const result = await f.request();
    assert.equal(result.statusCode, 200);
    assert.equal(result.json().outcome, "linked");
    assert.equal(result.json().humanIdentityId, f.principal);
    assert.equal(result.json().methods.emailPassword.connected, true);
    assert.deepEqual(result.json().methods.federated.map((method: { provider: string }) => method.provider), ["apple", "google"]);
    assert.deepEqual((await f.data.sessions.findById(SessionId.from(f.sessionId)))!.snapshot(), before);
    assert.equal((await f.data.sessions.listByHumanIdentityId(HumanIdentityId.from(f.principal))).length, 1);
    assert.equal(await f.data.identities.findById(HumanIdentityId.from("identity-2")), null);
    assert.equal((await f.relationship())!.humanIdentityId.value, f.principal);
    for (const secret of ["private-fixture-code", codeVerifier, nonce("first"), "registered-google-proof", "new-google-subject"]) {
      assert.equal(result.body.includes(secret), false);
    }
    assert.deepEqual(f.calls[0], { authorizationCode: "private-fixture-code", codeVerifier });
    const googleLogin = await f.app.inject({ method: "POST", url: "/authentication/federated/google/web", payload: payload("login") });
    assert.equal(googleLogin.statusCode, 200);
    assert.equal(googleLogin.json().session.humanIdentityId, f.principal);
    const email = await f.data.services.login.execute({ email: "owner@example.test", password: "Synthetic-password-123" });
    assert.equal(email.humanIdentityId, f.principal);
    f.data.appleVerifier.accept("fresh-apple-proof", { subject: "existing-apple-subject" });
    const apple = await f.data.services.authenticateFederated.execute({ provider: "apple", identityToken: "fresh-apple-proof", nonce: nonce("apple-after") });
    assert.equal(apple.humanIdentityId, f.principal);
  });

  it("is idempotent with fresh proof and never creates another relationship", async () => {
    const f = await fixture();
    assert.equal((await f.request()).json().outcome, "linked");
    assert.equal((await f.request(payload("second"))).json().outcome, "already_linked");
    assert.equal(f.data.federatedIdentities.count, 2);
    assert.equal((await f.data.sessions.listByHumanIdentityId(HumanIdentityId.from(f.principal))).length, 1);
  });

  it("rejects guests and invalid sessions before provider exchange", async () => {
    const f = await fixture();
    const guest = await f.app.inject({ method: "POST", url: path, payload: payload() });
    assert.equal(guest.statusCode, 401);
    assert.equal((await f.request(payload(), "not-a-session")).statusCode, 401);
    assert.equal(f.calls.length, 0);
    assert.equal(await f.relationship(), null);
  });

  for (const state of ["revoked", "expired", "inactive-human"] as const) {
    it(`rejects ${state} before provider exchange`, async () => {
      const f = await fixture();
      if (state === "revoked") await f.data.sessions.revoke(SessionId.from(f.sessionId));
      if (state === "expired") f.data.clock.set(new Date("2026-01-01T02:00:00Z"));
      if (state === "inactive-human") {
        const human = (await f.data.identities.findById(HumanIdentityId.from(f.principal)))!;
        human.suspend(f.data.clock); await f.data.identities.save(human);
      }
      assert.equal((await f.request()).statusCode, state === "inactive-human" ? 403 : 401);
      assert.equal(f.calls.length, 0);
      assert.equal(await f.relationship(), null);
    });
  }

  for (const allow of [["another-approved-principal"], []]) {
    it(`denies ${allow.length ? "unapproved" : "empty-allowlist"} targets without session mutation or exchange`, async () => {
      const f = await fixture({ allow });
      const before = (await f.data.sessions.findById(SessionId.from(f.sessionId)))!.snapshot();
      assert.equal((await f.request()).statusCode, 403);
      assert.deepEqual((await f.data.sessions.findById(SessionId.from(f.sessionId)))!.snapshot(), before);
      assert.equal(f.calls.length, 0);
    });
  }

  it("does not fall back to global or other-product authentication", async () => {
    const f = await fixture();
    for (const appId of ["unknown", "other-product", "coco-web"]) {
      const result = await f.request({ ...payload(), appId });
      assert.equal(result.statusCode, 503);
      assert.equal(result.json().error.code, "GOOGLE_WEB_LINKING_UNAVAILABLE");
    }
    assert.equal(f.calls.length, 0);
  });

  it("requires the app and PKCE verifier and rejects all client-supplied identity authority", async () => {
    const f = await fixture();
    const { appId: ignoredApp, ...noApp } = payload();
    const { codeVerifier: ignoredVerifier, ...noVerifier } = payload();
    void ignoredApp; void ignoredVerifier;
    const invalid: Record<string, unknown>[] = [noApp, noVerifier, { ...payload(), codeVerifier: "short" }, { ...payload(), nonce: "short" }];
    for (const extra of [{ humanIdentityId: "victim" }, { identityToken: "raw-token" }, { subject: "subject" }, { email: "owner@example.test" }, { redirectUri: "https://evil.test" }, { clientId: "legacy-client" }]) invalid.push({ ...payload(), ...extra });
    for (const body of invalid) assert.equal((await f.request(body)).statusCode, 400);
    assert.equal(f.calls.length, 0);
  });

  for (const code of ["AUTHORIZATION_CODE_REJECTED", "TOKEN_EXCHANGE_UNAVAILABLE"] as const) {
    it(`sanitizes ${code} without identity or session changes`, async () => {
      const f = await fixture({ exchangeError: new GoogleAuthorizationCodeExchangeError(code) });
      const result = await f.request();
      assert.equal(result.statusCode, code === "AUTHORIZATION_CODE_REJECTED" ? 401 : 503);
      assert.equal(result.body.includes("private-fixture-code"), false);
      assert.equal(await f.relationship(), null);
      assert.equal((await f.data.sessions.listByHumanIdentityId(HumanIdentityId.from(f.principal))).length, 1);
    });
  }

  it("rejects invalid provider proof without linking", async () => {
    const f = await fixture({ invalidToken: true });
    assert.equal((await f.request()).statusCode, 401);
    assert.equal(await f.relationship(), null);
  });

  it("rejects replayed nonce after a successful link", async () => {
    const f = await fixture();
    assert.equal((await f.request()).statusCode, 200);
    const result = await f.request({ ...payload(), authorizationCode: "different-code" });
    assert.equal(result.statusCode, 401);
    assert.equal(result.json().error.code, "FEDERATED_CREDENTIAL_INVALID");
    assert.equal(f.data.federatedIdentities.count, 2);
  });

  it("reactivates only the same principal's disabled Google relationship without replacing Apple/Email", async () => {
    const f = await fixture();
    assert.equal((await f.request()).statusCode, 200);
    const existing = (await f.relationship())!;
    existing.disable(f.data.clock);
    await f.data.federatedIdentities.save(existing);
    const result = await f.request(payload("reactivation"));
    assert.equal(result.statusCode, 200);
    assert.equal(result.json().outcome, "linked");
    assert.equal((await f.relationship())!.id.value, existing.id.value);
    assert.equal((await f.relationship())!.status, "active");
    assert.equal(result.json().methods.emailPassword.connected, true);
    assert.deepEqual(result.json().methods.federated.map((m: { provider: string }) => m.provider), ["apple", "google"]);
  });

  it("rejects a retired same-account relationship rather than reactivating it", async () => {
    const f = await fixture();
    assert.equal((await f.request()).statusCode, 200);
    const retired = FederatedIdentity.reconstitute({ ...(await f.relationship())!.snapshot(), status: "retired" });
    await f.data.federatedIdentities.save(retired);
    assert.equal((await f.request(payload("retired"))).statusCode, 409);
    assert.equal((await f.relationship())!.status, "retired");
  });

  it("never replaces an already connected Google subject with another subject", async () => {
    const f = await fixture();
    assert.equal((await f.request()).statusCode, 200);
    const before = (await f.relationship())!.snapshot();
    f.data.googleVerifier.accept("registered-google-proof", { subject: "replacement-subject" });
    assert.equal((await f.request(payload("replacement"))).statusCode, 409);
    assert.deepEqual((await f.relationship())!.snapshot(), before);
    assert.equal(f.data.federatedIdentities.count, 2);
  });

  it("shares nonce replay protection with legacy Google proof verification", async () => {
    const f = await fixture();
    f.data.googleVerifier.accept("other-proof", { subject: "other-subject" });
    await f.data.services.federatedAuthenticationMethods.link(SessionId.from(f.sessionId), { provider: "google", identityToken: "other-proof", nonce: nonce("first") });
    assert.equal((await f.request()).statusCode, 401);
    assert.equal(await f.relationship(), null);
  });

  it("rejects even a pristine foreign Google-only identity without reconciliation or metadata updates", async () => {
    const f = await fixture();
    const foreign = HumanIdentity.create(new UuidHumanIdentityIdGenerator(), f.data.clock);
    await f.data.identities.save(foreign);
    await f.data.federatedIdentities.save(FederatedIdentity.create(
      new UuidFederatedIdentityIdGenerator(), foreign.id, FederatedIdentityProvider.from("google"),
      FederatedProviderSubject.from("new-google-subject"),
      { email: "before@example.test", emailVerified: true, emailPrivate: null }, f.data.clock,
    ));
    const beforeHuman = foreign.snapshot();
    const beforeRelationship = (await f.relationship())!.snapshot();
    const result = await f.request();
    assert.equal(result.statusCode, 409);
    assert.equal(result.json().error.code, "FEDERATED_IDENTITY_LINK_CONFLICT");
    assert.deepEqual((await f.relationship())!.snapshot(), beforeRelationship);
    assert.deepEqual((await f.data.identities.findById(foreign.id))!.snapshot(), beforeHuman);
    assert.equal((await f.data.services.federatedAuthenticationMethods.list(SessionId.from(f.sessionId))).federated.length, 1);
  });

  it("does not use matching email to select or merge the target", async () => {
    const f = await fixture();
    const unrelated = await f.data.services.register.execute({ email: "unrelated@example.test", password: "Synthetic-password-456" });
    f.data.googleVerifier.accept("registered-google-proof", { subject: "new-google-subject", email: "unrelated@example.test" });
    assert.equal((await f.request()).statusCode, 200);
    assert.equal((await f.relationship())!.humanIdentityId.value, f.principal);
    assert.equal((await f.data.identities.findById(HumanIdentityId.from(unrelated.humanIdentityId)))!.status, "active");
    assert.equal((await f.data.services.federatedAuthenticationMethods.list(SessionId.from(unrelated.session.sessionId))).federated.length, 0);
  });

  for (const change of ["revoke", "expire", "suspend"] as const) {
    it(`rechecks a session/principal that changes during exchange: ${change}`, async () => {
      const f = await fixture({ exchangeHook: async (data, session) => {
        if (change === "revoke") await data.sessions.revoke(SessionId.from(session));
        if (change === "expire") data.clock.set(new Date("2026-01-01T02:00:00Z"));
        if (change === "suspend") {
          const human = (await data.identities.findById(HumanIdentityId.from("identity-1")))!;
          human.suspend(data.clock); await data.identities.save(human);
        }
      } });
      assert.equal((await f.request()).statusCode, change === "suspend" ? 403 : 401);
      assert.equal(await f.relationship(), null);
      if (change === "revoke") assert.equal((await f.data.sessions.findById(SessionId.from(f.sessionId)))!.status, "revoked");
    });
  }

  it("binds the exchanged proof to the preflight principal even if both principals are allowlisted", async () => {
    const f = await fixture({ allow: ["identity-1", "identity-2"], exchangeHook: async (data, session) => {
      const other = await data.services.register.execute({ email: "second@example.test", password: "Synthetic-password-456" });
      const before = (await data.sessions.findById(SessionId.from(session)))!.snapshot();
      await data.sessions.save(Session.reconstitute({ ...before, humanIdentityId: HumanIdentityId.from(other.humanIdentityId) }));
    } });
    assert.equal((await f.request()).statusCode, 401);
    assert.equal(await f.relationship(), null);
  });

  it("checks revocation again after token verification, inside the mutation transaction", async () => {
    const f = await fixture();
    const original = f.data.googleVerifier.verify.bind(f.data.googleVerifier);
    f.data.googleVerifier.verify = async input => {
      const proof = await original(input);
      await f.data.sessions.revoke(SessionId.from(f.sessionId));
      return proof;
    };
    assert.equal((await f.request()).statusCode, 401);
    assert.equal(await f.relationship(), null);
  });
});
