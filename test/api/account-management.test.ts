import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../src/api/app.js";
import { buildTestServices } from "../operational/test-doubles.js";
import { HumanIdentityId } from "../../src/identity/domain/human-identity-id.js";
import { SessionId } from "../../src/sessions/domain/session-id.js";

type Fixture = ReturnType<typeof buildTestServices>;
const password = "Synthetic-password-123!";
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });
let sequence = 0;
async function google(f: Fixture, app: FastifyInstance, subject = "synthetic-google") {
  const n = `synthetic_account_nonce_abcdefghijklmnopqrstuvwxyz_${++sequence}`;
  const proof = `synthetic-proof-${sequence}`;
  f.googleVerifier.accept(proof, { subject, email: "same@synthetic.example", emailVerified: true });
  const r = await app.inject({ method: "POST", url: "/authentication/federated/google", payload: { identityToken: proof, nonce: n } });
  assert.equal(r.statusCode, 200);
  return r.json().session as { sessionId: string; humanIdentityId: string };
}
async function counts(f: Fixture) {
  const humans=f.identities.listForInspection(); let credentials=0,sessions=0;
  for (const h of humans) { credentials+=(await f.credentials.listByHumanIdentityId(h.id)).length; sessions+=(await f.sessions.listByHumanIdentityId(h.id)).length; }
  return {humans:humans.length,credentials,sessions};
}
const mailToken = (f: Fixture) => {
  const link = f.emails.messages.at(-1)?.text.match(/https:\/\/[^\s]+/u)?.[0];
  assert.ok(link);
  return new URLSearchParams(new URL(link).hash.slice(1)).get("token")!;
};
describe("optional account-management self-service", () => {
  let app: FastifyInstance;
  afterEach(async () => app?.close());
  it("is closed by default, authenticated, and contains no provider subjects or credentials", async () => {
    const f = buildTestServices(); app = buildApp(f.services); const owner = await google(f, app);
    assert.equal((await app.inject({ method: "GET", url: "/account" })).statusCode, 401);
    const r = await app.inject({ method: "GET", url: "/account", headers: bearer(owner.sessionId) });
    assert.equal(r.statusCode, 200); assert.equal(r.json().accountManagementEnabled, false);
    assert.doesNotMatch(r.body, /providerSubject|identityToken|passwordHash|synthetic-google|synthetic-proof/);
    const denied = await app.inject({ method: "POST", url: "/account/email/connect", headers: bearer(owner.sessionId), payload: { email: "own@synthetic.example", password } });
    assert.equal(denied.statusCode, 403); assert.equal((await counts(f)).credentials, 0);
  });
  it("links Email only after mailbox proof, preserving the Google Human and its data", async () => {
    const f = buildTestServices({ accountManagementEnabled: true }); app = buildApp(f.services); const owner = await google(f, app);
    const before = f.identities.listForInspection().length;
    const linked = await app.inject({ method: "POST", url: "/account/email/connect", headers: bearer(owner.sessionId), payload: { email: "verified@synthetic.example", password } });
    assert.equal(linked.statusCode, 200); assert.equal(linked.json().outcome, "verification_pending"); assert.equal(f.identities.listForInspection().length, before);
    const login = () => app.inject({ method: "POST", url: "/login", payload: { email: "verified@synthetic.example", password } });
    assert.equal((await login()).statusCode, 401);
    const token = mailToken(f);
    assert.equal((await app.inject({ method: "POST", url: "/email-verification/verify", payload: { token } })).statusCode, 204);
    assert.equal((await login()).json().session.humanIdentityId, owner.humanIdentityId);
    assert.equal((await app.inject({ method: "POST", url: "/email-verification/verify", payload: { token } })).statusCode, 400);
    const state = await app.inject({ method: "GET", url: "/account", headers: bearer(owner.sessionId) });
    assert.equal(state.json().emailPassword.verified, true); assert.equal(state.json().pendingEmail, null);
    const audit = JSON.stringify(f.controlPlaneRepository.auditEvents);
    assert.match(audit, /authentication.email.connected/); assert.doesNotMatch(audit, /verified@synthetic|Synthetic-password|synthetic-proof/);
  });
  it("does not use an entered email as ownership or disclose another account on conflict", async () => {
    const f = buildTestServices({ accountManagementEnabled: true }); app = buildApp(f.services);
    const other = await app.inject({ method: "POST", url: "/register", payload: { email: "claimed@synthetic.example", password } });
    const owner = await google(f, app);
    const conflict = await app.inject({ method: "POST", url: "/account/email/connect", headers: bearer(owner.sessionId), payload: { email: "claimed@synthetic.example", password } });
    assert.equal(conflict.statusCode, 409); assert.equal(conflict.json().error.code, "EMAIL_LINK_CONFLICT");
    assert.equal(conflict.body.includes(other.json().humanIdentityId), false); assert.equal((await counts(f)).credentials, 1);
    const spoof = await app.inject({ method: "POST", url: "/account/email/connect", headers: bearer(owner.sessionId), payload: { email: "unused@synthetic.example", password, humanIdentityId: other.json().humanIdentityId } });
    assert.equal(spoof.statusCode, 400);
  });
  it("rejects an expired verification and never treats a pending email as another usable method", async () => {
    const f = buildTestServices({ accountManagementEnabled: true }); app = buildApp(f.services); const owner = await google(f, app);
    await app.inject({ method: "POST", url: "/account/email/connect", headers: bearer(owner.sessionId), payload: { email: "pending@synthetic.example", password } });
    const remove = await app.inject({ method: "DELETE", url: "/authentication/federated/google/link", headers: bearer(owner.sessionId) });
    assert.equal(remove.statusCode, 409); assert.equal(remove.json().error.code, "LAST_AUTHENTICATION_METHOD");
    const token = mailToken(f); f.clock.set(new Date("2026-01-02T00:00:01Z"));
    assert.equal((await app.inject({ method: "POST", url: "/email-verification/verify", payload: { token } })).statusCode, 400);
    assert.equal((await f.credentials.findByHumanIdentityId(HumanIdentityId.from(owner.humanIdentityId)))?.status, "disabled");
  });
  it("requires fresh primary access and leaves existing methods intact when it is stale", async () => {
    const f = buildTestServices({ accountManagementEnabled: true }); app = buildApp(f.services); const owner = await google(f, app);
    f.clock.set(new Date("2026-01-01T00:05:01Z"));
    const r = await app.inject({ method: "POST", url: "/account/email/connect", headers: bearer(owner.sessionId), payload: { email: "later@synthetic.example", password } });
    assert.equal(r.statusCode, 403); assert.equal(r.json().error.code, "REAUTHENTICATION_REQUIRED"); assert.equal((await counts(f)).credentials, 0);
    assert.equal((await f.sessions.findById(SessionId.from(owner.sessionId)))?.status, "active");
  });
  it("changes password only with current proof and invalidates all affected central sessions", async () => {
    const f = buildTestServices({ accountManagementEnabled: true }); app = buildApp(f.services);
    const r = await app.inject({ method: "POST", url: "/register", payload: { email: "password@synthetic.example", password } });
    const owner = r.json().session;
    const change = (old: string) => app.inject({ method: "POST", url: "/account/password/change", headers: bearer(owner.sessionId), payload: { currentPassword: old, password: "Replacement-password-456!" } });
    assert.equal((await change("wrong-password")).statusCode, 403);
    assert.equal((await change(password)).json().reauthenticationRequired, true);
    assert.equal((await f.sessions.findById(SessionId.from(owner.sessionId)))?.status, "revoked");
    assert.equal((await app.inject({ method: "POST", url: "/login", payload: { email: "password@synthetic.example", password } })).statusCode, 401);
    const fresh = await app.inject({ method: "POST", url: "/login", payload: { email: "password@synthetic.example", password: "Replacement-password-456!" } });
    assert.equal(fresh.json().session.humanIdentityId, owner.humanIdentityId);
  });
  it("disconnects a verified email while retaining Google access and cancels email challenges", async () => {
    const f = buildTestServices({ accountManagementEnabled: true }); app = buildApp(f.services); const owner = await google(f, app);
    await app.inject({ method: "POST", url: "/account/email/connect", headers: bearer(owner.sessionId), payload: { email: "remove@synthetic.example", password } });
    await app.inject({ method: "POST", url: "/email-verification/verify", payload: { token: mailToken(f) } });
    const r = await app.inject({ method: "DELETE", url: "/account/email", headers: bearer(owner.sessionId), payload: {} });
    assert.equal(r.statusCode, 200); assert.equal(r.json().reauthenticationRequired, false);
    assert.equal((await f.sessions.findById(SessionId.from(owner.sessionId)))?.status, "active");
    assert.equal((await google(f, app)).humanIdentityId, owner.humanIdentityId);
    assert.equal((await app.inject({ method: "POST", url: "/login", payload: { email: "remove@synthetic.example", password } })).statusCode, 401);
  });
  it("reauthenticates only the current existing Human, without registering or adopting a different account", async () => {
    const f = buildTestServices({ accountManagementEnabled: true }); app = buildApp(f.services); const owner = await google(f, app);
    const other = await app.inject({ method: "POST", url: "/register", payload: { email: "other@synthetic.example", password } });
    const sessions = (await counts(f)).sessions, humans = f.identities.listForInspection().length;
    const wrongEmail = await app.inject({ method: "POST", url: "/account/reauthenticate/email", headers: bearer(owner.sessionId), payload: { email: "other@synthetic.example", password } });
    assert.equal(wrongEmail.statusCode, 401); assert.equal(wrongEmail.json().error.code, "REAUTHENTICATION_REJECTED");
    f.appleVerifier.accept("unknown-apple", { subject: "new-apple-subject" });
    const wrongProvider = await app.inject({ method: "POST", url: "/account/reauthenticate/apple", headers: bearer(owner.sessionId), payload: { identityToken: "unknown-apple", nonce: "synthetic_nonce_abcdefghijklmnopqrstuvwxyz_123" } });
    assert.equal(wrongProvider.statusCode, 401); assert.equal(f.identities.listForInspection().length, humans); assert.equal((await counts(f)).sessions, sessions);
    const ownEmail = await app.inject({ method: "POST", url: "/account/reauthenticate/email", headers: bearer(other.json().session.sessionId), payload: { email: "other@synthetic.example", password } });
    assert.equal(ownEmail.statusCode, 200); assert.equal(ownEmail.json().session.humanIdentityId, other.json().humanIdentityId);
  });
});
