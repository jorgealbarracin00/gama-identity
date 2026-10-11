import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { afterEach, describe, it, mock } from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { buildRuntime, type ApplicationRuntime } from "../../../src/api/services.js";
import { buildApp } from "../../../src/api/app.js";
import { loadConfig } from "../../../src/config/env.js";
import { PostgresDatabase } from "../../../src/infrastructure/postgres/database.js";
import { PostgresFederatedIdentityRepository } from "../../../src/infrastructure/postgres/postgres-federated-identity-repository.js";
import { FederatedIdentity, FederatedIdentityProvider, FederatedProviderSubject } from "../../../src/authentication/federated/domain/federated-identity.js";
import { HumanIdentityId } from "../../../src/identity/domain/human-identity-id.js";
import { SessionId } from "../../../src/sessions/domain/session-id.js";
import { UuidFederatedIdentityIdGenerator } from "../../../src/shared/identifiers.js";
import { SystemClock } from "../../../src/shared/clock.js";

const testURL = process.env.POSTGRES_TEST_DATABASE_URL;
const clientId = "cashcast-preview-google-fixture";
const redirectUri = "https://cashcast-genesis-preview.vercel.app/api/auth/google/callback";
const verifier = "v".repeat(43);
const nonce = "n".repeat(43);
const keys = await generateKeyPair("RS256");
const publicJWK = { ...await exportJWK(keys.publicKey), kid: "synthetic-google-key", use: "sig", alg: "RS256" };
const cleanup: (() => Promise<void>)[] = [];
afterEach(async () => {
  mock.restoreAll();
  while (cleanup.length) await cleanup.pop()!();
});

async function token(options: {
  audience?: string; issuer?: string; nonce?: string; expired?: boolean; wrongSignature?: boolean;
} = {}) {
  return new SignJWT({ nonce: options.nonce ?? nonce, email: "other-address@example.test", email_verified: true })
    .setProtectedHeader({ alg: "RS256", kid: "synthetic-google-key" })
    .setIssuer(options.issuer ?? "https://accounts.google.com")
    .setAudience(options.audience ?? clientId)
    .setSubject("synthetic-google-subject")
    .setIssuedAt()
    .setExpirationTime(options.expired ? Math.floor(Date.now() / 1000) - 60 : "5m")
    .sign(options.wrongSignature ? (await generateKeyPair("RS256")).privateKey : keys.privateKey);
}

async function fixture(secondOwner = false) {
  const admin = new PostgresDatabase(testURL!);
  const schema = `scoped_google_link_${randomUUID().replaceAll("-", "")}`;
  await admin.query(`CREATE SCHEMA ${schema}`);
  const url = new URL(testURL!);
  url.searchParams.set("options", `-c search_path=${schema}`);
  url.searchParams.set("application_name", schema);
  const schemaURL = url.toString();
  const runtimes: ApplicationRuntime[] = [];
  const databases: PostgresDatabase[] = [];
  cleanup.push(async () => {
    for (const runtime of runtimes) await runtime.close();
    for (const database of databases) await database.close();
    await admin.query(`DROP SCHEMA ${schema} CASCADE`);
    await admin.close();
  });
  const seed = await buildRuntime(loadConfig({ REPOSITORY_MODE: "postgres", DATABASE_URL: schemaURL }));
  runtimes.push(seed);
  const owner = await seed.services.register.execute({ email: "owner@example.test", password: "Synthetic-password-123" });
  const other = secondOwner
    ? await seed.services.register.execute({ email: "other@example.test", password: "Synthetic-password-456" }) : null;
  await seed.close(); runtimes.pop();
  const database = new PostgresDatabase(schemaURL); databases.push(database);
  await new PostgresFederatedIdentityRepository(database).save(FederatedIdentity.create(
    new UuidFederatedIdentityIdGenerator(), HumanIdentityId.from(owner.humanIdentityId),
    FederatedIdentityProvider.from("apple"), FederatedProviderSubject.from("synthetic-existing-apple"),
    { email: "relay@example.test", emailVerified: true, emailPrivate: true }, new SystemClock(),
  ));
  const registeredGoogle = { clientId, clientSecret: "synthetic-only-not-a-real-secret", redirectUri };
  const configuration = loadConfig({
    REPOSITORY_MODE: "postgres", DATABASE_URL: schemaURL, GOOGLE_CLIENT_IDS: "legacy-google-native-fixture",
    IDENTITY_TRUSTED_APPS: JSON.stringify([
      { id: "coco-web", displayName: "Coco the Llama", baseUrl: "https://cocothellama.com" },
      { id: "cashcast-preview", displayName: "CashCast Preview", baseUrl: "https://cashcast-genesis-preview.vercel.app" },
      { id: "other-preview", displayName: "Other Test", baseUrl: "https://other-preview.example.test" },
      { id: "cashcast-web", displayName: "Future Production Test", baseUrl: "https://production.example.test" },
    ]),
    IDENTITY_WEB_APPS: JSON.stringify([
      { appId: "cashcast-preview", purpose: "preview", allowedPrincipalIds: [owner.humanIdentityId, ...(other ? [other.humanIdentityId] : [])], google: registeredGoogle },
      { appId: "other-preview", purpose: "preview", allowedPrincipalIds: [owner.humanIdentityId], google: { ...registeredGoogle, clientId: "other-preview-client", redirectUri: "https://other-preview.example.test/api/auth/google/callback" } },
      { appId: "cashcast-web", purpose: "production", google: { ...registeredGoogle, clientId: "future-production-client", redirectUri: "https://production.example.test/api/auth/google/callback" } },
    ]),
  });
  const state = {
    tokens: new Map([["synthetic-code", await token()]]),
    exchanges: 0, keys: 0, hook: undefined as (() => Promise<void>) | undefined,
  };
  mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
    const address = String(input);
    if (address === "https://oauth2.googleapis.com/token") {
      state.exchanges++;
      const body = new URLSearchParams(String(init?.body));
      assert.equal(body.get("client_id"), clientId);
      assert.equal(body.get("client_secret"), "synthetic-only-not-a-real-secret");
      assert.equal(body.get("redirect_uri"), redirectUri);
      if (state.hook) await state.hook();
      if (body.get("code_verifier") !== verifier || !state.tokens.has(body.get("code")!)) {
        return Response.json({ error: "invalid_grant" }, { status: 400 });
      }
      return Response.json({ id_token: state.tokens.get(body.get("code")!) });
    }
    if (address === "https://www.googleapis.com/oauth2/v3/certs") {
      state.keys++;
      return Response.json({ keys: [publicJWK] });
    }
    throw new Error("Unexpected network destination in synthetic provider test");
  });
  const runtime = await buildRuntime(configuration); runtimes.push(runtime);
  const app = buildApp(runtime.services);
  cleanup.push(() => app.close());
  const body = (extra: Record<string, unknown> = {}) => ({
    appId: "cashcast-preview", authorizationCode: "synthetic-code", codeVerifier: verifier, nonce, ...extra,
  });
  const request = (extra: Record<string, unknown> = {}, session = owner.session.sessionId) =>
    app.inject({ method: "POST", url: "/authentication/federated/google/web/link",
      headers: { authorization: `Bearer ${session}` }, payload: body(extra) });
  return { owner, other, app, runtime, database, configuration, schemaURL, schema, state, body, request,
    async secondRuntime() { const otherRuntime = await buildRuntime(configuration); runtimes.push(otherRuntime); return otherRuntime; },
  };
}

describe("registered Google web linking with real crypto and isolated PostgreSQL", { skip: testURL === undefined }, () => {
  it("uses the actual registered exchanger/verifier/composition and preserves one Human, session, Apple and Email", async () => {
    const f = await fixture();
    const result = await f.request();
    assert.equal(result.statusCode, 200);
    assert.equal(result.json().humanIdentityId, f.owner.humanIdentityId);
    assert.deepEqual(result.json().methods.federated.map((m: { provider: string }) => m.provider), ["apple", "google"]);
    assert.equal(result.json().methods.emailPassword.connected, true);
    assert.equal(f.state.exchanges, 1);
    assert.equal(f.state.keys, 1);
    for (const table of ["human_identities", "credentials", "sessions"]) {
      assert.equal(Number((await f.database.query(`SELECT COUNT(*) AS count FROM ${table}`)).rows[0]!.count), 1);
    }
    assert.equal(result.body.includes("synthetic-google-subject"), false);
    assert.equal(result.body.includes(f.state.tokens.get("synthetic-code")!), false);
    const newNonce = "s".repeat(43);
    f.state.tokens.set("signin-code", await token({ nonce: newNonce }));
    const signIn = await f.app.inject({ method: "POST", url: "/authentication/federated/google/web",
      payload: f.body({ authorizationCode: "signin-code", nonce: newNonce }) });
    assert.equal(signIn.statusCode, 200);
    assert.equal(signIn.json().session.humanIdentityId, f.owner.humanIdentityId);
  });

  for (const variant of ["legacy-audience", "other-audience", "issuer", "nonce", "expired", "signature"] as const) {
    it(`rejects ${variant} proof through the real scoped verifier`, async () => {
      const f = await fixture();
      f.state.tokens.set("synthetic-code", await token({
        ...(variant === "legacy-audience" ? { audience: "legacy-google-native-fixture" } : {}),
        ...(variant === "other-audience" ? { audience: "other-preview-client" } : {}),
        ...(variant === "issuer" ? { issuer: "https://evil.example.test" } : {}),
        ...(variant === "nonce" ? { nonce: "w".repeat(43) } : {}),
        ...(variant === "expired" ? { expired: true } : {}),
        ...(variant === "signature" ? { wrongSignature: true } : {}),
      }));
      assert.equal((await f.request()).statusCode, 401);
      assert.equal(Number((await f.database.query("SELECT COUNT(*) AS count FROM federated_identities WHERE provider = 'google'")).rows[0]!.count), 0);
    });
  }

  for (const variant of ["bad-code", "wrong-pkce"] as const) {
    it(`rejects ${variant} at the reused provider exchange before token verification`, async () => {
      const f = await fixture();
      const result = await f.request(variant === "bad-code" ? { authorizationCode: "rejected-code" } : { codeVerifier: "z".repeat(43) });
      assert.equal(result.statusCode, 401);
      assert.equal(result.json().error.code, "GOOGLE_AUTHORIZATION_CODE_INVALID");
      assert.equal(f.state.keys, 0);
    });
  }

  it("composes linking only for CashCast preview, retaining global audiences and other app behavior", async () => {
    const f = await fixture();
    assert.ok(f.runtime.services.webAuthenticationApps!.get("cashcast-preview")!.googleLink);
    assert.equal(f.runtime.services.webAuthenticationApps!.get("other-preview")!.googleLink, undefined);
    assert.equal(f.runtime.services.webAuthenticationApps!.get("cashcast-web")!.googleLink, undefined);
    assert.deepEqual(f.configuration.GOOGLE_CLIENT_IDS, ["legacy-google-native-fixture"]);
    for (const appId of ["other-preview", "cashcast-web", "coco-web"]) assert.equal((await f.request({ appId })).statusCode, 503);
    assert.equal(f.state.exchanges, 0);
    const generic = await f.app.inject({ method: "POST", url: "/authentication/federated/google/link",
      headers: { authorization: `Bearer ${f.owner.session.sessionId}` },
      payload: { identityToken: f.state.tokens.get("synthetic-code"), nonce } });
    assert.equal(generic.statusCode, 401);
  });

  it("rejects a reused Google nonce with durable PostgreSQL state across independent runtimes", async () => {
    const f = await fixture();
    const other = await f.secondRuntime();
    assert.equal((await f.request()).statusCode, 200);
    await assert.rejects(other.services.webAuthenticationApps!.get("cashcast-preview")!.googleLink!
      .execute(SessionId.from(f.owner.session.sessionId), { authorizationCode: "synthetic-code", codeVerifier: verifier, nonce }),
      (error: unknown) => (error as { code?: string }).code === "CREDENTIAL_REPLAYED");
  });

  it("does not enable the scoped mutation without durable PostgreSQL transactions", async () => {
    const f = await fixture();
    const memory = await buildRuntime({ ...f.configuration, REPOSITORY_MODE: "memory" });
    try {
      assert.equal(memory.services.webAuthenticationApps!.get("cashcast-preview")!.googleLink, undefined);
      assert.ok(memory.services.webAuthenticationApps!.get("cashcast-preview")!.google);
    } finally { await memory.close(); }
  });

  it("serializes fresh concurrent same-account links across independent connection pools", async () => {
    const f = await fixture();
    const other = await f.secondRuntime();
    f.state.tokens.set("code-a", await token({ nonce: "a".repeat(43) }));
    f.state.tokens.set("code-b", await token({ nonce: "b".repeat(43) }));
    const results = await Promise.all([
      f.runtime.services.webAuthenticationApps!.get("cashcast-preview")!.googleLink!.execute(SessionId.from(f.owner.session.sessionId),
        { authorizationCode: "code-a", codeVerifier: verifier, nonce: "a".repeat(43) }),
      other.services.webAuthenticationApps!.get("cashcast-preview")!.googleLink!.execute(SessionId.from(f.owner.session.sessionId),
        { authorizationCode: "code-b", codeVerifier: verifier, nonce: "b".repeat(43) }),
    ]);
    assert.deepEqual(results.map(r => r.outcome).sort(), ["already_linked", "linked"]);
    assert.equal(Number((await f.database.query("SELECT COUNT(*) AS count FROM federated_identities WHERE provider = 'google'")).rows[0]!.count), 1);
    assert.equal(Number((await f.database.query("SELECT COUNT(*) AS count FROM sessions")).rows[0]!.count), 1);
  });

  it("allows only one owner when two approved accounts concurrently prove the same Google subject", async () => {
    const f = await fixture(true);
    const other = await f.secondRuntime();
    f.state.tokens.set("code-a", await token({ nonce: "a".repeat(43) }));
    f.state.tokens.set("code-b", await token({ nonce: "b".repeat(43) }));
    const results = await Promise.allSettled([
      f.runtime.services.webAuthenticationApps!.get("cashcast-preview")!.googleLink!.execute(SessionId.from(f.owner.session.sessionId),
        { authorizationCode: "code-a", codeVerifier: verifier, nonce: "a".repeat(43) }),
      other.services.webAuthenticationApps!.get("cashcast-preview")!.googleLink!.execute(SessionId.from(f.other!.session.sessionId),
        { authorizationCode: "code-b", codeVerifier: verifier, nonce: "b".repeat(43) }),
    ]);
    assert.equal(results.filter(r => r.status === "fulfilled").length, 1);
    const failure = results.find(r => r.status === "rejected")!;
    assert.equal((failure as PromiseRejectedResult).reason.code, "FEDERATED_IDENTITY_LINK_CONFLICT");
    assert.equal(Number((await f.database.query("SELECT COUNT(*) AS count FROM human_identities WHERE status = 'active'")).rows[0]!.count), 2);
    assert.equal(Number((await f.database.query("SELECT COUNT(*) AS count FROM federated_identities WHERE provider = 'google'")).rows[0]!.count), 1);
  });

  it("rejects logout committed by another runtime while the provider exchange is pending", async () => {
    const f = await fixture();
    const other = await f.secondRuntime();
    let opened!: () => void; let release!: () => void;
    const reached = new Promise<void>(resolve => { opened = resolve; });
    const proceed = new Promise<void>(resolve => { release = resolve; });
    f.state.hook = async () => { opened(); await proceed; };
    const linking = f.request();
    await reached;
    await other.services.logout.execute(SessionId.from(f.owner.session.sessionId));
    release();
    assert.equal((await linking).statusCode, 401);
    assert.equal((await f.database.query("SELECT status FROM sessions WHERE id = $1", [f.owner.session.sessionId])).rows[0]!.status, "revoked");
    assert.equal(Number((await f.database.query("SELECT COUNT(*) AS count FROM federated_identities WHERE provider = 'google'")).rows[0]!.count), 0);
  });

  it("waits for a conflicting revocation row lock and rejects the newly revoked session before exchange", async () => {
    const f = await fixture();
    const locker = new PostgresDatabase(f.schemaURL);
    let linking: ReturnType<typeof f.request> | undefined;
    try {
      await locker.withTransaction(async () => {
        await locker.query("SELECT id FROM sessions WHERE id = $1 FOR UPDATE", [f.owner.session.sessionId]);
        await locker.query("UPDATE sessions SET status = 'revoked' WHERE id = $1", [f.owner.session.sessionId]);
        linking = f.request();
        const deadline = Date.now() + 3000;
        let blocked = false;
        while (Date.now() < deadline) {
          const waiting = await f.database.query("SELECT COUNT(*) AS count FROM pg_stat_activity WHERE application_name = $1 AND wait_event_type = 'Lock'", [f.schema]);
          if (Number(waiting.rows[0]!.count) > 0) { blocked = true; break; }
          await delay(10);
        }
        assert.equal(blocked, true, "Scoped preflight must wait for the session row lock");
        assert.equal(f.state.exchanges, 0);
      });
      assert.equal((await linking!).statusCode, 401);
      assert.equal(f.state.exchanges, 0);
      assert.equal((await f.database.query("SELECT status FROM sessions WHERE id = $1", [f.owner.session.sessionId])).rows[0]!.status, "revoked");
    } finally { await locker.close(); }
  });
});
