import assert from "node:assert/strict";
import { after, before, beforeEach, describe, it } from "node:test";

import { EmailCredential } from "../../src/authentication/credentials/domain/email-credential.js";
import { EmailCredentialId } from "../../src/authentication/credentials/domain/email-credential-id.js";
import { EmailAlreadyInUseError } from "../../src/authentication/credentials/domain/errors.js";
import { NormalizedEmail } from "../../src/authentication/credentials/domain/email.js";
import { PasswordHash } from "../../src/authentication/credentials/domain/password.js";
import { HumanIdentity } from "../../src/identity/domain/human-identity.js";
import { HumanIdentityId } from "../../src/identity/domain/human-identity-id.js";
import { PostgresDatabase } from "../../src/infrastructure/postgres/database.js";
import { runMigrations } from "../../src/infrastructure/postgres/migrations.js";
import { PostgresEmailCredentialRepository } from "../../src/infrastructure/postgres/postgres-email-credential-repository.js";
import { PostgresHumanIdentityRepository } from "../../src/infrastructure/postgres/postgres-human-identity-repository.js";
import { PostgresSessionRepository } from "../../src/infrastructure/postgres/postgres-session-repository.js";
import { Session } from "../../src/sessions/domain/session.js";
import { SessionId } from "../../src/sessions/domain/session-id.js";
import { buildRuntime } from "../../src/api/services.js";
import { loadConfig } from "../../src/config/env.js";

const testDatabaseUrl = process.env.POSTGRES_TEST_DATABASE_URL;

describe(
  "PostgreSQL persistence",
  { skip: testDatabaseUrl === undefined, concurrency: false },
  () => {
    let database: PostgresDatabase;
    let identities: PostgresHumanIdentityRepository;
    let credentials: PostgresEmailCredentialRepository;
    let sessions: PostgresSessionRepository;

    before(async () => {
      database = new PostgresDatabase(testDatabaseUrl!);
      await runMigrations(database);
      identities = new PostgresHumanIdentityRepository(database);
      credentials = new PostgresEmailCredentialRepository(database);
      sessions = new PostgresSessionRepository(database);
    });

    beforeEach(async () => {
      await database.query(
        "TRUNCATE sessions, credentials, human_identities CASCADE",
      );
    });

    after(async () => {
      await database.close();
    });

    it("runs versioned migrations repeatedly without changing applied state", async () => {
      await runMigrations(database);
      await runMigrations(database);
      const result = await database.query(
        "SELECT version FROM schema_migrations ORDER BY version",
      );
      assert.deepEqual(result.rows.map((row) => row.version), ["001"]);
    });

    it("starts and closes a PostgreSQL runtime after a connectivity check", async () => {
      const runtime = await buildRuntime(
        loadConfig({
          REPOSITORY_MODE: "postgres",
          DATABASE_URL: testDatabaseUrl,
        }),
      );
      assert.equal(await runtime.databaseHealth.check(), "connected");
      await runtime.close();
    });

    it("persists and reconstitutes all three aggregates", async () => {
      const identity = identityAggregate();
      await identities.save(identity);
      const credential = credentialAggregate(identity.id);
      await credentials.save(credential);
      const session = sessionAggregate(identity.id);
      await sessions.save(session);

      assert.deepEqual(
        (await identities.findById(identity.id))?.snapshot(),
        identity.snapshot(),
      );
      assert.equal(
        (
          await credentials.findByNormalizedEmail(
            NormalizedEmail.from("Person@example.com"),
          )
        )?.id.value,
        credential.id.value,
      );
      assert.deepEqual(
        (await sessions.findById(session.id))?.snapshot(),
        session.snapshot(),
      );
    });

    it("matches credential uniqueness and retired-email reuse semantics", async () => {
      const identity = identityAggregate();
      await identities.save(identity);
      const first = credentialAggregate(identity.id);
      await credentials.save(first);
      await assert.rejects(
        credentials.save(
          credentialAggregate(
            identity.id,
            "22222222-2222-4222-8222-222222222222",
          ),
        ),
        EmailAlreadyInUseError,
      );
      first.retire(fixedClock);
      await credentials.save(first);
      await credentials.save(
        credentialAggregate(
          identity.id,
          "22222222-2222-4222-8222-222222222222",
        ),
      );
    });

    it("rolls back every repository write when a transaction fails", async () => {
      const identity = identityAggregate();
      await assert.rejects(
        database.withTransaction(async () => {
          await identities.save(identity);
          await credentials.save(credentialAggregate(identity.id));
          await sessions.save(sessionAggregate(identity.id));
          throw new Error("forced registration failure");
        }),
      );
      assert.equal(await identities.findById(identity.id), null);
      assert.equal(
        await credentials.findById(
          EmailCredentialId.from("11111111-1111-4111-8111-111111111111"),
        ),
        null,
      );
      assert.equal(
        await sessions.findById(
          SessionId.from("33333333-3333-4333-8333-333333333333"),
        ),
        null,
      );
    });

    it("revokes sessions idempotently with repository parity", async () => {
      const identity = identityAggregate();
      await identities.save(identity);
      const session = sessionAggregate(identity.id);
      await sessions.save(session);
      await sessions.revoke(session.id);
      await sessions.revoke(session.id);
      assert.equal((await sessions.findById(session.id))?.status, "revoked");
      assert.equal(await sessions.findActiveById(session.id), null);
    });
  },
);

const fixedClock = {
  now: () => new Date("2026-01-01T00:00:00.000Z"),
};

function identityAggregate(): HumanIdentity {
  return HumanIdentity.reconstitute({
    id: HumanIdentityId.from("00000000-0000-4000-8000-000000000001"),
    status: "active",
    createdAt: fixedClock.now(),
    updatedAt: fixedClock.now(),
  });
}

function credentialAggregate(
  humanIdentityId: HumanIdentityId,
  id = "11111111-1111-4111-8111-111111111111",
): EmailCredential {
  return EmailCredential.reconstitute({
    id: EmailCredentialId.from(id),
    humanIdentityId,
    email: NormalizedEmail.from("Person@example.com"),
    passwordHash: PasswordHash.from("test:correct-password"),
    status: "active",
    createdAt: fixedClock.now(),
    updatedAt: fixedClock.now(),
  });
}

function sessionAggregate(humanIdentityId: HumanIdentityId): Session {
  return Session.reconstitute({
    id: SessionId.from("33333333-3333-4333-8333-333333333333"),
    humanIdentityId,
    createdAt: fixedClock.now(),
    lastAccessedAt: fixedClock.now(),
    expiresAt: new Date("2026-01-02T00:00:00.000Z"),
    status: "active",
  });
}
