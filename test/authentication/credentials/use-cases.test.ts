import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";

import type { EmailCredentialMetadata } from "../../../src/authentication/credentials/application/credential-metadata.js";
import { EmailCredentialNotFoundError } from "../../../src/authentication/credentials/application/errors.js";
import {
  CreateEmailCredential,
  DisableEmailCredential,
  EnableEmailCredential,
  FindEmailCredentialByEmail,
  GetEmailCredential,
  ReplaceEmailCredentialPassword,
  RetireEmailCredential,
} from "../../../src/authentication/credentials/application/use-cases.js";
import { EmailCredentialId } from "../../../src/authentication/credentials/domain/email-credential-id.js";
import { EmailAlreadyInUseError } from "../../../src/authentication/credentials/domain/errors.js";
import { BaselinePasswordPolicy } from "../../../src/authentication/credentials/domain/password-policy.js";
import { HumanIdentityId } from "../../../src/identity/domain/human-identity-id.js";
import { InMemoryEmailCredentialRepository } from "./in-memory-email-credential-repository.js";
import {
  DeterministicPasswordOperations,
  FixedClock,
  FixedEmailCredentialIdGenerator,
} from "./test-doubles.js";

describe("Email Credential use cases", () => {
  const credentialId = EmailCredentialId.from("credential_01");
  const humanIdentityId = HumanIdentityId.from("human_01");
  const plaintextPassword = "simple long password";
  let repository: InMemoryEmailCredentialRepository;
  let clock: FixedClock;
  let passwordOperations: DeterministicPasswordOperations;
  let create: CreateEmailCredential;

  beforeEach(() => {
    repository = new InMemoryEmailCredentialRepository();
    clock = new FixedClock(new Date("2026-02-01T00:00:00.000Z"));
    passwordOperations = new DeterministicPasswordOperations();
    create = new CreateEmailCredential(
      repository,
      new FixedEmailCredentialIdGenerator(credentialId.value),
      clock,
      new BaselinePasswordPolicy(),
      passwordOperations,
    );
  });

  async function createCredential(): Promise<EmailCredentialMetadata> {
    return create.execute({
      humanIdentityId,
      email: "  Person@EXAMPLE.COM ",
      plaintextPassword,
    });
  }

  it("normalizes, hashes, saves, and returns safe metadata on creation", async () => {
    const result = await createCredential();

    assert.deepEqual(result, {
      id: "credential_01",
      humanIdentityId: "human_01",
      email: "Person@example.com",
      status: "active",
      createdAt: new Date("2026-02-01T00:00:00.000Z"),
      updatedAt: new Date("2026-02-01T00:00:00.000Z"),
    });
    assert.equal(passwordOperations.hashCalls, 1);
    assert.equal("passwordHash" in result, false);
    assert.equal("plaintextPassword" in result, false);

    const stored = await repository.findById(credentialId);
    assert.ok(stored);
    assert.equal(
      await stored.verifyPassword(plaintextPassword, passwordOperations),
      true,
    );
  });

  it("rejects duplicate normalized email before hashing", async () => {
    await createCredential();
    const duplicateCreator = new CreateEmailCredential(
      repository,
      new FixedEmailCredentialIdGenerator("credential_02"),
      clock,
      new BaselinePasswordPolicy(),
      passwordOperations,
    );

    await assert.rejects(
      () =>
        duplicateCreator.execute({
          humanIdentityId: HumanIdentityId.from("human_02"),
          email: "Person@example.com",
          plaintextPassword: "another long password",
        }),
      EmailAlreadyInUseError,
    );
    assert.equal(passwordOperations.hashCalls, 1);
  });

  it("gets by ID and finds by normalized email as safe metadata", async () => {
    const created = await createCredential();

    const byId = await new GetEmailCredential(repository).execute(credentialId);
    const byEmail = await new FindEmailCredentialByEmail(repository).execute(
      "Person@EXAMPLE.COM",
    );

    assert.deepEqual(byId, created);
    assert.deepEqual(byEmail, created);
    assert.equal(
      await new FindEmailCredentialByEmail(repository).execute(
        "missing@example.com",
      ),
      null,
    );
  });

  it("disables, enables, and retires while returning safe metadata", async () => {
    await createCredential();

    clock.set(new Date("2026-02-02T00:00:00.000Z"));
    const disabled = await new DisableEmailCredential(
      repository,
      clock,
    ).execute(credentialId);
    assert.equal(disabled.status, "disabled");

    clock.set(new Date("2026-02-03T00:00:00.000Z"));
    const enabled = await new EnableEmailCredential(repository, clock).execute(
      credentialId,
    );
    assert.equal(enabled.status, "active");

    clock.set(new Date("2026-02-04T00:00:00.000Z"));
    const retired = await new RetireEmailCredential(repository, clock).execute(
      credentialId,
    );
    assert.equal(retired.status, "retired");
    assert.deepEqual(
      retired.updatedAt,
      new Date("2026-02-04T00:00:00.000Z"),
    );
    assert.equal("passwordHash" in retired, false);
  });

  it("validates, hashes, and replaces a password", async () => {
    await createCredential();
    clock.set(new Date("2026-02-02T00:00:00.000Z"));

    const result = await new ReplaceEmailCredentialPassword(
      repository,
      clock,
      new BaselinePasswordPolicy(),
      passwordOperations,
    ).execute({
      credentialId,
      plaintextPassword: "replacement password",
    });

    assert.deepEqual(
      result.updatedAt,
      new Date("2026-02-02T00:00:00.000Z"),
    );
    assert.equal(passwordOperations.hashCalls, 2);
    const stored = await repository.findById(credentialId);
    assert.ok(stored);
    assert.equal(
      await stored.verifyPassword("replacement password", passwordOperations),
      true,
    );
    assert.equal(
      await stored.verifyPassword(plaintextPassword, passwordOperations),
      false,
    );
  });

  it("reports missing credentials consistently", async () => {
    const missing = EmailCredentialId.from("missing");
    const operations = [
      () => new GetEmailCredential(repository).execute(missing),
      () => new DisableEmailCredential(repository, clock).execute(missing),
      () => new EnableEmailCredential(repository, clock).execute(missing),
      () => new RetireEmailCredential(repository, clock).execute(missing),
      () =>
        new ReplaceEmailCredentialPassword(
          repository,
          clock,
          new BaselinePasswordPolicy(),
          passwordOperations,
        ).execute({
          credentialId: missing,
          plaintextPassword: "replacement password",
        }),
    ];

    for (const operation of operations) {
      await assert.rejects(operation, EmailCredentialNotFoundError);
    }
  });
});
