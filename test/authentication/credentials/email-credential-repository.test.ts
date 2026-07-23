import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";

import { EmailCredential } from "../../../src/authentication/credentials/domain/email-credential.js";
import { EmailCredentialId } from "../../../src/authentication/credentials/domain/email-credential-id.js";
import { EmailAlreadyInUseError } from "../../../src/authentication/credentials/domain/errors.js";
import { NormalizedEmail } from "../../../src/authentication/credentials/domain/email.js";
import { PasswordHash } from "../../../src/authentication/credentials/domain/password.js";
import { HumanIdentityId } from "../../../src/identity/domain/human-identity-id.js";
import { InMemoryEmailCredentialRepository } from "./in-memory-email-credential-repository.js";
import {
  FixedClock,
  FixedEmailCredentialIdGenerator,
} from "./test-doubles.js";

describe("InMemoryEmailCredentialRepository", () => {
  let repository: InMemoryEmailCredentialRepository;
  let clock: FixedClock;

  beforeEach(() => {
    repository = new InMemoryEmailCredentialRepository();
    clock = new FixedClock(new Date("2026-02-01T00:00:00.000Z"));
  });

  function credential(id: string, rawEmail: string): EmailCredential {
    return EmailCredential.create(
      new FixedEmailCredentialIdGenerator(id),
      HumanIdentityId.from(`owner_${id}`),
      NormalizedEmail.from(rawEmail),
      PasswordHash.from(`hash_${id}`),
      clock,
    );
  }

  it("saves and looks up complete aggregates by ID and normalized email", async () => {
    const saved = credential("credential_01", "Person@EXAMPLE.COM");
    await repository.save(saved);

    const byId = await repository.findById(
      EmailCredentialId.from("credential_01"),
    );
    const byEmail = await repository.findByNormalizedEmail(
      NormalizedEmail.from("Person@example.com"),
    );

    assert.equal(byId?.id.value, saved.id.value);
    assert.equal(byId?.humanIdentityId.value, saved.humanIdentityId.value);
    assert.equal(byEmail?.id.value, saved.id.value);
  });

  it("enforces uniqueness among non-retired credentials", async () => {
    await repository.save(credential("credential_01", "Person@EXAMPLE.COM"));

    await assert.rejects(
      () =>
        repository.save(
          credential("credential_02", "Person@example.com"),
        ),
      EmailAlreadyInUseError,
    );
  });

  it("releases normalized email uniqueness after retirement", async () => {
    const retired = credential("credential_01", "Person@example.com");
    await repository.save(retired);
    clock.set(new Date("2026-02-02T00:00:00.000Z"));
    retired.retire(clock);
    await repository.save(retired);

    assert.equal(
      await repository.findByNormalizedEmail(
        NormalizedEmail.from("Person@example.com"),
      ),
      null,
    );

    const replacement = credential("credential_02", "Person@EXAMPLE.COM");
    await repository.save(replacement);
    const found = await repository.findByNormalizedEmail(replacement.email);
    assert.equal(found?.id.value, "credential_02");
  });

  it("returns isolated aggregate copies", async () => {
    const saved = credential("credential_01", "person@example.com");
    await repository.save(saved);

    const firstRead = await repository.findById(saved.id);
    assert.notEqual(firstRead, saved);
    assert.ok(firstRead);
    firstRead.disable(clock);

    const secondRead = await repository.findById(saved.id);
    assert.equal(secondRead?.status, "active");
    assert.notEqual(secondRead, firstRead);
  });

  it("returns null for unknown IDs and emails", async () => {
    assert.equal(
      await repository.findById(EmailCredentialId.from("missing")),
      null,
    );
    assert.equal(
      await repository.findByNormalizedEmail(
        NormalizedEmail.from("missing@example.com"),
      ),
      null,
    );
  });
});
