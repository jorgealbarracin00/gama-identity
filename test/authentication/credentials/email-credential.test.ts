import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { EmailCredential } from "../../../src/authentication/credentials/domain/email-credential.js";
import {
  CredentialUnavailableForAuthenticationError,
  InvalidEmailCredentialTransitionError,
  RetiredEmailCredentialMutationError,
} from "../../../src/authentication/credentials/domain/errors.js";
import { NormalizedEmail } from "../../../src/authentication/credentials/domain/email.js";
import { PasswordHash } from "../../../src/authentication/credentials/domain/password.js";
import { HumanIdentityId } from "../../../src/identity/domain/human-identity-id.js";
import {
  DeterministicPasswordOperations,
  FixedClock,
  FixedEmailCredentialIdGenerator,
} from "./test-doubles.js";

const createdAt = new Date("2026-02-01T00:00:00.000Z");
const changedAt = new Date("2026-02-02T00:00:00.000Z");

function createCredential(): {
  credential: EmailCredential;
  clock: FixedClock;
} {
  const clock = new FixedClock(createdAt);
  const credential = EmailCredential.create(
    new FixedEmailCredentialIdGenerator("credential_01"),
    HumanIdentityId.from("human_01"),
    NormalizedEmail.from("Person@Example.COM"),
    PasswordHash.from("test-hash:original password"),
    clock,
  );
  clock.set(changedAt);
  return { credential, clock };
}

describe("EmailCredential", () => {
  it("starts active and belongs to exactly one Human Identity", () => {
    const { credential } = createCredential();

    assert.equal(credential.id.value, "credential_01");
    assert.equal(credential.humanIdentityId.value, "human_01");
    assert.equal(credential.email.value, "Person@example.com");
    assert.equal(credential.status, "active");
    assert.deepEqual(credential.createdAt, createdAt);
    assert.deepEqual(credential.updatedAt, createdAt);
  });

  it("disables, enables, and retires with transition timestamps", () => {
    const { credential, clock } = createCredential();
    credential.disable(clock);
    assert.equal(credential.status, "disabled");
    assert.deepEqual(credential.updatedAt, changedAt);

    const enabledAt = new Date("2026-02-03T00:00:00.000Z");
    clock.set(enabledAt);
    credential.enable(clock);
    assert.equal(credential.status, "active");
    assert.deepEqual(credential.updatedAt, enabledAt);

    const retiredAt = new Date("2026-02-04T00:00:00.000Z");
    clock.set(retiredAt);
    credential.retire(clock);
    assert.equal(credential.status, "retired");
    assert.deepEqual(credential.updatedAt, retiredAt);
  });

  it("allows retirement from disabled", () => {
    const { credential, clock } = createCredential();
    credential.disable(clock);
    clock.set(new Date("2026-02-03T00:00:00.000Z"));
    credential.retire(clock);

    assert.equal(credential.status, "retired");
  });

  it("treats requested current states as idempotent", () => {
    const active = createCredential();
    active.credential.enable(active.clock);
    assert.deepEqual(active.credential.updatedAt, createdAt);

    const disabled = createCredential();
    disabled.credential.disable(disabled.clock);
    const disabledAt = disabled.credential.updatedAt;
    disabled.clock.set(new Date("2026-02-05T00:00:00.000Z"));
    disabled.credential.disable(disabled.clock);
    assert.deepEqual(disabled.credential.updatedAt, disabledAt);

    disabled.credential.retire(disabled.clock);
    const retiredAt = disabled.credential.updatedAt;
    disabled.clock.set(new Date("2026-02-06T00:00:00.000Z"));
    disabled.credential.retire(disabled.clock);
    assert.deepEqual(disabled.credential.updatedAt, retiredAt);
  });

  it("rejects enabling and disabling after retirement", () => {
    const { credential, clock } = createCredential();
    credential.retire(clock);

    assert.throws(
      () => credential.enable(clock),
      InvalidEmailCredentialTransitionError,
    );
    assert.throws(
      () => credential.disable(clock),
      InvalidEmailCredentialTransitionError,
    );
  });

  it("replaces the password and advances updatedAt without exposing its hash", async () => {
    const { credential, clock } = createCredential();
    const passwordOperations = new DeterministicPasswordOperations();

    credential.replacePassword(
      PasswordHash.from("test-hash:new password value"),
      clock,
    );

    assert.deepEqual(credential.updatedAt, changedAt);
    assert.equal(
      await credential.verifyPassword(
        "new password value",
        passwordOperations,
      ),
      true,
    );
    assert.equal(
      await credential.verifyPassword("original password", passwordOperations),
      false,
    );
    assert.equal("passwordHash" in credential, false);
  });

  it("does not allow password replacement after retirement", () => {
    const { credential, clock } = createCredential();
    credential.retire(clock);

    assert.throws(
      () => credential.replacePassword(PasswordHash.from("replacement"), clock),
      RetiredEmailCredentialMutationError,
    );
  });

  it("permits password verification only while active", async () => {
    const active = createCredential();
    const passwordOperations = new DeterministicPasswordOperations();
    assert.equal(active.credential.isEligibleForAuthentication(), true);
    assert.equal(
      await active.credential.verifyPassword(
        "original password",
        passwordOperations,
      ),
      true,
    );

    active.credential.disable(active.clock);
    assert.equal(active.credential.isEligibleForAuthentication(), false);
    await assert.rejects(
      () =>
        active.credential.verifyPassword(
          "original password",
          passwordOperations,
        ),
      CredentialUnavailableForAuthenticationError,
    );

    active.credential.retire(active.clock);
    assert.throws(
      () => active.credential.assertEligibleForAuthentication(),
      CredentialUnavailableForAuthenticationError,
    );
  });

  it("defensively copies timestamps and aggregate state", () => {
    const { credential, clock } = createCredential();
    const exposedTime = credential.createdAt;
    exposedTime.setUTCFullYear(2030);
    const copy = credential.copy();
    copy.disable(clock);

    assert.deepEqual(credential.createdAt, createdAt);
    assert.equal(credential.status, "active");
    assert.equal(copy.status, "disabled");
  });
});
