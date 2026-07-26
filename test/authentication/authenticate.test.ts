import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { Authenticate } from "../../src/authentication/application/authenticate.js";
import { InMemoryEmailCredentialRepository } from "../../src/authentication/credentials/adapters/in-memory-email-credential-repository.js";
import { CreateEmailCredential, DisableEmailCredential } from "../../src/authentication/credentials/application/use-cases.js";
import { BaselinePasswordPolicy } from "../../src/authentication/credentials/domain/password-policy.js";
import { EmailCredentialId } from "../../src/authentication/credentials/domain/email-credential-id.js";
import { InMemoryHumanIdentityRepository } from "../../src/identity/adapters/in-memory-human-identity-repository.js";
import { CreateHumanIdentity, SuspendHumanIdentity } from "../../src/identity/application/use-cases.js";
import { CredentialIds, DeterministicPasswords, IdentityIds, MutableClock } from "../operational/test-doubles.js";

describe("Authenticate", () => {
  async function fixture() {
    const clock = new MutableClock(new Date("2026-01-01T00:00:00Z"));
    const identities = new InMemoryHumanIdentityRepository();
    const credentials = new InMemoryEmailCredentialRepository();
    const passwords = new DeterministicPasswords();
    const identity = await new CreateHumanIdentity(
      identities,
      new IdentityIds(),
      clock,
    ).execute();
    const credential = await new CreateEmailCredential(
      credentials,
      new CredentialIds(),
      clock,
      new BaselinePasswordPolicy(),
      passwords,
    ).execute({
      humanIdentityId: identity.id,
      email: "Person@EXAMPLE.com",
      plaintextPassword: "correct-password",
    });
    return {
      authenticate: new Authenticate(credentials, identities, passwords),
      clock,
      identities,
      credentials,
      identity,
      credential,
    };
  }

  it("normalizes email and returns the Human Identity on success", async () => {
    const { authenticate } = await fixture();
    const result = await authenticate.execute({
      email: " Person@example.COM ",
      plaintextPassword: "correct-password",
    });
    assert.equal(result.outcome, "success");
    if (result.outcome === "success") {
      assert.equal(result.humanIdentityId.value, "identity-1");
    }
  });

  it("does not distinguish unknown email, malformed email, or wrong password", async () => {
    const { authenticate } = await fixture();
    for (const input of [
      { email: "missing@example.com", plaintextPassword: "correct-password" },
      { email: "not-an-email", plaintextPassword: "correct-password" },
      { email: "Person@example.com", plaintextPassword: "wrong-password" },
    ]) {
      assert.deepEqual(await authenticate.execute(input), {
        outcome: "invalid_credentials",
      });
    }
  });

  it("distinguishes unavailable credentials and identities internally", async () => {
    const first = await fixture();
    await new DisableEmailCredential(first.credentials, first.clock).execute(
      EmailCredentialId.from(first.credential.id),
    );
    assert.deepEqual(
      await first.authenticate.execute({
        email: "Person@example.com",
        plaintextPassword: "correct-password",
      }),
      { outcome: "credential_unavailable" },
    );

    const second = await fixture();
    await new SuspendHumanIdentity(second.identities, second.clock).execute(
      second.identity.id,
    );
    assert.deepEqual(
      await second.authenticate.execute({
        email: "Person@example.com",
        plaintextPassword: "correct-password",
      }),
      { outcome: "identity_unavailable" },
    );
  });
});
