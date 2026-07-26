import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { NormalizedEmail } from "../../src/authentication/credentials/domain/email.js";
import { InvalidLoginError } from "../../src/operations/application/errors.js";
import { SessionId } from "../../src/sessions/domain/session-id.js";
import { buildTestServices } from "../operational/test-doubles.js";

describe("registration and login orchestration", () => {
  it("registers identity, credential, authentication, and session in order", async () => {
    const { services, identities, credentials, sessions } = buildTestServices();
    const result = await services.register.execute({
      email: "Retail.User@EXAMPLE.com",
      password: "correct-password",
    });

    assert.equal(result.humanIdentityId, "identity-1");
    assert.equal(result.session.sessionId, "session-1");
    assert.ok(
      await identities.findById(
        (await credentials.findByNormalizedEmail(
          NormalizedEmail.from("Retail.User@example.com"),
        ))!.humanIdentityId,
      ),
    );
    assert.ok(
      await sessions.findActiveById(SessionId.from(result.session.sessionId)),
    );
  });

  it("logs in without returning credentials or aggregates", async () => {
    const { services } = buildTestServices();
    await services.register.execute({
      email: "person@example.com",
      password: "correct-password",
    });
    const session = await services.login.execute({
      email: "person@example.com",
      password: "correct-password",
    });
    assert.equal(session.sessionId, "session-2");
    assert.deepEqual(Object.keys(session).sort(), [
      "createdAt",
      "expiresAt",
      "humanIdentityId",
      "lastAccessedAt",
      "sessionId",
    ]);
  });

  it("presents every authentication failure as an invalid login", async () => {
    const { services } = buildTestServices();
    await assert.rejects(
      services.login.execute({
        email: "missing@example.com",
        password: "correct-password",
      }),
      InvalidLoginError,
    );
  });

  it("compensates the newly created identity when registration conflicts", async () => {
    const { services, identities } = buildTestServices();
    await services.register.execute({
      email: "person@example.com",
      password: "correct-password",
    });
    await assert.rejects(
      services.register.execute({
        email: "person@example.com",
        password: "another-password",
      }),
    );
    assert.equal(
      await identities.findById(
        (await import("../../src/identity/domain/human-identity-id.js"))
          .HumanIdentityId.from("identity-2"),
      ),
      null,
    );
  });
});
