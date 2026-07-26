import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { HumanIdentityId } from "../../src/identity/domain/human-identity-id.js";
import { InMemorySessionRepository } from "../../src/sessions/adapters/in-memory-session-repository.js";
import { CreateSession, Logout, ValidateSession } from "../../src/sessions/application/use-cases.js";
import { Session } from "../../src/sessions/domain/session.js";
import { SessionId } from "../../src/sessions/domain/session-id.js";
import { MutableClock, SessionIds } from "../operational/test-doubles.js";

describe("Session lifecycle", () => {
  it("creates, touches, expires, and reports explicit validation results", async () => {
    const clock = new MutableClock(new Date("2026-01-01T00:00:00Z"));
    const repository = new InMemorySessionRepository();
    const created = await new CreateSession(
      repository,
      new SessionIds(),
      clock,
      60,
    ).execute(HumanIdentityId.from("identity-1"));

    clock.set(new Date("2026-01-01T00:00:30Z"));
    const active = await new ValidateSession(repository, clock).execute(
      SessionId.from(created.sessionId),
    );
    assert.equal(active.outcome, "authenticated");
    if (active.outcome === "authenticated") {
      assert.equal(active.lastAccessedAt, "2026-01-01T00:00:30.000Z");
    }

    clock.set(new Date("2026-01-01T00:01:00Z"));
    assert.deepEqual(
      await new ValidateSession(repository, clock).execute(
        SessionId.from(created.sessionId),
      ),
      { outcome: "expired" },
    );
  });

  it("revokes idempotently and distinguishes revoked from invalid", async () => {
    const clock = new MutableClock(new Date("2026-01-01T00:00:00Z"));
    const repository = new InMemorySessionRepository();
    const created = await new CreateSession(
      repository,
      new SessionIds(),
      clock,
      60,
    ).execute(HumanIdentityId.from("identity-1"));
    const id = SessionId.from(created.sessionId);
    const logout = new Logout(repository);
    await logout.execute(id);
    await logout.execute(id);

    assert.deepEqual(await new ValidateSession(repository, clock).execute(id), {
      outcome: "revoked",
    });
    assert.deepEqual(
      await new ValidateSession(repository, clock).execute(
        SessionId.from("unknown"),
      ),
      { outcome: "invalid" },
    );
  });

  it("keeps session lifecycle independent from Human Identity", () => {
    const clock = new MutableClock(new Date("2026-01-01T00:00:00Z"));
    const session = Session.create(
      new SessionIds(),
      HumanIdentityId.from("identity-1"),
      60,
      clock,
    );
    session.revoke();
    session.revoke();
    assert.equal(session.status, "revoked");
  });
});
