import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { HumanIdentityId } from "../../src/identity/domain/human-identity-id.js";
import { InMemorySessionRepository } from "../../src/sessions/adapters/in-memory-session-repository.js";
import { CreateSession, Logout, RenewSession, SessionRenewalError, ValidateSession } from "../../src/sessions/application/use-cases.js";
import { Session } from "../../src/sessions/domain/session.js";
import { SessionId } from "../../src/sessions/domain/session-id.js";
import { MutableClock, RenewalTokens, SessionIds } from "../operational/test-doubles.js";

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
      "renewal-hash",
      300,
      clock,
    );
    session.revoke();
    session.revoke();
    assert.equal(session.status, "revoked");
  });

  it("rotates a valid renewal credential into a new access and renewal session", async () => {
    const clock = new MutableClock(new Date("2026-01-01T00:00:00Z"));
    const repository = new InMemorySessionRepository();
    const tokens = new RenewalTokens();
    const create = new CreateSession(repository, new SessionIds(), clock, 60, tokens, 300);
    const original = await create.execute(HumanIdentityId.from("identity-1"));
    clock.set(new Date("2026-01-01T00:02:00Z"));

    const renewed = await new RenewSession(
      repository,
      create,
      tokens,
      clock,
      async (work) => work(),
    ).execute(original.renewalToken);

    assert.notEqual(renewed.sessionId, original.sessionId);
    assert.notEqual(renewed.renewalToken, original.renewalToken);
    assert.equal(renewed.humanIdentityId, original.humanIdentityId);
    assert.deepEqual(
      await new ValidateSession(repository, clock).execute(SessionId.from(original.sessionId)),
      { outcome: "revoked" },
    );
  });

  it("rejects reuse, revocation, and expiry of renewal credentials", async () => {
    const clock = new MutableClock(new Date("2026-01-01T00:00:00Z"));
    const repository = new InMemorySessionRepository();
    const tokens = new RenewalTokens();
    const create = new CreateSession(repository, new SessionIds(), clock, 60, tokens, 300);
    const renewal = new RenewSession(repository, create, tokens, clock, async (work) => work());
    const rotated = await create.execute(HumanIdentityId.from("identity-1"));
    await renewal.execute(rotated.renewalToken);
    await assert.rejects(
      renewal.execute(rotated.renewalToken),
      (error) => error instanceof SessionRenewalError && error.reason === "revoked",
    );

    const expired = await create.execute(HumanIdentityId.from("identity-1"));
    clock.set(new Date("2026-01-01T00:06:00Z"));
    await assert.rejects(
      renewal.execute(expired.renewalToken),
      (error) => error instanceof SessionRenewalError && error.reason === "expired",
    );
  });
});
