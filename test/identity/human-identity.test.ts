import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { InvalidHumanIdentityTransitionError } from "../../src/identity/domain/errors.js";
import { HumanIdentity } from "../../src/identity/domain/human-identity.js";
import { HumanIdentityId } from "../../src/identity/domain/human-identity-id.js";
import { FixedClock, FixedIdentityIdGenerator } from "./test-doubles.js";

const createdAt = new Date("2026-01-01T00:00:00.000Z");
const changedAt = new Date("2026-01-02T00:00:00.000Z");

function createIdentity(): {
  identity: HumanIdentity;
  clock: FixedClock;
} {
  const clock = new FixedClock(createdAt);
  const identity = HumanIdentity.create(
    new FixedIdentityIdGenerator("human_01"),
    clock,
  );
  clock.set(changedAt);
  return { identity, clock };
}

describe("HumanIdentity", () => {
  it("starts active with its generated ID and creation time", () => {
    const { identity } = createIdentity();

    assert.equal(identity.id.value, "human_01");
    assert.equal(identity.status, "active");
    assert.deepEqual(identity.createdAt, createdAt);
    assert.deepEqual(identity.updatedAt, createdAt);
  });

  it("uses stable opaque ID value semantics and rejects empty IDs", () => {
    const first = HumanIdentityId.from("human_01");
    const same = HumanIdentityId.from("human_01");
    const other = HumanIdentityId.from("human_02");

    assert.equal(first.equals(same), true);
    assert.equal(first.equals(other), false);
    assert.throws(() => HumanIdentityId.from("  "), /must not be empty/);
  });

  it("suspends an active identity and advances updatedAt", () => {
    const { identity, clock } = createIdentity();

    identity.suspend(clock);

    assert.equal(identity.status, "suspended");
    assert.deepEqual(identity.createdAt, createdAt);
    assert.deepEqual(identity.updatedAt, changedAt);
  });

  it("reactivates a suspended identity and advances updatedAt", () => {
    const { identity, clock } = createIdentity();
    identity.suspend(clock);
    const reactivatedAt = new Date("2026-01-03T00:00:00.000Z");
    clock.set(reactivatedAt);

    identity.reactivate(clock);

    assert.equal(identity.status, "active");
    assert.deepEqual(identity.updatedAt, reactivatedAt);
  });

  it("retires active and suspended identities", () => {
    const active = createIdentity();
    active.identity.retire(active.clock);
    assert.equal(active.identity.status, "retired");
    assert.deepEqual(active.identity.updatedAt, changedAt);

    const suspended = createIdentity();
    suspended.identity.suspend(suspended.clock);
    const retiredAt = new Date("2026-01-03T00:00:00.000Z");
    suspended.clock.set(retiredAt);
    suspended.identity.retire(suspended.clock);
    assert.equal(suspended.identity.status, "retired");
    assert.deepEqual(suspended.identity.updatedAt, retiredAt);
  });

  it("treats transitions to the current state as idempotent", () => {
    const suspended = createIdentity();
    suspended.identity.suspend(suspended.clock);
    const suspendedUpdatedAt = suspended.identity.updatedAt;
    suspended.clock.set(new Date("2026-01-04T00:00:00.000Z"));
    suspended.identity.suspend(suspended.clock);
    assert.deepEqual(suspended.identity.updatedAt, suspendedUpdatedAt);

    const active = createIdentity();
    active.identity.reactivate(active.clock);
    assert.deepEqual(active.identity.updatedAt, createdAt);

    active.identity.retire(active.clock);
    const retiredUpdatedAt = active.identity.updatedAt;
    active.clock.set(new Date("2026-01-04T00:00:00.000Z"));
    active.identity.retire(active.clock);
    assert.deepEqual(active.identity.updatedAt, retiredUpdatedAt);
  });

  it("does not allow a retired identity to be suspended", () => {
    const { identity, clock } = createIdentity();
    identity.retire(clock);

    assert.throws(
      () => identity.suspend(clock),
      (error: unknown) =>
        error instanceof InvalidHumanIdentityTransitionError &&
        error.from === "retired" &&
        error.to === "suspended",
    );
  });

  it("does not allow a retired identity to be reactivated", () => {
    const { identity, clock } = createIdentity();
    identity.retire(clock);

    assert.throws(
      () => identity.reactivate(clock),
      (error: unknown) =>
        error instanceof InvalidHumanIdentityTransitionError &&
        error.from === "retired" &&
        error.to === "active",
    );
  });

  it("does not expose mutable timestamp state", () => {
    const { identity } = createIdentity();
    const exposedCreatedAt = identity.createdAt;
    exposedCreatedAt.setUTCFullYear(2030);
    const snapshot = identity.snapshot();
    snapshot.updatedAt.setUTCFullYear(2030);

    assert.deepEqual(identity.createdAt, createdAt);
    assert.deepEqual(identity.updatedAt, createdAt);
  });
});
