import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";

import { HumanIdentityNotFoundError } from "../../src/identity/application/errors.js";
import {
  CreateHumanIdentity,
  GetHumanIdentity,
  ReactivateHumanIdentity,
  RetireHumanIdentity,
  SuspendHumanIdentity,
} from "../../src/identity/application/use-cases.js";
import { HumanIdentityId } from "../../src/identity/domain/human-identity-id.js";
import {
  FixedClock,
  FixedIdentityIdGenerator,
  InMemoryHumanIdentityRepository,
} from "./test-doubles.js";

describe("Human Identity use cases", () => {
  const id = HumanIdentityId.from("human_01");
  const createdAt = new Date("2026-01-01T00:00:00.000Z");
  let repository: InMemoryHumanIdentityRepository;
  let clock: FixedClock;

  beforeEach(() => {
    repository = new InMemoryHumanIdentityRepository();
    clock = new FixedClock(createdAt);
  });

  it("creates and saves a Human Identity", async () => {
    const create = new CreateHumanIdentity(
      repository,
      new FixedIdentityIdGenerator(id.value),
      clock,
    );

    const identity = await create.execute();

    assert.equal(identity.id.equals(id), true);
    assert.equal(identity.status, "active");
    assert.equal(repository.saveCount, 1);
    assert.equal(await repository.findById(id), identity);
  });

  it("gets a Human Identity by ID through the repository", async () => {
    const created = await new CreateHumanIdentity(
      repository,
      new FixedIdentityIdGenerator(id.value),
      clock,
    ).execute();

    const found = await new GetHumanIdentity(repository).execute(id);

    assert.equal(found, created);
  });

  it("suspends, reactivates, and retires through separate use cases", async () => {
    const identity = await new CreateHumanIdentity(
      repository,
      new FixedIdentityIdGenerator(id.value),
      clock,
    ).execute();

    clock.set(new Date("2026-01-02T00:00:00.000Z"));
    const suspended = await new SuspendHumanIdentity(
      repository,
      clock,
    ).execute(id);
    assert.equal(suspended, identity);
    assert.equal(suspended.status, "suspended");

    clock.set(new Date("2026-01-03T00:00:00.000Z"));
    const active = await new ReactivateHumanIdentity(
      repository,
      clock,
    ).execute(id);
    assert.equal(active.status, "active");

    clock.set(new Date("2026-01-04T00:00:00.000Z"));
    const retired = await new RetireHumanIdentity(repository, clock).execute(id);
    assert.equal(retired.status, "retired");
    assert.equal(repository.saveCount, 4);
  });

  it("reports missing identities consistently for every lookup use case", async () => {
    const missingId = HumanIdentityId.from("missing");
    const operations = [
      () => new GetHumanIdentity(repository).execute(missingId),
      () => new SuspendHumanIdentity(repository, clock).execute(missingId),
      () => new ReactivateHumanIdentity(repository, clock).execute(missingId),
      () => new RetireHumanIdentity(repository, clock).execute(missingId),
    ];

    for (const operation of operations) {
      await assert.rejects(
        operation,
        (error: unknown) =>
          error instanceof HumanIdentityNotFoundError &&
          error.identityId.equals(missingId),
      );
    }

    assert.equal(repository.saveCount, 0);
  });
});
