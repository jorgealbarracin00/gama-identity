import type { HumanIdentityStatus } from "./human-identity.js";

export class InvalidHumanIdentityTransitionError extends Error {
  constructor(
    readonly from: HumanIdentityStatus,
    readonly to: HumanIdentityStatus,
  ) {
    super(`Human Identity cannot transition from ${from} to ${to}`);
    this.name = "InvalidHumanIdentityTransitionError";
  }
}
