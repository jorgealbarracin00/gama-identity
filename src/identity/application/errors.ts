import type { HumanIdentityId } from "../domain/human-identity-id.js";

export class HumanIdentityNotFoundError extends Error {
  constructor(readonly identityId: HumanIdentityId) {
    super(`Human Identity ${identityId.value} was not found`);
    this.name = "HumanIdentityNotFoundError";
  }
}
