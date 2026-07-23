import type { HumanIdentity } from "../domain/human-identity.js";
import type { HumanIdentityId } from "../domain/human-identity-id.js";

export interface HumanIdentityRepository {
  save(identity: HumanIdentity): Promise<void>;
  findById(id: HumanIdentityId): Promise<HumanIdentity | null>;
}
