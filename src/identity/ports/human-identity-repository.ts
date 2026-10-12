import type { HumanIdentity } from "../domain/human-identity.js";
import type { HumanIdentityId } from "../domain/human-identity-id.js";

export interface HumanIdentityRepository {
  /** Transaction-scoped serialization of one Human's account methods. */
  lockForAccountManagement?(id: HumanIdentityId): Promise<void>;
  save(identity: HumanIdentity): Promise<void>;
  findById(id: HumanIdentityId): Promise<HumanIdentity | null>;
}
