import type { Session } from "../domain/session.js";
import type { SessionId } from "../domain/session-id.js";
import type { HumanIdentityId } from "../../identity/domain/human-identity-id.js";

export interface SessionRepository {
  save(session: Session): Promise<void>;
  findById(id: SessionId): Promise<Session | null>;
  findActiveById(id: SessionId): Promise<Session | null>;
  findByRenewalTokenHashForUpdate(hash: string): Promise<Session | null>;
  listByHumanIdentityId(humanIdentityId: HumanIdentityId): Promise<readonly Session[]>;
  revoke(id: SessionId): Promise<void>;
  revokeByHumanIdentityId(humanIdentityId: HumanIdentityId): Promise<void>;
}
