import type { Session } from "../domain/session.js";
import type { SessionId } from "../domain/session-id.js";

export interface SessionRepository {
  save(session: Session): Promise<void>;
  findById(id: SessionId): Promise<Session | null>;
  findActiveById(id: SessionId): Promise<Session | null>;
  revoke(id: SessionId): Promise<void>;
}
