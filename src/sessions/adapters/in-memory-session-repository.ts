import type { Session } from "../domain/session.js";
import type { SessionId } from "../domain/session-id.js";
import type { SessionRepository } from "../ports/session-repository.js";

export class InMemorySessionRepository implements SessionRepository {
  private readonly sessions = new Map<string, Session>();

  async save(session: Session): Promise<void> {
    this.sessions.set(session.id.value, session.copy());
  }

  async findById(id: SessionId): Promise<Session | null> {
    return this.sessions.get(id.value)?.copy() ?? null;
  }

  async findActiveById(id: SessionId): Promise<Session | null> {
    const session = await this.findById(id);
    return session?.status === "active" ? session : null;
  }

  async revoke(id: SessionId): Promise<void> {
    const session = this.sessions.get(id.value);
    if (session === undefined) return;
    session.revoke();
    this.sessions.set(id.value, session);
  }

  async remove(id: SessionId): Promise<void> {
    this.sessions.delete(id.value);
  }
}
