import type { SessionStatus } from "./session.js";

export class SessionUnavailableError extends Error {
  constructor(readonly status: SessionStatus) {
    super(`Session is ${status}`);
    this.name = "SessionUnavailableError";
  }
}
