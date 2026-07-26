import type { DatabaseHealth } from "../api/services.js";

export class HealthCheck {
  constructor(private readonly database: DatabaseHealth) {}

  async execute(): Promise<{
    readonly status: "running" | "degraded";
    readonly database: {
      readonly status: "connected" | "not_configured" | "unavailable";
    };
  }> {
    try {
      return {
        status: "running",
        database: { status: await this.database.check() },
      };
    } catch {
      return {
        status: "degraded",
        database: { status: "unavailable" },
      };
    }
  }
}
