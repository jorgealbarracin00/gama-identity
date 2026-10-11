/** Fixture seeding includes TRUNCATE, so the parsed URL must select the exact local target. */
export function consoleFixtureDatabaseAllowed(value: string | undefined, management: boolean): boolean {
  try {
    const url = new URL(value ?? "");
    return ["postgres:", "postgresql:"].includes(url.protocol)
      && url.hostname === "127.0.0.1"
      // PostgreSQL query options can override the URL host or port.
      && url.search === "" && url.hash === ""
      && (management ? /^\/[a-z0-9_]+_management_test$/ : /^\/[a-z0-9_]+_ui$/).test(url.pathname);
  } catch {
    return false;
  }
}
