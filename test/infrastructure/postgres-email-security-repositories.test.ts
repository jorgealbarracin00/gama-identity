import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { QueryResult, QueryResultRow } from "pg";

import type { DatabaseQuery } from "../../src/infrastructure/postgres/database.js";
import { PostgresIdentitySecurityAttemptRepository } from "../../src/infrastructure/postgres/postgres-email-security-repositories.js";

class RecordingDatabase implements DatabaseQuery {
  queryText = "";
  queryValues: readonly unknown[] = [];

  async query<Row extends QueryResultRow = QueryResultRow>(
    text: string,
    values: readonly unknown[] = [],
  ): Promise<QueryResult<Row>> {
    this.queryText = text;
    this.queryValues = values;
    return {
      command: "SELECT",
      rowCount: 1,
      oid: 0,
      fields: [],
      rows: [{ accepted: true } as unknown as Row],
    };
  }
}

describe("PostgresIdentitySecurityAttemptRepository", () => {
  it("binds the rate-limit boundary as a timestamp and the window as seconds", async () => {
    const database = new RecordingDatabase();
    const repository = new PostgresIdentitySecurityAttemptRepository(database);
    const occurredAt = new Date("2026-10-04T00:00:00.000Z");

    const accepted = await repository.consume({
      action: "registration",
      subjectHash: "subject-hash",
      ipHash: "ip-hash",
      occurredAt,
      windowSeconds: 900,
      maximumAttempts: 5,
    });

    assert.equal(accepted, true);
    assert.match(
      database.queryText,
      /occurred_at >= \$4::timestamptz - make_interval\(secs => \$5::int\)/,
    );
    assert.match(database.queryText, /\$4::timestamptz FROM recent/);
    assert.deepEqual(database.queryValues, [
      "registration",
      "subject-hash",
      "ip-hash",
      occurredAt,
      900,
      5,
    ]);
  });
});
