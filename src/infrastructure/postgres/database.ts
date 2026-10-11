import { AsyncLocalStorage } from "node:async_hooks";

import {
  Pool,
  type PoolClient,
  type PoolConfig,
  type QueryResult,
  type QueryResultRow,
} from "pg";

export interface DatabaseQuery {
  query<Row extends QueryResultRow = QueryResultRow>(
    text: string,
    values?: readonly unknown[],
  ): Promise<QueryResult<Row>>;
}

export class PostgresDatabase implements DatabaseQuery {
  private readonly pool: Pool;
  private readonly transactionClient = new AsyncLocalStorage<PoolClient>();

  constructor(
    connectionString: string,
    sslRequired = false,
    onPoolError: (error: Error) => void = () => {},
    private readonly identityManagementFencing = false,
  ) {
    const poolConfig: PoolConfig = {
      connectionString,
      max: 10,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
    };
    if (sslRequired) {
      poolConfig.ssl = { rejectUnauthorized: false };
    }
    this.pool = new Pool(poolConfig);
    this.pool.on("error", onPoolError);
  }

  query<Row extends QueryResultRow = QueryResultRow>(
    text: string,
    values?: readonly unknown[],
  ): Promise<QueryResult<Row>> {
    if (this.identityManagementFencing && this.transactionClient.getStore() === undefined) {
      return this.withTransaction(() => this.query<Row>(text, values));
    }
    const queryable = this.transactionClient.getStore() ?? this.pool;
    return queryable.query<Row>(text, values as unknown[]);
  }

  async checkConnection(): Promise<void> {
    await this.pool.query("SELECT 1");
  }

  async withTransaction<T>(work: () => Promise<T>): Promise<T> {
    return this.transaction(work, false);
  }

  async withIdentityManagementTransaction<T>(work: () => Promise<T>): Promise<T> {
    if (!this.identityManagementFencing) throw new Error("Identity management execution is disabled");
    if (this.transactionClient.getStore()) throw new Error("Exclusive identity management transaction cannot be nested");
    return this.transaction(work, true);
  }

  private async transaction<T>(work: () => Promise<T>, exclusive: boolean): Promise<T> {
    if (this.transactionClient.getStore() !== undefined) {
      return work();
    }

    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      if (this.identityManagementFencing) await client.query(exclusive ? "SELECT pg_advisory_xact_lock(710021)" : "SELECT pg_advisory_xact_lock_shared(710021)");
      const result = await this.transactionClient.run(client, work);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
