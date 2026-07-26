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
    const queryable = this.transactionClient.getStore() ?? this.pool;
    return queryable.query<Row>(text, values as unknown[]);
  }

  async checkConnection(): Promise<void> {
    await this.pool.query("SELECT 1");
  }

  async withTransaction<T>(work: () => Promise<T>): Promise<T> {
    if (this.transactionClient.getStore() !== undefined) {
      return work();
    }

    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
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
