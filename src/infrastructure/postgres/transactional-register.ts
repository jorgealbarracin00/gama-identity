import type {
  CredentialsInput,
  Register,
  RegistrationResult,
} from "../../operations/application/use-cases.js";
import type { PostgresDatabase } from "./database.js";

export class TransactionalRegister {
  constructor(
    private readonly register: Register,
    private readonly database: PostgresDatabase,
  ) {}

  execute(input: CredentialsInput): Promise<RegistrationResult> {
    return this.database.withTransaction(() => this.register.execute(input));
  }
}
