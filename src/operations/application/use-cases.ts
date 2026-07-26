import type {
  Authenticate,
  AuthenticationResult,
} from "../../authentication/application/authenticate.js";
import type {
  CreateEmailCredential,
} from "../../authentication/credentials/application/use-cases.js";
import { EmailCredentialId } from "../../authentication/credentials/domain/email-credential-id.js";
import type { CreateHumanIdentity } from "../../identity/application/use-cases.js";
import type { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type {
  CreateSession,
  SessionMetadata,
} from "../../sessions/application/use-cases.js";
import { SessionId } from "../../sessions/domain/session-id.js";
import { InvalidLoginError, RegistrationFailedError } from "./errors.js";

export interface CredentialsInput {
  readonly email: string;
  readonly password: string;
}

export interface RegistrationCompensator {
  removeIdentity(id: HumanIdentityId): Promise<void>;
  removeCredential(id: EmailCredentialId): Promise<void>;
  removeSession(id: SessionId): Promise<void>;
}

export interface RegistrationResult {
  readonly humanIdentityId: string;
  readonly session: SessionMetadata;
}

export class Register {
  constructor(
    private readonly createIdentity: CreateHumanIdentity,
    private readonly createCredential: CreateEmailCredential,
    private readonly authenticate: Authenticate,
    private readonly createSession: CreateSession,
    private readonly compensator: RegistrationCompensator,
  ) {}

  async execute(input: CredentialsInput): Promise<RegistrationResult> {
    let identityId: HumanIdentityId | undefined;
    let credentialId: EmailCredentialId | undefined;
    let sessionId: SessionId | undefined;

    try {
      const identity = await this.createIdentity.execute();
      identityId = identity.id;
      const credential = await this.createCredential.execute({
        humanIdentityId: identity.id,
        email: input.email,
        plaintextPassword: input.password,
      });
      credentialId = EmailCredentialId.from(credential.id);

      const authentication = await this.authenticate.execute({
        email: input.email,
        plaintextPassword: input.password,
      });
      if (authentication.outcome !== "success") {
        throw new RegistrationFailedError();
      }

      const session = await this.createSession.execute(
        authentication.humanIdentityId,
      );
      sessionId = SessionId.from(session.sessionId);
      return { humanIdentityId: identity.id.value, session };
    } catch (error) {
      if (sessionId !== undefined) await this.compensator.removeSession(sessionId);
      if (credentialId !== undefined) {
        await this.compensator.removeCredential(credentialId);
      }
      if (identityId !== undefined) {
        await this.compensator.removeIdentity(identityId);
      }
      throw error;
    }
  }
}

export class Login {
  constructor(
    private readonly authenticate: Authenticate,
    private readonly createSession: CreateSession,
  ) {}

  async execute(input: CredentialsInput): Promise<SessionMetadata> {
    const result: AuthenticationResult = await this.authenticate.execute({
      email: input.email,
      plaintextPassword: input.password,
    });
    if (result.outcome !== "success") {
      throw new InvalidLoginError();
    }
    return this.createSession.execute(result.humanIdentityId);
  }
}
