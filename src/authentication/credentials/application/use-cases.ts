import type { HumanIdentityId } from "../../../identity/domain/human-identity-id.js";
import type { Clock } from "../../../shared/clock.js";
import { EmailCredential } from "../domain/email-credential.js";
import type {
  EmailCredentialId,
  EmailCredentialIdGenerator,
} from "../domain/email-credential-id.js";
import { EmailAlreadyInUseError } from "../domain/errors.js";
import { NormalizedEmail } from "../domain/email.js";
import type { PasswordPolicy } from "../domain/password-policy.js";
import type { EmailCredentialRepository } from "../ports/email-credential-repository.js";
import type { PasswordHasher } from "../ports/password-operations.js";
import {
  type EmailCredentialMetadata,
  toEmailCredentialMetadata,
} from "./credential-metadata.js";
import { EmailCredentialNotFoundError } from "./errors.js";

export interface CreateEmailCredentialInput {
  readonly humanIdentityId: HumanIdentityId;
  readonly email: string;
  readonly plaintextPassword: string;
}

export class CreateEmailCredential {
  constructor(
    private readonly repository: EmailCredentialRepository,
    private readonly idGenerator: EmailCredentialIdGenerator,
    private readonly clock: Clock,
    private readonly passwordPolicy: PasswordPolicy,
    private readonly passwordHasher: PasswordHasher,
  ) {}

  async execute(
    input: CreateEmailCredentialInput,
  ): Promise<EmailCredentialMetadata> {
    const email = NormalizedEmail.from(input.email);
    this.passwordPolicy.validate(input.plaintextPassword);

    const existing = await this.repository.findByNormalizedEmail(email);
    if (existing !== null) {
      throw new EmailAlreadyInUseError();
    }

    const passwordHash = await this.passwordHasher.hash(
      input.plaintextPassword,
    );
    const credential = EmailCredential.create(
      this.idGenerator,
      input.humanIdentityId,
      email,
      passwordHash,
      this.clock,
    );

    await this.repository.save(credential);
    return toEmailCredentialMetadata(credential);
  }
}

abstract class ExistingEmailCredentialUseCase {
  constructor(protected readonly repository: EmailCredentialRepository) {}

  protected async getCredential(
    id: EmailCredentialId,
  ): Promise<EmailCredential> {
    const credential = await this.repository.findById(id);

    if (credential === null) {
      throw new EmailCredentialNotFoundError(id);
    }

    return credential;
  }
}

export class GetEmailCredential extends ExistingEmailCredentialUseCase {
  async execute(id: EmailCredentialId): Promise<EmailCredentialMetadata> {
    const credential = await this.getCredential(id);
    return toEmailCredentialMetadata(credential);
  }
}

export class FindEmailCredentialByEmail {
  constructor(private readonly repository: EmailCredentialRepository) {}

  async execute(rawEmail: string): Promise<EmailCredentialMetadata | null> {
    const email = NormalizedEmail.from(rawEmail);
    const credential = await this.repository.findByNormalizedEmail(email);

    return credential === null ? null : toEmailCredentialMetadata(credential);
  }
}

abstract class MutateEmailCredentialUseCase extends ExistingEmailCredentialUseCase {
  constructor(
    repository: EmailCredentialRepository,
    protected readonly clock: Clock,
  ) {
    super(repository);
  }

  protected async saveMetadata(
    credential: EmailCredential,
  ): Promise<EmailCredentialMetadata> {
    await this.repository.save(credential);
    return toEmailCredentialMetadata(credential);
  }
}

export class DisableEmailCredential extends MutateEmailCredentialUseCase {
  async execute(id: EmailCredentialId): Promise<EmailCredentialMetadata> {
    const credential = await this.getCredential(id);
    credential.disable(this.clock);
    return this.saveMetadata(credential);
  }
}

export class EnableEmailCredential extends MutateEmailCredentialUseCase {
  async execute(id: EmailCredentialId): Promise<EmailCredentialMetadata> {
    const credential = await this.getCredential(id);
    credential.enable(this.clock);
    return this.saveMetadata(credential);
  }
}

export class RetireEmailCredential extends MutateEmailCredentialUseCase {
  async execute(id: EmailCredentialId): Promise<EmailCredentialMetadata> {
    const credential = await this.getCredential(id);
    credential.retire(this.clock);
    return this.saveMetadata(credential);
  }
}

export interface ReplaceEmailCredentialPasswordInput {
  readonly credentialId: EmailCredentialId;
  readonly plaintextPassword: string;
}

export class ReplaceEmailCredentialPassword extends MutateEmailCredentialUseCase {
  constructor(
    repository: EmailCredentialRepository,
    clock: Clock,
    private readonly passwordPolicy: PasswordPolicy,
    private readonly passwordHasher: PasswordHasher,
  ) {
    super(repository, clock);
  }

  async execute(
    input: ReplaceEmailCredentialPasswordInput,
  ): Promise<EmailCredentialMetadata> {
    this.passwordPolicy.validate(input.plaintextPassword);
    const credential = await this.getCredential(input.credentialId);
    const passwordHash = await this.passwordHasher.hash(
      input.plaintextPassword,
    );

    credential.replacePassword(passwordHash, this.clock);
    return this.saveMetadata(credential);
  }
}
