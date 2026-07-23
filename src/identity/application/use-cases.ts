import type { Clock } from "../../shared/clock.js";
import { HumanIdentity } from "../domain/human-identity.js";
import type {
  HumanIdentityId,
  HumanIdentityIdGenerator,
} from "../domain/human-identity-id.js";
import type { HumanIdentityRepository } from "../ports/human-identity-repository.js";
import { HumanIdentityNotFoundError } from "./errors.js";

export class CreateHumanIdentity {
  constructor(
    private readonly repository: HumanIdentityRepository,
    private readonly idGenerator: HumanIdentityIdGenerator,
    private readonly clock: Clock,
  ) {}

  async execute(): Promise<HumanIdentity> {
    const identity = HumanIdentity.create(this.idGenerator, this.clock);
    await this.repository.save(identity);
    return identity;
  }
}

abstract class ExistingHumanIdentityUseCase {
  constructor(protected readonly repository: HumanIdentityRepository) {}

  protected async getIdentity(id: HumanIdentityId): Promise<HumanIdentity> {
    const identity = await this.repository.findById(id);

    if (identity === null) {
      throw new HumanIdentityNotFoundError(id);
    }

    return identity;
  }
}

export class GetHumanIdentity extends ExistingHumanIdentityUseCase {
  async execute(id: HumanIdentityId): Promise<HumanIdentity> {
    return this.getIdentity(id);
  }
}

export class SuspendHumanIdentity extends ExistingHumanIdentityUseCase {
  constructor(
    repository: HumanIdentityRepository,
    private readonly clock: Clock,
  ) {
    super(repository);
  }

  async execute(id: HumanIdentityId): Promise<HumanIdentity> {
    const identity = await this.getIdentity(id);
    identity.suspend(this.clock);
    await this.repository.save(identity);
    return identity;
  }
}

export class ReactivateHumanIdentity extends ExistingHumanIdentityUseCase {
  constructor(
    repository: HumanIdentityRepository,
    private readonly clock: Clock,
  ) {
    super(repository);
  }

  async execute(id: HumanIdentityId): Promise<HumanIdentity> {
    const identity = await this.getIdentity(id);
    identity.reactivate(this.clock);
    await this.repository.save(identity);
    return identity;
  }
}

export class RetireHumanIdentity extends ExistingHumanIdentityUseCase {
  constructor(
    repository: HumanIdentityRepository,
    private readonly clock: Clock,
  ) {
    super(repository);
  }

  async execute(id: HumanIdentityId): Promise<HumanIdentity> {
    const identity = await this.getIdentity(id);
    identity.retire(this.clock);
    await this.repository.save(identity);
    return identity;
  }
}
