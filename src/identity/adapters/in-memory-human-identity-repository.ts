import type { HumanIdentity } from "../domain/human-identity.js";
import type { HumanIdentityId } from "../domain/human-identity-id.js";
import type { HumanIdentityRepository } from "../ports/human-identity-repository.js";

export class InMemoryHumanIdentityRepository
  implements HumanIdentityRepository
{
  private readonly identities = new Map<string, HumanIdentity>();

  async save(identity: HumanIdentity): Promise<void> {
    this.identities.set(identity.id.value, identity.copy());
  }

  async findById(id: HumanIdentityId): Promise<HumanIdentity | null> {
    return this.identities.get(id.value)?.copy() ?? null;
  }

  async remove(id: HumanIdentityId): Promise<void> {
    this.identities.delete(id.value);
  }
}
