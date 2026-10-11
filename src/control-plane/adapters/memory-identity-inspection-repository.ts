import type { InMemoryHumanIdentityRepository } from "../../identity/adapters/in-memory-human-identity-repository.js";
import type { EmailCredentialRepository } from "../../authentication/credentials/ports/email-credential-repository.js";
import type { FederatedIdentityRepository } from "../../authentication/federated/ports/federated-identity-repository.js";
import { inspectionPage, type IdentityInspectionRepository, type InspectionRequest } from "../application/identity-explorer.js";

export class MemoryIdentityInspectionRepository implements IdentityInspectionRepository {
  constructor(
    private readonly identities: InMemoryHumanIdentityRepository,
    private readonly credentials: EmailCredentialRepository,
    private readonly federated: FederatedIdentityRepository,
  ) {}
  async inspect(input: InspectionRequest) {
    const humans = await Promise.all(this.identities.listForInspection().map(async (human) => {
      const [credentials, providers] = await Promise.all([
        this.credentials.listByHumanIdentityId(human.id), this.federated.listByHumanIdentityId(human.id),
      ]);
      return {
        humanIdentityId: human.id.value, displayName: null, status: human.status,
        authenticationMethods: [
          ...credentials.map((credential) => ({ method: "email_password", status: credential.status, email: credential.email.value, emailVerified: credential.emailVerified })),
          ...providers.map((provider) => ({ method: provider.provider.value, status: provider.status, email: provider.providerEmail, emailVerified: provider.providerEmailVerified })),
        ],
      };
    }));
    return inspectionPage(humans, input);
  }
}
