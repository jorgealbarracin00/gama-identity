import { randomUUID } from "node:crypto";

import type { EmailCredentialRepository } from "../../authentication/credentials/ports/email-credential-repository.js";
import { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type { HumanIdentityRepository } from "../../identity/ports/human-identity-repository.js";
import type { Clock } from "../../shared/clock.js";
import type {
  PlatformAdministrationMembership,
  ProductEntitlement,
  ProductParticipation,
  RegisteredProduct,
  Tenant,
  TenantMembership,
  TenantProvisioningRequest,
} from "../models.js";
import type { ControlPlaneRepository } from "../ports/control-plane-repository.js";
import type {
  ProductWorkforceAccess,
  ResolvedHumanIdentity,
} from "./workforce-administration.js";
import { WorkforceAdministration } from "./workforce-administration.js";
import {
  AdministrationPrincipals,
  authorizationError,
  type PlatformAdministrationPrincipal,
} from "./administration-principals.js";

type AtomicExecutor = <T>(work: () => Promise<T>) => Promise<T>;
type TenantIdGenerator = () => string;

export class PlatformAdministrationError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "PlatformAdministrationError";
  }
}

export interface PlatformGrantWorkforceInput {
  readonly tenantId: string;
  readonly productId: string;
  readonly humanIdentityId: string;
  readonly tenantRole: string;
}

export interface ProvisionTenantInput {
  readonly idempotencyKey: string;
  readonly displayName: string;
  readonly initialOwnerHumanIdentityId: string;
}

export interface ProvisionTenantResult {
  readonly tenant: Tenant;
  readonly initialOwnerMembership: TenantMembership;
  readonly created: boolean;
}

export interface TenantProductProjection {
  readonly productId: string;
  readonly displayName: string;
  readonly productStatus: RegisteredProduct["status"];
  readonly participationStatus: ProductParticipation["status"];
}

export interface PlatformTeamProductAccessProjection extends TenantProductProjection {
  readonly entitlementStatus: ProductEntitlement["status"] | null;
}

export interface PlatformTeamMemberProjection {
  readonly tenantId: string;
  readonly humanIdentityId: string;
  readonly displayName: null;
  readonly email: string | null;
  readonly humanIdentityStatus: "active" | "suspended" | "retired" | null;
  readonly signInMethods: readonly string[];
  /** Compatibility alias retained for the original Platform Team contract. */
  readonly status: TenantMembership["status"];
  readonly membershipStatus: TenantMembership["status"];
  readonly tenantRole: TenantMembership["tenantRole"];
  readonly products: readonly PlatformTeamProductAccessProjection[];
}

export class PlatformAdministration {
  private readonly provisioningInFlight = new Map<string, Promise<ProvisionTenantResult>>();

  constructor(
    private readonly principals: AdministrationPrincipals,
    private readonly workforce: WorkforceAdministration,
    private readonly repository: ControlPlaneRepository,
    private readonly identities: HumanIdentityRepository,
    private readonly credentials: EmailCredentialRepository,
    private readonly clock: Clock,
    private readonly atomically: AtomicExecutor = async (work) => work(),
    private readonly tenantIdGenerator: TenantIdGenerator = randomUUID,
  ) {}

  async listTenants(actorHumanIdentityId: string): Promise<readonly Tenant[]> {
    await this.principals.platform(actorHumanIdentityId);
    return this.repository.listTenants();
  }

  async provisionTenant(actorHumanIdentityId: string, input: ProvisionTenantInput): Promise<ProvisionTenantResult> {
    const principal = await this.principals.platform(actorHumanIdentityId);
    const displayName = input.displayName.trim();
    if (displayName.length === 0) throw platformError("INVALID_TENANT", "Tenant display name is required");
    if (input.idempotencyKey.trim().length === 0) throw platformError("INVALID_IDEMPOTENCY_KEY", "An idempotency key is required");

    const inFlight = this.provisioningInFlight.get(input.idempotencyKey);
    if (inFlight !== undefined) {
      try {
        await inFlight;
      } catch {
        // A failed transaction does not consume the request identity. Retry it.
      }
      return this.provisionTenantAtomically(principal, input, displayName);
    }

    const operation = this.provisionTenantAtomically(principal, input, displayName);
    this.provisioningInFlight.set(input.idempotencyKey, operation);
    try {
      return await operation;
    } finally {
      if (this.provisioningInFlight.get(input.idempotencyKey) === operation) {
        this.provisioningInFlight.delete(input.idempotencyKey);
      }
    }
  }

  private async provisionTenantAtomically(
    principal: PlatformAdministrationPrincipal,
    input: ProvisionTenantInput,
    displayName: string,
  ): Promise<ProvisionTenantResult> {
    return this.atomically(async () => {
      const existing = await this.repository.findTenantProvisioningRequest(input.idempotencyKey);
      if (existing !== null) return this.resolveProvisioningRetry(existing, displayName, input.initialOwnerHumanIdentityId);

      const owner = await this.identities.findById(HumanIdentityId.from(input.initialOwnerHumanIdentityId));
      if (owner?.status !== "active") throw platformError("IDENTITY_NOT_FOUND", "An active initial Owner Human Identity is required");

      const tenant: Tenant = { id: this.tenantIdGenerator(), displayName, status: "active" };
      const request: TenantProvisioningRequest = {
        idempotencyKey: input.idempotencyKey,
        tenantId: tenant.id,
        displayName,
        initialOwnerHumanIdentityId: input.initialOwnerHumanIdentityId,
        createdAt: this.clock.now(),
      };
      const reserved = await this.repository.insertTenantProvisioningRequestIfAbsent(request);
      if (!reserved) {
        const concurrent = await this.repository.findTenantProvisioningRequest(input.idempotencyKey);
        if (concurrent === null) throw platformError("TENANT_PROVISIONING_CONFLICT", "Tenant provisioning could not be resolved");
        return this.resolveProvisioningRetry(concurrent, displayName, input.initialOwnerHumanIdentityId);
      }
      if (!(await this.repository.insertTenantIfAbsent(tenant))) {
        throw platformError("TENANT_ID_CONFLICT", "Generated Tenant identity already exists");
      }
      const initialOwnerMembership = await this.workforce.establishInitialTenantOwner({
        actorReference: principal.actorReference,
        authorityScope: principal.kind,
        tenantId: tenant.id,
        humanIdentityId: input.initialOwnerHumanIdentityId,
      });
      await this.repository.appendAudit({
        id: randomUUID(),
        eventType: "tenant.created",
        actorReference: principal.actorReference,
        subjectReference: tenant.id,
        tenantId: tenant.id,
        eventData: {
          authorityScope: principal.kind,
          displayName,
          initialOwnerHumanIdentityId: input.initialOwnerHumanIdentityId,
          status: tenant.status,
        },
        occurredAt: this.clock.now(),
      });
      return { tenant, initialOwnerMembership, created: true };
    });
  }

  async listProducts(actorHumanIdentityId: string): Promise<readonly RegisteredProduct[]> {
    await this.principals.platform(actorHumanIdentityId);
    return this.repository.listProducts();
  }

  async listTenantProducts(actorHumanIdentityId: string, tenantId: string): Promise<readonly TenantProductProjection[]> {
    await this.principals.platform(actorHumanIdentityId);
    await this.requireTenant(tenantId, false);
    const participations = await this.repository.listParticipationsForTenant(tenantId);
    return Promise.all(participations.map((participation) => this.projectTenantProduct(participation)));
  }

  async assignTenantProduct(actorHumanIdentityId: string, tenantId: string, productId: string): Promise<TenantProductProjection> {
    const principal = await this.principals.platform(actorHumanIdentityId);
    return this.atomically(async () => {
      await this.repository.lockTenant(tenantId);
      await this.requireTenant(tenantId, true);
      const product = await this.requireProduct(productId, true);
      const existing = await this.repository.findParticipation(tenantId, productId);
      if (existing?.status === "active") return this.toTenantProduct(product, existing);
      if (existing?.status === "retired") {
        throw platformError("PRODUCT_PARTICIPATION_RETIRED", "A retired Tenant Product participation cannot be reactivated");
      }
      const participation: ProductParticipation = { tenantId, productId, status: "active" };
      await this.repository.saveParticipation(participation);
      await this.repository.appendAudit({
        id: randomUUID(),
        eventType: existing === null ? "tenant.product.assigned" : "tenant.product.reactivated",
        actorReference: principal.actorReference,
        subjectReference: `${tenantId}:${productId}`,
        tenantId,
        productId,
        eventData: {
          authorityScope: principal.kind,
          previousParticipationStatus: existing?.status ?? "none",
          participationStatus: "active",
        },
        occurredAt: this.clock.now(),
      });
      return this.toTenantProduct(product, participation);
    });
  }

  async resolveHumanIdentityByEmail(actorHumanIdentityId: string, email: string): Promise<ResolvedHumanIdentity> {
    await this.principals.platform(actorHumanIdentityId);
    return this.workforce.resolveHumanIdentityByEmail(email);
  }

  async resolveHumanIdentityById(actorHumanIdentityId: string, humanIdentityId: string): Promise<ResolvedHumanIdentity> {
    await this.principals.platform(actorHumanIdentityId);
    return this.workforce.resolveHumanIdentityById(humanIdentityId);
  }

  async resolveHumanIdentity(actorHumanIdentityId: string, identifier: string): Promise<ResolvedHumanIdentity> {
    await this.principals.platform(actorHumanIdentityId);
    return this.workforce.resolveHumanIdentity(identifier);
  }

  async listTenantWorkforce(actorHumanIdentityId: string, tenantId: string): Promise<readonly PlatformTeamMemberProjection[]> {
    await this.principals.platform(actorHumanIdentityId);
    const [memberships, participations] = await Promise.all([
      this.workforce.listTenantWorkforce(tenantId),
      this.repository.listParticipationsForTenant(tenantId),
    ]);
    return Promise.all(memberships.map((membership) => this.projectTeamMember(membership, participations)));
  }

  async inspectTenantMembership(actorHumanIdentityId: string, tenantId: string, humanIdentityId: string): Promise<PlatformTeamMemberProjection> {
    await this.principals.platform(actorHumanIdentityId);
    const [membership, participations] = await Promise.all([
      this.workforce.inspectTenantMembership(tenantId, humanIdentityId),
      this.repository.listParticipationsForTenant(tenantId),
    ]);
    return this.projectTeamMember(membership, participations);
  }

  async grantProductWorkforceAccess(actorHumanIdentityId: string, input: PlatformGrantWorkforceInput): Promise<ProductWorkforceAccess> {
    const principal = await this.principals.platform(actorHumanIdentityId);
    return this.workforce.grantProductWorkforceAccess({
      ...input,
      actorReference: principal.actorReference,
      authorityScope: principal.kind,
    });
  }

  async changeTenantRole(
    actorHumanIdentityId: string,
    tenantId: string,
    humanIdentityId: string,
    tenantRole: string,
  ): Promise<TenantMembership> {
    const principal = await this.principals.platform(actorHumanIdentityId);
    return this.workforce.changeTenantRole({
      actorReference: principal.actorReference,
      authorityScope: principal.kind,
      tenantId,
      humanIdentityId,
      tenantRole,
    });
  }

  async revokeProductAccess(
    actorHumanIdentityId: string,
    tenantId: string,
    productId: string,
    humanIdentityId: string,
  ): Promise<ProductEntitlement | null> {
    const principal = await this.principals.platform(actorHumanIdentityId);
    return this.workforce.revokeProductAccess({
      actorReference: principal.actorReference,
      authorityScope: principal.kind,
      tenantId,
      productId,
      humanIdentityId,
    });
  }

  async revokeTenantMembership(
    actorHumanIdentityId: string,
    tenantId: string,
    humanIdentityId: string,
  ): Promise<TenantMembership | null> {
    const principal = await this.principals.platform(actorHumanIdentityId);
    return this.workforce.revokeTenantMembership({
      actorReference: principal.actorReference,
      authorityScope: principal.kind,
      tenantId,
      humanIdentityId,
    });
  }

  private async resolveProvisioningRetry(
    request: TenantProvisioningRequest,
    displayName: string,
    initialOwnerHumanIdentityId: string,
  ): Promise<ProvisionTenantResult> {
    if (request.displayName !== displayName || request.initialOwnerHumanIdentityId !== initialOwnerHumanIdentityId) {
      throw platformError("IDEMPOTENCY_KEY_REUSED", "Idempotency key was already used for different Tenant provisioning input");
    }
    const [tenant, membership] = await Promise.all([
      this.repository.findTenant(request.tenantId),
      this.repository.findMembership(request.tenantId, request.initialOwnerHumanIdentityId),
    ]);
    if (tenant === null || membership === null) {
      throw platformError("TENANT_PROVISIONING_INCOMPLETE", "Tenant provisioning record is inconsistent");
    }
    return { tenant, initialOwnerMembership: membership, created: false };
  }

  private async projectTenantProduct(participation: ProductParticipation): Promise<TenantProductProjection> {
    const product = await this.requireProduct(participation.productId, false);
    return this.toTenantProduct(product, participation);
  }

  private toTenantProduct(product: RegisteredProduct, participation: ProductParticipation): TenantProductProjection {
    return {
      productId: product.id,
      displayName: product.displayName,
      productStatus: product.status,
      participationStatus: participation.status,
    };
  }

  private async projectTeamMember(
    membership: TenantMembership,
    participations: readonly ProductParticipation[],
  ): Promise<PlatformTeamMemberProjection> {
    const identityId = HumanIdentityId.from(membership.humanIdentityId);
    const [identity, credential, products] = await Promise.all([
      this.identities.findById(identityId),
      this.credentials.findByHumanIdentityId(identityId),
      Promise.all(participations.map(async (participation) => {
        const [product, entitlement] = await Promise.all([
          this.requireProduct(participation.productId, false),
          this.repository.findEntitlement(membership.tenantId, participation.productId, membership.humanIdentityId),
        ]);
        return {
          ...this.toTenantProduct(product, participation),
          entitlementStatus: entitlement?.status ?? null,
        };
      })),
    ]);
    const resolvedIdentity = identity?.status === "active"
      ? await this.workforce.resolveHumanIdentityById(identity.id.value)
      : null;
    return {
      tenantId: membership.tenantId,
      humanIdentityId: membership.humanIdentityId,
      displayName: null,
      email: resolvedIdentity?.email ?? credential?.email.value ?? null,
      humanIdentityStatus: identity?.status ?? null,
      signInMethods: resolvedIdentity?.signInMethods ?? [],
      status: membership.status,
      membershipStatus: membership.status,
      tenantRole: membership.tenantRole,
      products,
    };
  }

  private async requireTenant(tenantId: string, active: boolean): Promise<Tenant> {
    const tenant = await this.repository.findTenant(tenantId);
    if (tenant === null) throw platformError("TENANT_NOT_FOUND", "Tenant was not found");
    if (active && tenant.status !== "active") throw platformError("TENANT_INACTIVE", "Tenant is not active");
    return tenant;
  }

  private async requireProduct(productId: string, active: boolean): Promise<RegisteredProduct> {
    const product = await this.repository.findProduct(productId);
    if (product === null) throw platformError("PRODUCT_NOT_FOUND", "Registered Product was not found");
    if (active && product.status !== "active") throw platformError("PRODUCT_NOT_AVAILABLE", "Registered Product is not active");
    return product;
  }
}

function platformError(code: string, message: string): PlatformAdministrationError {
  return new PlatformAdministrationError(code, message);
}

/**
 * Explicit deployment-time provisioning boundary for the first administrator.
 * It is intentionally not included in the HTTP service surface.
 */
export class PlatformAdministrationProvisioning {
  constructor(
    private readonly repository: ControlPlaneRepository,
    private readonly identities: HumanIdentityRepository,
    private readonly clock: Clock,
    private readonly atomically: AtomicExecutor = async (work) => work(),
  ) {}

  async bootstrapAdministrator(humanIdentityId: string, actorReference: string): Promise<PlatformAdministrationMembership> {
    if (actorReference.trim().length === 0) {
      throw authorizationError("NOT_AUTHORIZED", "An accountable bootstrap actor reference is required");
    }
    return this.atomically(async () => {
      const identity = await this.identities.findById(HumanIdentityId.from(humanIdentityId));
      if (identity?.status !== "active") {
        throw authorizationError("IDENTITY_NOT_FOUND", "An active Human Identity is required");
      }
      const existing = await this.repository.findPlatformAdministrationMembership(humanIdentityId);
      if (existing?.status === "active") return existing;
      if (existing !== null) {
        throw authorizationError(
          "PLATFORM_ADMINISTRATION_MEMBERSHIP_INACTIVE",
          "An inactive Platform administration membership cannot be bootstrapped",
        );
      }
      const now = this.clock.now();
      const membership: PlatformAdministrationMembership = {
        humanIdentityId,
        platformRole: "administrator",
        status: "active",
        createdAt: now,
        updatedAt: now,
      };
      const inserted = await this.repository.insertPlatformAdministrationMembershipIfAbsent(membership);
      if (!inserted) {
        const concurrent = await this.repository.findPlatformAdministrationMembership(humanIdentityId);
        if (concurrent?.status === "active") return concurrent;
        throw authorizationError(
          "PLATFORM_ADMINISTRATION_MEMBERSHIP_INACTIVE",
          "An inactive Platform administration membership cannot be bootstrapped",
        );
      }
      await this.repository.appendAudit({
        id: randomUUID(),
        eventType: "platform.administration.membership.granted",
        actorReference,
        subjectReference: humanIdentityId,
        eventData: {
          authorityScope: "deployment-bootstrap",
          platformRole: "administrator",
          status: "active",
        },
        occurredAt: this.clock.now(),
      });
      return membership;
    });
  }
}
