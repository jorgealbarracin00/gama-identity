import { randomUUID } from "node:crypto";

import { NormalizedEmail } from "../../authentication/credentials/domain/email.js";
import { InvalidEmailError } from "../../authentication/credentials/domain/errors.js";
import type { EmailCredentialRepository } from "../../authentication/credentials/ports/email-credential-repository.js";
import { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type { HumanIdentityRepository } from "../../identity/ports/human-identity-repository.js";
import type { Clock } from "../../shared/clock.js";
import {
  isTenantWorkforceRole,
  type LifecycleStatus,
  type ProductEntitlement,
  type ProductParticipation,
  type TenantMembership,
  type TenantWorkforceRole,
} from "../models.js";
import type { ControlPlaneRepository } from "../ports/control-plane-repository.js";

type AtomicExecutor = <T>(work: () => Promise<T>) => Promise<T>;

export class WorkforceAdministrationError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "WorkforceAdministrationError";
  }
}

export interface ResolvedHumanIdentity {
  readonly humanIdentityId: string;
  readonly displayName: null;
  readonly email: string;
  readonly status: LifecycleStatus;
}

export interface EstablishInitialTenantOwnerInput {
  readonly actorReference: string;
  readonly authorityScope?: AdministrationAuthorityScope;
  readonly tenantId: string;
  readonly humanIdentityId: string;
}

export interface GrantProductWorkforceAccessInput {
  readonly actorReference: string;
  readonly authorityScope?: AdministrationAuthorityScope;
  readonly authorityProductId?: string;
  readonly tenantId: string;
  readonly productId: string;
  readonly humanIdentityId: string;
  readonly tenantRole: string;
}

export interface ProductWorkforceAccess {
  readonly membership: TenantMembership;
  readonly participation: ProductParticipation;
  readonly entitlement: ProductEntitlement;
}

export interface ChangeTenantRoleInput {
  readonly actorReference: string;
  readonly authorityScope?: AdministrationAuthorityScope;
  readonly authorityProductId?: string;
  readonly tenantId: string;
  readonly humanIdentityId: string;
  readonly tenantRole: string;
}

export interface RevokeProductAccessInput {
  readonly actorReference: string;
  readonly authorityScope?: AdministrationAuthorityScope;
  readonly authorityProductId?: string;
  readonly tenantId: string;
  readonly productId: string;
  readonly humanIdentityId: string;
}

export interface RevokeTenantMembershipInput {
  readonly actorReference: string;
  readonly authorityScope?: AdministrationAuthorityScope;
  readonly authorityProductId?: string;
  readonly tenantId: string;
  readonly humanIdentityId: string;
}

export type AdministrationAuthorityScope =
  | "platform-administration"
  | "tenant-team-administration"
  | "internal-workforce-administration";

/**
 * Authoritative internal workforce administration service.
 *
 * HTTP routes never invoke this service without first passing through either
 * the Platform-administration or Tenant-Team principal policy adapter.
 */
export class WorkforceAdministration {
  constructor(
    private readonly repository: ControlPlaneRepository,
    private readonly identities: HumanIdentityRepository,
    private readonly credentials: EmailCredentialRepository,
    private readonly clock: Clock,
    private readonly atomically: AtomicExecutor = async (work) => work(),
  ) {}

  async resolveHumanIdentityByEmail(rawEmail: string): Promise<ResolvedHumanIdentity> {
    let email: NormalizedEmail;
    try {
      email = NormalizedEmail.from(rawEmail);
    } catch (cause) {
      if (cause instanceof InvalidEmailError) throw error("INVALID_EMAIL", "A valid email address is required");
      throw cause;
    }
    const credential = await this.credentials.findByNormalizedEmail(email);
    if (credential === null || credential.status !== "active") {
      throw error("IDENTITY_NOT_FOUND", "No active Human Identity was found");
    }
    const identity = await this.identities.findById(credential.humanIdentityId);
    if (identity === null || identity.status !== "active") {
      throw error("IDENTITY_NOT_FOUND", "No active Human Identity was found");
    }
    return {
      humanIdentityId: identity.id.value,
      displayName: null,
      email: email.value,
      status: identity.status,
    };
  }

  async listTenantWorkforce(tenantId: string): Promise<readonly TenantMembership[]> {
    await this.requireTenant(tenantId, false);
    return this.repository.listMembershipsForTenant(tenantId);
  }

  async inspectTenantMembership(tenantId: string, humanIdentityId: string): Promise<TenantMembership> {
    await this.requireTenant(tenantId, false);
    const membership = await this.repository.findMembership(tenantId, humanIdentityId);
    if (membership === null) throw error("MEMBERSHIP_NOT_FOUND", "Tenant Membership was not found");
    return membership;
  }

  async establishInitialTenantOwner(input: EstablishInitialTenantOwnerInput): Promise<TenantMembership> {
    requireActor(input.actorReference);
    return this.atomically(async () => {
      await this.requireActiveIdentity(input.humanIdentityId);
      await this.requireTenant(input.tenantId, true);
      const memberships = await this.repository.lockMembershipsForTenant(input.tenantId);
      const existing = memberships.find((membership) => membership.humanIdentityId === input.humanIdentityId) ?? null;
      if (existing?.status === "active" && existing.tenantRole === "owner") return existing;
      if (memberships.some((membership) => membership.status === "active" && membership.tenantRole === "owner")) {
        throw error("INITIAL_OWNER_ALREADY_ESTABLISHED", "Tenant already has an active Owner");
      }
      if (existing?.status === "retired") {
        throw error("MEMBERSHIP_RETIRED", "A retired Tenant Membership cannot be reactivated");
      }
      const now = this.clock.now();
      const owner: TenantMembership = {
        tenantId: input.tenantId,
        humanIdentityId: input.humanIdentityId,
        status: "active",
        tenantRole: "owner",
        createdAt: existing?.createdAt ?? now,
        updatedAt: now,
      };
      await this.repository.saveMembership(owner);
      await this.audit(
        existing === null ? "tenant.membership.granted" : "tenant.membership.role.changed",
        input.actorReference,
        `${input.tenantId}:${input.humanIdentityId}`,
        input.tenantId,
        undefined,
        {
          previousMembershipStatus: existing?.status ?? "none",
          membershipStatus: "active",
          previousTenantRole: existing?.tenantRole ?? "none",
          tenantRole: "owner",
        },
        input.authorityScope,
      );
      return owner;
    });
  }

  async grantProductWorkforceAccess(input: GrantProductWorkforceAccessInput): Promise<ProductWorkforceAccess> {
    const tenantRole = requireRole(input.tenantRole);
    requireActor(input.actorReference);
    return this.atomically(async () => {
      await this.requireActiveIdentity(input.humanIdentityId);
      await this.requireTenant(input.tenantId, true);
      await this.requireProduct(input.productId);
      const lockedMemberships = await this.repository.lockMembershipsForTenant(input.tenantId);
      const existingMembership = lockedMemberships.find((membership) => membership.humanIdentityId === input.humanIdentityId) ?? null;
      const existingParticipation = await this.repository.findParticipation(input.tenantId, input.productId);
      const existingEntitlement = await this.repository.findEntitlement(input.tenantId, input.productId, input.humanIdentityId);
      if (existingMembership?.status === "retired") throw error("MEMBERSHIP_RETIRED", "A retired Tenant Membership cannot be reactivated");
      if (existingParticipation?.status === "retired") throw error("PRODUCT_NOT_AVAILABLE", "Retired Product Participation cannot be reactivated");
      if (existingEntitlement?.status === "retired") throw error("ENTITLEMENT_RETIRED", "A retired Product Entitlement cannot be reactivated");
      if (existingMembership?.status === "active" && existingMembership.tenantRole === "owner" && tenantRole !== "owner") {
        assertAnotherActiveOwner(lockedMemberships, input.humanIdentityId);
      }

      const now = this.clock.now();
      const proposedMembership: TenantMembership = {
        tenantId: input.tenantId,
        humanIdentityId: input.humanIdentityId,
        status: "active",
        tenantRole,
        createdAt: existingMembership?.createdAt ?? now,
        updatedAt: now,
      };
      const membership = sameMembershipAuthority(existingMembership, proposedMembership) ? existingMembership! : proposedMembership;
      if (membership === proposedMembership) {
        await this.repository.saveMembership(membership);
        await this.audit(
          existingMembership === null ? "tenant.membership.granted" : existingMembership.tenantRole !== tenantRole ? "tenant.membership.role.changed" : "tenant.membership.reactivated",
          input.actorReference,
          `${input.tenantId}:${input.humanIdentityId}`,
          input.tenantId,
          input.productId,
          {
            previousMembershipStatus: existingMembership?.status ?? "none",
            membershipStatus: "active",
            previousTenantRole: existingMembership?.tenantRole ?? "none",
            tenantRole,
          },
          input.authorityScope,
        );
      }

      const participation: ProductParticipation = { tenantId: input.tenantId, productId: input.productId, status: "active" };
      if (existingParticipation?.status !== "active") {
        await this.repository.saveParticipation(participation);
        await this.audit("product.participation.established", input.actorReference, `${input.tenantId}:${input.productId}`, input.tenantId, input.productId, {
          previousParticipationStatus: existingParticipation?.status ?? "none",
          participationStatus: "active",
        }, input.authorityScope);
      }

      const entitlement: ProductEntitlement = { tenantId: input.tenantId, productId: input.productId, humanIdentityId: input.humanIdentityId, status: "active" };
      if (existingEntitlement?.status !== "active") {
        await this.repository.saveEntitlement(entitlement);
        await this.audit("product.entitlement.granted", input.actorReference, `${input.tenantId}:${input.productId}:${input.humanIdentityId}`, input.tenantId, input.productId, {
          previousEntitlementStatus: existingEntitlement?.status ?? "none",
          entitlementStatus: "active",
        }, input.authorityScope);
      }
      return { membership, participation, entitlement };
    });
  }

  async changeTenantRole(input: ChangeTenantRoleInput): Promise<TenantMembership> {
    const tenantRole = requireRole(input.tenantRole);
    requireActor(input.actorReference);
    return this.atomically(async () => {
      await this.requireTenant(input.tenantId, false);
      const memberships = await this.repository.lockMembershipsForTenant(input.tenantId);
      const membership = memberships.find((candidate) => candidate.humanIdentityId === input.humanIdentityId);
      if (membership === undefined) throw error("MEMBERSHIP_NOT_FOUND", "Tenant Membership was not found");
      if (membership.status !== "active") throw error("MEMBERSHIP_INACTIVE", "Only an active Tenant Membership can change role");
      if (membership.tenantRole === tenantRole) return membership;
      if (membership.tenantRole === "owner" && tenantRole !== "owner") assertAnotherActiveOwner(memberships, input.humanIdentityId);
      const updated = { ...membership, tenantRole, updatedAt: this.clock.now() };
      await this.repository.saveMembership(updated);
      await this.audit("tenant.membership.role.changed", input.actorReference, `${input.tenantId}:${input.humanIdentityId}`, input.tenantId, input.authorityProductId, {
        previousTenantRole: membership.tenantRole,
        tenantRole,
      }, input.authorityScope);
      return updated;
    });
  }

  async revokeProductAccess(input: RevokeProductAccessInput): Promise<ProductEntitlement | null> {
    requireActor(input.actorReference);
    return this.atomically(async () => {
      await this.requireTenant(input.tenantId, false);
      await this.requireProduct(input.productId, false);
      const entitlement = await this.repository.findEntitlement(input.tenantId, input.productId, input.humanIdentityId);
      if (entitlement === null || entitlement.status !== "active") return entitlement;
      const suspended: ProductEntitlement = { ...entitlement, status: "suspended" };
      await this.repository.saveEntitlement(suspended);
      await this.audit("product.entitlement.revoked", input.actorReference, `${input.tenantId}:${input.productId}:${input.humanIdentityId}`, input.tenantId, input.productId, {
        previousEntitlementStatus: "active",
        entitlementStatus: "suspended",
      }, input.authorityScope);
      return suspended;
    });
  }

  async revokeTenantMembership(input: RevokeTenantMembershipInput): Promise<TenantMembership | null> {
    requireActor(input.actorReference);
    return this.atomically(async () => {
      await this.requireTenant(input.tenantId, false);
      const memberships = await this.repository.lockMembershipsForTenant(input.tenantId);
      const membership = memberships.find((candidate) => candidate.humanIdentityId === input.humanIdentityId);
      if (membership === undefined || membership.status !== "active") return membership ?? null;
      if (membership.tenantRole === "owner") assertAnotherActiveOwner(memberships, input.humanIdentityId);
      const suspended = { ...membership, status: "suspended" as const, updatedAt: this.clock.now() };
      await this.repository.saveMembership(suspended);
      const entitlements = await this.repository.listEntitlementsForHuman(input.tenantId, input.humanIdentityId);
      for (const entitlement of entitlements) {
        if (entitlement.status === "active") {
          await this.repository.saveEntitlement({ ...entitlement, status: "suspended" });
          await this.audit(
            "product.entitlement.revoked",
            input.actorReference,
            `${input.tenantId}:${entitlement.productId}:${input.humanIdentityId}`,
            input.tenantId,
            entitlement.productId,
            {
              previousEntitlementStatus: "active",
              entitlementStatus: "suspended",
            },
            input.authorityScope,
          );
        }
      }
      await this.audit("tenant.membership.revoked", input.actorReference, `${input.tenantId}:${input.humanIdentityId}`, input.tenantId, input.authorityProductId, {
        tenantRole: membership.tenantRole,
        previousMembershipStatus: "active",
        membershipStatus: "suspended",
      }, input.authorityScope);
      return suspended;
    });
  }

  private async requireActiveIdentity(humanIdentityId: string): Promise<void> {
    const identity = await this.identities.findById(HumanIdentityId.from(humanIdentityId));
    if (identity === null || identity.status !== "active") throw error("IDENTITY_NOT_FOUND", "An active Human Identity is required");
  }

  private async requireTenant(tenantId: string, active = true): Promise<void> {
    const tenant = await this.repository.findTenant(tenantId);
    if (tenant === null) throw error("TENANT_NOT_FOUND", "Tenant was not found");
    if (active && tenant.status !== "active") throw error("TENANT_INACTIVE", "Tenant is not active");
  }

  private async requireProduct(productId: string, active = true): Promise<void> {
    const product = await this.repository.findProduct(productId);
    if (product === null) throw error("PRODUCT_NOT_FOUND", "Registered Product was not found");
    if (active && product.status !== "active") throw error("PRODUCT_NOT_AVAILABLE", "Registered Product is not active");
  }

  private async audit(
    eventType: string,
    actorReference: string,
    subjectReference: string,
    tenantId: string,
    productId?: string,
    eventData?: Readonly<Record<string, string>>,
    authorityScope: AdministrationAuthorityScope = "internal-workforce-administration",
  ): Promise<void> {
    await this.repository.appendAudit({
      id: randomUUID(),
      eventType,
      actorReference,
      subjectReference,
      tenantId,
      ...(productId === undefined ? {} : { productId }),
      eventData: { authorityScope, ...(eventData ?? {}) },
      occurredAt: this.clock.now(),
    });
  }
}

function requireRole(value: string): TenantWorkforceRole {
  if (!isTenantWorkforceRole(value)) throw error("INVALID_TENANT_ROLE", "Tenant workforce role must be owner, admin, or staff");
  return value;
}

function requireActor(actorReference: string): void {
  if (actorReference.trim().length === 0) throw error("NOT_AUTHORIZED", "An accountable Platform administration actor is required");
}

function assertAnotherActiveOwner(memberships: readonly TenantMembership[], humanIdentityId: string): void {
  const anotherOwner = memberships.some((membership) => membership.humanIdentityId !== humanIdentityId && membership.status === "active" && membership.tenantRole === "owner");
  if (!anotherOwner) throw error("LAST_OWNER", "The final active tenant owner cannot be demoted or revoked");
}

function sameMembershipAuthority(current: TenantMembership | null, proposed: TenantMembership): boolean {
  return current?.status === proposed.status && current.tenantRole === proposed.tenantRole;
}

function error(code: string, message: string): WorkforceAdministrationError {
  return new WorkforceAdministrationError(code, message);
}
