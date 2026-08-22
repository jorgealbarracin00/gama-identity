import type { EmailCredentialRepository } from "../../authentication/credentials/ports/email-credential-repository.js";
import { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type {
  LifecycleStatus,
  ProductEntitlement,
  TenantMembership,
  TenantWorkforceRole,
} from "../models.js";
import type { ControlPlaneRepository } from "../ports/control-plane-repository.js";
import {
  AdministrationPrincipals,
  type TenantWorkforcePrincipal,
  authorizationError,
} from "./administration-principals.js";
import type { ProductWorkforceAccess } from "./workforce-administration.js";
import { WorkforceAdministration } from "./workforce-administration.js";

export interface TenantAdministrationContext {
  readonly actorHumanIdentityId: string;
  readonly tenantId: string;
  readonly productId: string;
}

export interface TeamMemberProjection {
  readonly humanIdentityId: string;
  readonly email: string | null;
  readonly tenantRole: TenantWorkforceRole;
  readonly membershipStatus: LifecycleStatus;
  readonly productParticipationStatus: LifecycleStatus | null;
  readonly productEntitlementStatus: LifecycleStatus | null;
}

export class TenantTeamAdministration {
  constructor(
    private readonly principals: AdministrationPrincipals,
    private readonly workforce: WorkforceAdministration,
    private readonly repository: ControlPlaneRepository,
    private readonly credentials: EmailCredentialRepository,
  ) {}

  async listTeam(context: TenantAdministrationContext): Promise<readonly TeamMemberProjection[]> {
    const principal = await this.requireTeamAdministrator(context);
    const [memberships, participation] = await Promise.all([
      this.workforce.listTenantWorkforce(principal.tenantId),
      this.repository.findParticipation(principal.tenantId, principal.productId),
    ]);
    return Promise.all(memberships.map(async (membership) => {
      const [credential, entitlement] = await Promise.all([
        this.credentials.findByHumanIdentityId(HumanIdentityId.from(membership.humanIdentityId)),
        this.repository.findEntitlement(principal.tenantId, principal.productId, membership.humanIdentityId),
      ]);
      return {
        humanIdentityId: membership.humanIdentityId,
        email: credential?.email.value ?? null,
        tenantRole: membership.tenantRole,
        membershipStatus: membership.status,
        productParticipationStatus: participation?.status ?? null,
        productEntitlementStatus: entitlement?.status ?? null,
      };
    }));
  }

  async addTeamMember(
    context: TenantAdministrationContext,
    email: string,
    requestedRole: string,
  ): Promise<ProductWorkforceAccess> {
    const principal = await this.requireTeamAdministrator(context);
    const target = await this.workforce.resolveHumanIdentityByEmail(email);
    this.rejectSelfMutation(principal, target.humanIdentityId);
    const existing = await this.repository.findMembership(principal.tenantId, target.humanIdentityId);
    this.authorizeGrant(principal, existing, requestedRole);
    return this.workforce.grantProductWorkforceAccess({
      actorReference: principal.actorReference,
      authorityScope: "tenant-team-administration",
      authorityProductId: principal.productId,
      tenantId: principal.tenantId,
      productId: principal.productId,
      humanIdentityId: target.humanIdentityId,
      tenantRole: requestedRole,
    });
  }

  async changeTeamMemberRole(
    context: TenantAdministrationContext,
    targetHumanIdentityId: string,
    requestedRole: string,
  ): Promise<TenantMembership> {
    const principal = await this.requireTeamAdministrator(context);
    this.rejectSelfMutation(principal, targetHumanIdentityId);
    const target = await this.workforce.inspectTenantMembership(principal.tenantId, targetHumanIdentityId);
    if (principal.tenantRole !== "owner") {
      throw authorizationError("ROLE_ESCALATION_FORBIDDEN", "Tenant administrators cannot change Tenant roles");
    }
    this.requireOwnerManageableTarget(target);
    this.requireOwnerAssignableRole(requestedRole);
    return this.workforce.changeTenantRole({
      actorReference: principal.actorReference,
      authorityScope: "tenant-team-administration",
      authorityProductId: principal.productId,
      tenantId: principal.tenantId,
      humanIdentityId: targetHumanIdentityId,
      tenantRole: requestedRole,
    });
  }

  async grantProductAccess(
    context: TenantAdministrationContext,
    targetHumanIdentityId: string,
  ): Promise<ProductWorkforceAccess> {
    const principal = await this.requireTeamAdministrator(context);
    this.rejectSelfMutation(principal, targetHumanIdentityId);
    const target = await this.workforce.inspectTenantMembership(principal.tenantId, targetHumanIdentityId);
    this.authorizeExistingTarget(principal, target);
    this.requireActiveTarget(target);
    return this.workforce.grantProductWorkforceAccess({
      actorReference: principal.actorReference,
      authorityScope: "tenant-team-administration",
      authorityProductId: principal.productId,
      tenantId: principal.tenantId,
      productId: principal.productId,
      humanIdentityId: targetHumanIdentityId,
      tenantRole: target.tenantRole,
    });
  }

  async revokeProductAccess(
    context: TenantAdministrationContext,
    targetHumanIdentityId: string,
  ): Promise<ProductEntitlement | null> {
    const principal = await this.requireTeamAdministrator(context);
    this.rejectSelfMutation(principal, targetHumanIdentityId);
    const target = await this.workforce.inspectTenantMembership(principal.tenantId, targetHumanIdentityId);
    this.authorizeExistingTarget(principal, target);
    this.requireActiveTarget(target);
    return this.workforce.revokeProductAccess({
      actorReference: principal.actorReference,
      authorityScope: "tenant-team-administration",
      authorityProductId: principal.productId,
      tenantId: principal.tenantId,
      productId: principal.productId,
      humanIdentityId: targetHumanIdentityId,
    });
  }

  async removeTeamMember(
    context: TenantAdministrationContext,
    targetHumanIdentityId: string,
  ): Promise<TenantMembership | null> {
    const principal = await this.requireTeamAdministrator(context);
    this.rejectSelfMutation(principal, targetHumanIdentityId);
    const target = await this.workforce.inspectTenantMembership(principal.tenantId, targetHumanIdentityId);
    this.authorizeExistingTarget(principal, target);
    return this.workforce.revokeTenantMembership({
      actorReference: principal.actorReference,
      authorityScope: "tenant-team-administration",
      authorityProductId: principal.productId,
      tenantId: principal.tenantId,
      humanIdentityId: targetHumanIdentityId,
    });
  }

  private async requireTeamAdministrator(context: TenantAdministrationContext): Promise<TenantWorkforcePrincipal> {
    const principal = await this.principals.tenant(
      context.actorHumanIdentityId,
      context.tenantId,
      context.productId,
    );
    if (principal.tenantRole !== "owner" && principal.tenantRole !== "admin") {
      throw authorizationError("NOT_TENANT_ADMIN", "Owner or Admin Tenant role is required for Team administration");
    }
    return principal;
  }

  private authorizeGrant(
    principal: TenantWorkforcePrincipal,
    current: TenantMembership | null,
    requestedRole: string,
  ): void {
    if (principal.tenantRole === "owner") {
      if (current !== null) this.requireOwnerManageableTarget(current);
      this.requireOwnerAssignableRole(requestedRole);
      return;
    }
    if (current !== null && current.tenantRole !== "staff") {
      throw authorizationError("ROLE_ESCALATION_FORBIDDEN", "Tenant Admin may manage Staff only");
    }
    if (requestedRole !== "staff") {
      throw authorizationError("ROLE_ESCALATION_FORBIDDEN", "Tenant Admin may add Staff only");
    }
  }

  private authorizeExistingTarget(principal: TenantWorkforcePrincipal, target: TenantMembership): void {
    if (principal.tenantRole === "owner") {
      this.requireOwnerManageableTarget(target);
      return;
    }
    if (target.tenantRole !== "staff") {
      throw authorizationError("ROLE_ESCALATION_FORBIDDEN", "Tenant Admin may manage Staff only");
    }
  }

  private requireOwnerManageableTarget(target: TenantMembership): void {
    if (target.tenantRole === "owner") {
      throw authorizationError("ROLE_ESCALATION_FORBIDDEN", "Owner membership changes require Platform administration");
    }
  }

  private requireOwnerAssignableRole(requestedRole: string): void {
    if (requestedRole !== "admin" && requestedRole !== "staff") {
      throw authorizationError("ROLE_ESCALATION_FORBIDDEN", "Tenant Owner may assign Admin or Staff only");
    }
  }

  private requireActiveTarget(target: TenantMembership): void {
    if (target.status !== "active") {
      throw authorizationError("MEMBERSHIP_INACTIVE", "Product access requires an active Tenant Membership");
    }
  }

  private rejectSelfMutation(principal: TenantWorkforcePrincipal, targetHumanIdentityId: string): void {
    if (principal.humanIdentityId === targetHumanIdentityId) {
      throw authorizationError("SELF_MUTATION_FORBIDDEN", "Tenant Team administration cannot mutate the acting Principal");
    }
  }
}
