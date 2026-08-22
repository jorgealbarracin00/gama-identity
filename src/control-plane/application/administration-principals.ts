import { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import type { HumanIdentityRepository } from "../../identity/ports/human-identity-repository.js";
import type { TenantWorkforceRole } from "../models.js";
import type { ControlPlaneRepository } from "../ports/control-plane-repository.js";
import type { ControlPlane } from "./control-plane.js";

export class AdministrationAuthorizationError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = "AdministrationAuthorizationError";
  }
}

export interface PlatformAdministrationPrincipal {
  readonly kind: "platform-administration";
  readonly humanIdentityId: string;
  readonly platformRole: "administrator";
  readonly actorReference: string;
}

export interface TenantWorkforcePrincipal {
  readonly kind: "tenant-workforce";
  readonly humanIdentityId: string;
  readonly tenantId: string;
  readonly productId: string;
  readonly tenantRole: TenantWorkforceRole;
  readonly actorReference: string;
}

/**
 * Derives administration principals from current authoritative state.
 * Sessions establish the Human Identity; this service deliberately rechecks
 * authority for every request so a revoked role does not survive in a session.
 */
export class AdministrationPrincipals {
  constructor(
    private readonly repository: ControlPlaneRepository,
    private readonly identities: HumanIdentityRepository,
    private readonly controlPlane: ControlPlane,
  ) {}

  async platform(humanIdentityId: string): Promise<PlatformAdministrationPrincipal> {
    const identity = await this.identities.findById(HumanIdentityId.from(humanIdentityId));
    const membership = await this.repository.findPlatformAdministrationMembership(humanIdentityId);
    if (
      identity?.status !== "active" ||
      membership?.status !== "active" ||
      membership.platformRole !== "administrator"
    ) {
      throw authorizationError("NOT_PLATFORM_ADMIN", "Platform administration authority is required");
    }
    return {
      kind: "platform-administration",
      humanIdentityId,
      platformRole: membership.platformRole,
      actorReference: `human-identity:${humanIdentityId}`,
    };
  }

  async tenant(
    humanIdentityId: string,
    tenantId: string,
    productId: string,
  ): Promise<TenantWorkforcePrincipal> {
    const context = await this.controlPlane.workforceContext(humanIdentityId, tenantId, productId);
    if (!context.workforceContextSatisfied || context.tenantRole === null) {
      throw authorizationError("NOT_TENANT_ADMIN", "An active workforce context is required for Team administration");
    }
    return {
      kind: "tenant-workforce",
      humanIdentityId,
      tenantId: context.tenantId,
      productId: context.productId,
      tenantRole: context.tenantRole,
      actorReference: `human-identity:${humanIdentityId}`,
    };
  }
}

export function authorizationError(code: string, message: string): AdministrationAuthorizationError {
  return new AdministrationAuthorizationError(code, message);
}
