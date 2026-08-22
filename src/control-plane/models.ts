export type LifecycleStatus = "active" | "suspended" | "retired";

export const PLATFORM_ADMINISTRATION_ROLES = ["administrator"] as const;
export type PlatformAdministrationRole = (typeof PLATFORM_ADMINISTRATION_ROLES)[number];

export const TENANT_WORKFORCE_ROLES = ["owner", "admin", "staff"] as const;
export type TenantWorkforceRole = (typeof TENANT_WORKFORCE_ROLES)[number];

export function isTenantWorkforceRole(value: string): value is TenantWorkforceRole {
  return TENANT_WORKFORCE_ROLES.some((role) => role === value);
}

export interface RegisteredProduct {
  readonly id: string;
  readonly displayName: string;
  readonly status: LifecycleStatus;
}

export interface Tenant {
  readonly id: string;
  readonly displayName: string;
  readonly status: LifecycleStatus;
}

export interface TenantProvisioningRequest {
  readonly idempotencyKey: string;
  readonly tenantId: string;
  readonly displayName: string;
  readonly initialOwnerHumanIdentityId: string;
  readonly createdAt: Date;
}

export interface PlatformAdministrationMembership {
  readonly humanIdentityId: string;
  readonly platformRole: PlatformAdministrationRole;
  readonly status: LifecycleStatus;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export interface ProductWorkload {
  readonly id: string;
  readonly productId: string;
  readonly secretHash: string;
  readonly status: LifecycleStatus;
}

export interface TenantMembership {
  readonly tenantId: string;
  readonly humanIdentityId: string;
  readonly status: LifecycleStatus;
  readonly tenantRole: TenantWorkforceRole;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export interface ProductParticipation {
  readonly tenantId: string;
  readonly productId: string;
  readonly status: LifecycleStatus;
}

export interface ProductEntitlement {
  readonly tenantId: string;
  readonly productId: string;
  readonly humanIdentityId: string;
  readonly status: LifecycleStatus;
}

export interface PlatformAuditEvent {
  readonly id: string;
  readonly eventType: string;
  readonly actorReference: string;
  readonly subjectReference: string;
  readonly productId?: string;
  readonly tenantId?: string;
  readonly eventData?: Readonly<Record<string, string>>;
  readonly occurredAt: Date;
}

export const COCO_PRODUCT_ID = "coco-the-llama";
export const COCO_WORKLOAD_ID = "coco-backend";
export const COCO_DEVELOPMENT_TENANT_ID = "coco-development";
