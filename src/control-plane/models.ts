export type LifecycleStatus = "active" | "suspended" | "retired";

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
  readonly occurredAt: Date;
}

export const COCO_PRODUCT_ID = "coco-the-llama";
export const COCO_WORKLOAD_ID = "coco-backend";
export const COCO_DEVELOPMENT_TENANT_ID = "coco-development";
