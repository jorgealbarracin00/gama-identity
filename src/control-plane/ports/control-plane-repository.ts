import type {
  PlatformAuditEvent,
  ProductEntitlement,
  ProductParticipation,
  ProductWorkload,
  RegisteredProduct,
  Tenant,
  TenantMembership,
} from "../models.js";

export interface ControlPlaneRepository {
  saveProduct(product: RegisteredProduct): Promise<void>;
  findProduct(id: string): Promise<RegisteredProduct | null>;
  saveTenant(tenant: Tenant): Promise<void>;
  findTenant(id: string): Promise<Tenant | null>;
  saveWorkload(workload: ProductWorkload): Promise<void>;
  findWorkload(id: string): Promise<ProductWorkload | null>;
  saveMembership(membership: TenantMembership): Promise<void>;
  findMembership(tenantId: string, humanIdentityId: string): Promise<TenantMembership | null>;
  saveParticipation(participation: ProductParticipation): Promise<void>;
  findParticipation(tenantId: string, productId: string): Promise<ProductParticipation | null>;
  saveEntitlement(entitlement: ProductEntitlement): Promise<void>;
  findEntitlement(tenantId: string, productId: string, humanIdentityId: string): Promise<ProductEntitlement | null>;
  appendAudit(event: PlatformAuditEvent): Promise<void>;
}
