import type {
  PlatformAuditEvent,
  PlatformAdministrationMembership,
  ProductEntitlement,
  ProductParticipation,
  ProductWorkload,
  RegisteredProduct,
  Tenant,
  TenantMembership,
  TenantProvisioningRequest,
} from "../models.js";

export interface ControlPlaneRepository {
  saveProduct(product: RegisteredProduct): Promise<void>;
  findProduct(id: string): Promise<RegisteredProduct | null>;
  listProducts(): Promise<readonly RegisteredProduct[]>;
  saveTenant(tenant: Tenant): Promise<void>;
  insertTenantIfAbsent(tenant: Tenant): Promise<boolean>;
  findTenant(id: string): Promise<Tenant | null>;
  listTenants(): Promise<readonly Tenant[]>;
  lockTenant(id: string): Promise<void>;
  insertTenantProvisioningRequestIfAbsent(request: TenantProvisioningRequest): Promise<boolean>;
  findTenantProvisioningRequest(idempotencyKey: string): Promise<TenantProvisioningRequest | null>;
  insertPlatformAdministrationMembershipIfAbsent(membership: PlatformAdministrationMembership): Promise<boolean>;
  savePlatformAdministrationMembership(membership: PlatformAdministrationMembership): Promise<void>;
  findPlatformAdministrationMembership(humanIdentityId: string): Promise<PlatformAdministrationMembership | null>;
  saveWorkload(workload: ProductWorkload): Promise<void>;
  findWorkload(id: string): Promise<ProductWorkload | null>;
  saveMembership(membership: TenantMembership): Promise<void>;
  findMembership(tenantId: string, humanIdentityId: string): Promise<TenantMembership | null>;
  listMembershipsForTenant(tenantId: string): Promise<readonly TenantMembership[]>;
  lockMembershipsForTenant(tenantId: string): Promise<readonly TenantMembership[]>;
  saveParticipation(participation: ProductParticipation): Promise<void>;
  findParticipation(tenantId: string, productId: string): Promise<ProductParticipation | null>;
  listParticipationsForTenant(tenantId: string): Promise<readonly ProductParticipation[]>;
  saveEntitlement(entitlement: ProductEntitlement): Promise<void>;
  findEntitlement(tenantId: string, productId: string, humanIdentityId: string): Promise<ProductEntitlement | null>;
  listEntitlementsForHuman(tenantId: string, humanIdentityId: string): Promise<readonly ProductEntitlement[]>;
  appendAudit(event: PlatformAuditEvent): Promise<void>;
}
