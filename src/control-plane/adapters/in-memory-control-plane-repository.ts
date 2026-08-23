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
import type { ControlPlaneRepository } from "../ports/control-plane-repository.js";

export class InMemoryControlPlaneRepository implements ControlPlaneRepository {
  readonly auditEvents: PlatformAuditEvent[] = [];
  private readonly products = new Map<string, RegisteredProduct>();
  private readonly tenants = new Map<string, Tenant>();
  private readonly tenantProvisioningRequests = new Map<string, TenantProvisioningRequest>();
  private readonly platformAdministrationMemberships = new Map<string, PlatformAdministrationMembership>();
  private readonly workloads = new Map<string, ProductWorkload>();
  private readonly memberships = new Map<string, TenantMembership>();
  private readonly participations = new Map<string, ProductParticipation>();
  private readonly entitlements = new Map<string, ProductEntitlement>();

  async saveProduct(product: RegisteredProduct): Promise<void> { this.products.set(product.id, product); }
  async findProduct(id: string): Promise<RegisteredProduct | null> { return this.products.get(id) ?? null; }
  async listProducts(): Promise<readonly RegisteredProduct[]> { return [...this.products.values()].sort((left, right) => left.displayName.localeCompare(right.displayName) || left.id.localeCompare(right.id)); }
  async saveTenant(tenant: Tenant): Promise<void> { this.tenants.set(tenant.id, tenant); }
  async insertTenantIfAbsent(tenant: Tenant): Promise<boolean> {
    if (this.tenants.has(tenant.id)) return false;
    this.tenants.set(tenant.id, tenant);
    return true;
  }
  async findTenant(id: string): Promise<Tenant | null> { return this.tenants.get(id) ?? null; }
  async listTenants(): Promise<readonly Tenant[]> { return [...this.tenants.values()].sort((left, right) => left.id.localeCompare(right.id)); }
  async lockTenant(_id: string): Promise<void> {}
  async insertTenantProvisioningRequestIfAbsent(request: TenantProvisioningRequest): Promise<boolean> {
    if (this.tenantProvisioningRequests.has(request.idempotencyKey)) return false;
    this.tenantProvisioningRequests.set(request.idempotencyKey, request);
    return true;
  }
  async findTenantProvisioningRequest(idempotencyKey: string): Promise<TenantProvisioningRequest | null> { return this.tenantProvisioningRequests.get(idempotencyKey) ?? null; }
  async insertPlatformAdministrationMembershipIfAbsent(membership: PlatformAdministrationMembership): Promise<boolean> {
    if (this.platformAdministrationMemberships.has(membership.humanIdentityId)) return false;
    this.platformAdministrationMemberships.set(membership.humanIdentityId, membership);
    return true;
  }
  async savePlatformAdministrationMembership(membership: PlatformAdministrationMembership): Promise<void> { this.platformAdministrationMemberships.set(membership.humanIdentityId, membership); }
  async findPlatformAdministrationMembership(humanIdentityId: string): Promise<PlatformAdministrationMembership | null> { return this.platformAdministrationMemberships.get(humanIdentityId) ?? null; }
  async saveWorkload(workload: ProductWorkload): Promise<void> { this.workloads.set(workload.id, workload); }
  async findWorkload(id: string): Promise<ProductWorkload | null> { return this.workloads.get(id) ?? null; }
  async saveMembership(membership: TenantMembership): Promise<void> { this.memberships.set(`${membership.tenantId}:${membership.humanIdentityId}`, membership); }
  async findMembership(tenantId: string, humanIdentityId: string): Promise<TenantMembership | null> { return this.memberships.get(`${tenantId}:${humanIdentityId}`) ?? null; }
  async listMembershipsForTenant(tenantId: string): Promise<readonly TenantMembership[]> { return [...this.memberships.values()].filter((membership) => membership.tenantId === tenantId); }
  async listMembershipsForHuman(humanIdentityId: string): Promise<readonly TenantMembership[]> { return [...this.memberships.values()].filter((membership) => membership.humanIdentityId === humanIdentityId); }
  async lockMembershipsForTenant(tenantId: string): Promise<readonly TenantMembership[]> { return this.listMembershipsForTenant(tenantId); }
  async saveParticipation(participation: ProductParticipation): Promise<void> { this.participations.set(`${participation.tenantId}:${participation.productId}`, participation); }
  async findParticipation(tenantId: string, productId: string): Promise<ProductParticipation | null> { return this.participations.get(`${tenantId}:${productId}`) ?? null; }
  async listParticipationsForTenant(tenantId: string): Promise<readonly ProductParticipation[]> { return [...this.participations.values()].filter((participation) => participation.tenantId === tenantId).sort((left, right) => left.productId.localeCompare(right.productId)); }
  async saveEntitlement(entitlement: ProductEntitlement): Promise<void> { this.entitlements.set(`${entitlement.tenantId}:${entitlement.productId}:${entitlement.humanIdentityId}`, entitlement); }
  async findEntitlement(tenantId: string, productId: string, humanIdentityId: string): Promise<ProductEntitlement | null> { return this.entitlements.get(`${tenantId}:${productId}:${humanIdentityId}`) ?? null; }
  async listEntitlementsForHuman(tenantId: string, humanIdentityId: string): Promise<readonly ProductEntitlement[]> { return [...this.entitlements.values()].filter((entitlement) => entitlement.tenantId === tenantId && entitlement.humanIdentityId === humanIdentityId); }
  async listEntitlementsForHumanAcrossTenants(humanIdentityId: string): Promise<readonly ProductEntitlement[]> { return [...this.entitlements.values()].filter((entitlement) => entitlement.humanIdentityId === humanIdentityId); }
  async appendAudit(event: PlatformAuditEvent): Promise<void> { this.auditEvents.push(event); }
}
