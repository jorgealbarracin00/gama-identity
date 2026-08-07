import type {
  PlatformAuditEvent,
  ProductEntitlement,
  ProductParticipation,
  ProductWorkload,
  RegisteredProduct,
  Tenant,
  TenantMembership,
} from "../models.js";
import type { ControlPlaneRepository } from "../ports/control-plane-repository.js";

export class InMemoryControlPlaneRepository implements ControlPlaneRepository {
  readonly auditEvents: PlatformAuditEvent[] = [];
  private readonly products = new Map<string, RegisteredProduct>();
  private readonly tenants = new Map<string, Tenant>();
  private readonly workloads = new Map<string, ProductWorkload>();
  private readonly memberships = new Map<string, TenantMembership>();
  private readonly participations = new Map<string, ProductParticipation>();
  private readonly entitlements = new Map<string, ProductEntitlement>();

  async saveProduct(product: RegisteredProduct): Promise<void> { this.products.set(product.id, product); }
  async findProduct(id: string): Promise<RegisteredProduct | null> { return this.products.get(id) ?? null; }
  async saveTenant(tenant: Tenant): Promise<void> { this.tenants.set(tenant.id, tenant); }
  async findTenant(id: string): Promise<Tenant | null> { return this.tenants.get(id) ?? null; }
  async saveWorkload(workload: ProductWorkload): Promise<void> { this.workloads.set(workload.id, workload); }
  async findWorkload(id: string): Promise<ProductWorkload | null> { return this.workloads.get(id) ?? null; }
  async saveMembership(membership: TenantMembership): Promise<void> { this.memberships.set(`${membership.tenantId}:${membership.humanIdentityId}`, membership); }
  async findMembership(tenantId: string, humanIdentityId: string): Promise<TenantMembership | null> { return this.memberships.get(`${tenantId}:${humanIdentityId}`) ?? null; }
  async saveParticipation(participation: ProductParticipation): Promise<void> { this.participations.set(`${participation.tenantId}:${participation.productId}`, participation); }
  async findParticipation(tenantId: string, productId: string): Promise<ProductParticipation | null> { return this.participations.get(`${tenantId}:${productId}`) ?? null; }
  async saveEntitlement(entitlement: ProductEntitlement): Promise<void> { this.entitlements.set(`${entitlement.tenantId}:${entitlement.productId}:${entitlement.humanIdentityId}`, entitlement); }
  async findEntitlement(tenantId: string, productId: string, humanIdentityId: string): Promise<ProductEntitlement | null> { return this.entitlements.get(`${tenantId}:${productId}:${humanIdentityId}`) ?? null; }
  async appendAudit(event: PlatformAuditEvent): Promise<void> { this.auditEvents.push(event); }
}
