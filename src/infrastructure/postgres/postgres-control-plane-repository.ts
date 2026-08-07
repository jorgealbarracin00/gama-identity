import type { DatabaseQuery } from "./database.js";
import type {
  PlatformAuditEvent,
  ProductEntitlement,
  ProductParticipation,
  ProductWorkload,
  RegisteredProduct,
  Tenant,
  TenantMembership,
} from "../../control-plane/models.js";
import type { ControlPlaneRepository } from "../../control-plane/ports/control-plane-repository.js";

type StatusRow = { id: string; display_name: string; status: "active" | "suspended" | "retired" };
type WorkloadRow = { id: string; product_id: string; secret_hash: string; status: "active" | "suspended" | "retired" };
type RelationshipRow = { status: "active" | "suspended" | "retired" };

export class PostgresControlPlaneRepository implements ControlPlaneRepository {
  constructor(private readonly database: DatabaseQuery) {}

  async saveProduct(product: RegisteredProduct): Promise<void> {
    await this.database.query(`INSERT INTO registered_products (id, display_name, status) VALUES ($1, $2, $3)
      ON CONFLICT (id) DO UPDATE SET display_name = EXCLUDED.display_name, status = EXCLUDED.status`, [product.id, product.displayName, product.status]);
  }
  async findProduct(id: string): Promise<RegisteredProduct | null> {
    const result = await this.database.query<StatusRow>("SELECT id, display_name, status FROM registered_products WHERE id = $1", [id]);
    const row = result.rows[0]; return row === undefined ? null : { id: row.id, displayName: row.display_name, status: row.status };
  }
  async saveTenant(tenant: Tenant): Promise<void> {
    await this.database.query(`INSERT INTO tenants (id, display_name, status) VALUES ($1, $2, $3)
      ON CONFLICT (id) DO UPDATE SET display_name = EXCLUDED.display_name, status = EXCLUDED.status`, [tenant.id, tenant.displayName, tenant.status]);
  }
  async findTenant(id: string): Promise<Tenant | null> {
    const result = await this.database.query<StatusRow>("SELECT id, display_name, status FROM tenants WHERE id = $1", [id]);
    const row = result.rows[0]; return row === undefined ? null : { id: row.id, displayName: row.display_name, status: row.status };
  }
  async saveWorkload(workload: ProductWorkload): Promise<void> {
    await this.database.query(`INSERT INTO product_workloads (id, product_id, secret_hash, status) VALUES ($1, $2, $3, $4)
      ON CONFLICT (id) DO UPDATE SET product_id = EXCLUDED.product_id, secret_hash = EXCLUDED.secret_hash, status = EXCLUDED.status`, [workload.id, workload.productId, workload.secretHash, workload.status]);
  }
  async findWorkload(id: string): Promise<ProductWorkload | null> {
    const result = await this.database.query<WorkloadRow>("SELECT id, product_id, secret_hash, status FROM product_workloads WHERE id = $1", [id]);
    const row = result.rows[0]; return row === undefined ? null : { id: row.id, productId: row.product_id, secretHash: row.secret_hash, status: row.status };
  }
  async saveMembership(value: TenantMembership): Promise<void> {
    await this.database.query(`INSERT INTO tenant_memberships (tenant_id, human_identity_id, status) VALUES ($1, $2, $3)
      ON CONFLICT (tenant_id, human_identity_id) DO UPDATE SET status = EXCLUDED.status`, [value.tenantId, value.humanIdentityId, value.status]);
  }
  async findMembership(tenantId: string, humanIdentityId: string): Promise<TenantMembership | null> {
    const result = await this.database.query<RelationshipRow>("SELECT status FROM tenant_memberships WHERE tenant_id = $1 AND human_identity_id = $2", [tenantId, humanIdentityId]);
    const row = result.rows[0]; return row === undefined ? null : { tenantId, humanIdentityId, status: row.status };
  }
  async saveParticipation(value: ProductParticipation): Promise<void> {
    await this.database.query(`INSERT INTO product_participations (tenant_id, product_id, status) VALUES ($1, $2, $3)
      ON CONFLICT (tenant_id, product_id) DO UPDATE SET status = EXCLUDED.status`, [value.tenantId, value.productId, value.status]);
  }
  async findParticipation(tenantId: string, productId: string): Promise<ProductParticipation | null> {
    const result = await this.database.query<RelationshipRow>("SELECT status FROM product_participations WHERE tenant_id = $1 AND product_id = $2", [tenantId, productId]);
    const row = result.rows[0]; return row === undefined ? null : { tenantId, productId, status: row.status };
  }
  async saveEntitlement(value: ProductEntitlement): Promise<void> {
    await this.database.query(`INSERT INTO product_entitlements (tenant_id, product_id, human_identity_id, status) VALUES ($1, $2, $3, $4)
      ON CONFLICT (tenant_id, product_id, human_identity_id) DO UPDATE SET status = EXCLUDED.status`, [value.tenantId, value.productId, value.humanIdentityId, value.status]);
  }
  async findEntitlement(tenantId: string, productId: string, humanIdentityId: string): Promise<ProductEntitlement | null> {
    const result = await this.database.query<RelationshipRow>("SELECT status FROM product_entitlements WHERE tenant_id = $1 AND product_id = $2 AND human_identity_id = $3", [tenantId, productId, humanIdentityId]);
    const row = result.rows[0]; return row === undefined ? null : { tenantId, productId, humanIdentityId, status: row.status };
  }
  async appendAudit(event: PlatformAuditEvent): Promise<void> {
    await this.database.query(`INSERT INTO platform_audit_events (id, event_type, actor_reference, subject_reference, product_id, tenant_id, occurred_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7)`, [event.id, event.eventType, event.actorReference, event.subjectReference, event.productId ?? null, event.tenantId ?? null, event.occurredAt]);
  }
}
