import type { DatabaseQuery } from "./database.js";
import type {
  PlatformAuditEvent,
  PlatformAdministrationMembership,
  PlatformAdministrationRole,
  ProductEntitlement,
  ProductParticipation,
  ProductWorkload,
  RegisteredProduct,
  Tenant,
  TenantMembership,
  TenantProvisioningRequest,
  TenantWorkforceRole,
} from "../../control-plane/models.js";
import type { ControlPlaneRepository } from "../../control-plane/ports/control-plane-repository.js";

type StatusRow = { id: string; display_name: string; status: "active" | "suspended" | "retired" };
type WorkloadRow = { id: string; product_id: string; secret_hash: string; status: "active" | "suspended" | "retired" };
type PlatformAdministrationMembershipRow = {
  human_identity_id: string;
  platform_role: PlatformAdministrationRole;
  status: "active" | "suspended" | "retired";
  created_at: Date;
  updated_at: Date;
};
type RelationshipRow = { status: "active" | "suspended" | "retired" };
type MembershipRow = RelationshipRow & {
  tenant_id: string;
  human_identity_id: string;
  tenant_role: TenantWorkforceRole;
  created_at: Date;
  updated_at: Date;
};
type EntitlementRow = RelationshipRow & { tenant_id: string; product_id: string; human_identity_id: string };
type ParticipationRow = RelationshipRow & { tenant_id: string; product_id: string };
type TenantProvisioningRequestRow = {
  idempotency_key: string;
  tenant_id: string;
  display_name: string;
  initial_owner_human_identity_id: string;
  created_at: Date;
};

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
  async listProducts(): Promise<readonly RegisteredProduct[]> {
    const result = await this.database.query<StatusRow>("SELECT id, display_name, status FROM registered_products ORDER BY display_name, id");
    return result.rows.map((row) => ({ id: row.id, displayName: row.display_name, status: row.status }));
  }
  async saveTenant(tenant: Tenant): Promise<void> {
    await this.database.query(`INSERT INTO tenants (id, display_name, status) VALUES ($1, $2, $3)
      ON CONFLICT (id) DO UPDATE SET display_name = EXCLUDED.display_name, status = EXCLUDED.status`, [tenant.id, tenant.displayName, tenant.status]);
  }
  async insertTenantIfAbsent(tenant: Tenant): Promise<boolean> {
    const result = await this.database.query(`INSERT INTO tenants (id, display_name, status) VALUES ($1, $2, $3)
      ON CONFLICT (id) DO NOTHING RETURNING id`, [tenant.id, tenant.displayName, tenant.status]);
    return result.rowCount === 1;
  }
  async findTenant(id: string): Promise<Tenant | null> {
    const result = await this.database.query<StatusRow>("SELECT id, display_name, status FROM tenants WHERE id = $1", [id]);
    const row = result.rows[0]; return row === undefined ? null : { id: row.id, displayName: row.display_name, status: row.status };
  }
  async listTenants(): Promise<readonly Tenant[]> {
    const result = await this.database.query<StatusRow>("SELECT id, display_name, status FROM tenants ORDER BY display_name, id");
    return result.rows.map((row) => ({ id: row.id, displayName: row.display_name, status: row.status }));
  }
  async lockTenant(id: string): Promise<void> {
    await this.database.query("SELECT id FROM tenants WHERE id = $1 FOR UPDATE", [id]);
  }
  async insertTenantProvisioningRequestIfAbsent(value: TenantProvisioningRequest): Promise<boolean> {
    const result = await this.database.query(`INSERT INTO tenant_provisioning_requests
      (idempotency_key, tenant_id, display_name, initial_owner_human_identity_id, created_at)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (idempotency_key) DO NOTHING
      RETURNING idempotency_key`, [value.idempotencyKey, value.tenantId, value.displayName, value.initialOwnerHumanIdentityId, value.createdAt]);
    return result.rowCount === 1;
  }
  async findTenantProvisioningRequest(idempotencyKey: string): Promise<TenantProvisioningRequest | null> {
    const result = await this.database.query<TenantProvisioningRequestRow>(`SELECT idempotency_key, tenant_id, display_name,
      initial_owner_human_identity_id, created_at FROM tenant_provisioning_requests WHERE idempotency_key = $1`, [idempotencyKey]);
    const row = result.rows[0];
    return row === undefined ? null : {
      idempotencyKey: row.idempotency_key,
      tenantId: row.tenant_id,
      displayName: row.display_name,
      initialOwnerHumanIdentityId: row.initial_owner_human_identity_id,
      createdAt: row.created_at,
    };
  }
  async insertPlatformAdministrationMembershipIfAbsent(value: PlatformAdministrationMembership): Promise<boolean> {
    const result = await this.database.query(`INSERT INTO platform_administration_memberships
      (human_identity_id, platform_role, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (human_identity_id) DO NOTHING
      RETURNING human_identity_id`,
    [value.humanIdentityId, value.platformRole, value.status, value.createdAt, value.updatedAt]);
    return result.rowCount === 1;
  }
  async savePlatformAdministrationMembership(value: PlatformAdministrationMembership): Promise<void> {
    await this.database.query(`INSERT INTO platform_administration_memberships
      (human_identity_id, platform_role, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (human_identity_id) DO UPDATE SET platform_role = EXCLUDED.platform_role, status = EXCLUDED.status, updated_at = EXCLUDED.updated_at`,
    [value.humanIdentityId, value.platformRole, value.status, value.createdAt, value.updatedAt]);
  }
  async findPlatformAdministrationMembership(humanIdentityId: string): Promise<PlatformAdministrationMembership | null> {
    const result = await this.database.query<PlatformAdministrationMembershipRow>(`SELECT human_identity_id, platform_role, status, created_at, updated_at
      FROM platform_administration_memberships WHERE human_identity_id = $1`, [humanIdentityId]);
    const row = result.rows[0];
    return row === undefined ? null : {
      humanIdentityId: row.human_identity_id,
      platformRole: row.platform_role,
      status: row.status,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
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
    await this.database.query(`INSERT INTO tenant_memberships (tenant_id, human_identity_id, status, tenant_role, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (tenant_id, human_identity_id) DO UPDATE SET status = EXCLUDED.status, tenant_role = EXCLUDED.tenant_role, updated_at = EXCLUDED.updated_at`,
      [value.tenantId, value.humanIdentityId, value.status, value.tenantRole, value.createdAt, value.updatedAt]);
  }
  async findMembership(tenantId: string, humanIdentityId: string): Promise<TenantMembership | null> {
    const result = await this.database.query<MembershipRow>(`${selectMembership} WHERE tenant_id = $1 AND human_identity_id = $2`, [tenantId, humanIdentityId]);
    return toMembership(result.rows[0]);
  }
  async listMembershipsForTenant(tenantId: string): Promise<readonly TenantMembership[]> {
    const result = await this.database.query<MembershipRow>(`${selectMembership} WHERE tenant_id = $1 ORDER BY created_at, human_identity_id`, [tenantId]);
    return result.rows.map(toMembership).filter((membership): membership is TenantMembership => membership !== null);
  }
  async lockMembershipsForTenant(tenantId: string): Promise<readonly TenantMembership[]> {
    // The Tenant row also serializes creation of the first/new membership;
    // row-locking only existing memberships would leave an empty-key race.
    await this.database.query("SELECT id FROM tenants WHERE id = $1 FOR UPDATE", [tenantId]);
    const result = await this.database.query<MembershipRow>(`${selectMembership} WHERE tenant_id = $1 ORDER BY human_identity_id FOR UPDATE`, [tenantId]);
    return result.rows.map(toMembership).filter((membership): membership is TenantMembership => membership !== null);
  }
  async saveParticipation(value: ProductParticipation): Promise<void> {
    await this.database.query(`INSERT INTO product_participations (tenant_id, product_id, status) VALUES ($1, $2, $3)
      ON CONFLICT (tenant_id, product_id) DO UPDATE SET status = EXCLUDED.status`, [value.tenantId, value.productId, value.status]);
  }
  async findParticipation(tenantId: string, productId: string): Promise<ProductParticipation | null> {
    const result = await this.database.query<RelationshipRow>("SELECT status FROM product_participations WHERE tenant_id = $1 AND product_id = $2", [tenantId, productId]);
    const row = result.rows[0]; return row === undefined ? null : { tenantId, productId, status: row.status };
  }
  async listParticipationsForTenant(tenantId: string): Promise<readonly ProductParticipation[]> {
    const result = await this.database.query<ParticipationRow>(`SELECT tenant_id, product_id, status FROM product_participations
      WHERE tenant_id = $1 ORDER BY product_id`, [tenantId]);
    return result.rows.map((row) => ({ tenantId: row.tenant_id, productId: row.product_id, status: row.status }));
  }
  async saveEntitlement(value: ProductEntitlement): Promise<void> {
    await this.database.query(`INSERT INTO product_entitlements (tenant_id, product_id, human_identity_id, status) VALUES ($1, $2, $3, $4)
      ON CONFLICT (tenant_id, product_id, human_identity_id) DO UPDATE SET status = EXCLUDED.status`, [value.tenantId, value.productId, value.humanIdentityId, value.status]);
  }
  async findEntitlement(tenantId: string, productId: string, humanIdentityId: string): Promise<ProductEntitlement | null> {
    const result = await this.database.query<RelationshipRow>("SELECT status FROM product_entitlements WHERE tenant_id = $1 AND product_id = $2 AND human_identity_id = $3", [tenantId, productId, humanIdentityId]);
    const row = result.rows[0]; return row === undefined ? null : { tenantId, productId, humanIdentityId, status: row.status };
  }
  async listEntitlementsForHuman(tenantId: string, humanIdentityId: string): Promise<readonly ProductEntitlement[]> {
    const result = await this.database.query<EntitlementRow>(`SELECT tenant_id, product_id, human_identity_id, status FROM product_entitlements
      WHERE tenant_id = $1 AND human_identity_id = $2 ORDER BY product_id`, [tenantId, humanIdentityId]);
    return result.rows.map((row) => ({ tenantId: row.tenant_id, productId: row.product_id, humanIdentityId: row.human_identity_id, status: row.status }));
  }
  async appendAudit(event: PlatformAuditEvent): Promise<void> {
    await this.database.query(`INSERT INTO platform_audit_events (id, event_type, actor_reference, subject_reference, product_id, tenant_id, event_data, occurred_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, [event.id, event.eventType, event.actorReference, event.subjectReference, event.productId ?? null, event.tenantId ?? null, event.eventData ?? {}, event.occurredAt]);
  }
}

const selectMembership = `SELECT tenant_id, human_identity_id, status, tenant_role, created_at, updated_at FROM tenant_memberships`;

function toMembership(row: MembershipRow | undefined): TenantMembership | null {
  return row === undefined ? null : {
    tenantId: row.tenant_id,
    humanIdentityId: row.human_identity_id,
    status: row.status,
    tenantRole: row.tenant_role,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}
