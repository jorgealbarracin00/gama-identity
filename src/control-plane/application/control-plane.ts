import { randomUUID } from "node:crypto";

import type { PasswordHasher, PasswordVerifier } from "../../authentication/credentials/ports/password-operations.js";
import type { HumanIdentityRepository } from "../../identity/ports/human-identity-repository.js";
import type { Clock } from "../../shared/clock.js";
import { PasswordHash } from "../../authentication/credentials/domain/password.js";
import { HumanIdentityId } from "../../identity/domain/human-identity-id.js";
import {
  COCO_DEVELOPMENT_TENANT_ID,
  COCO_PRODUCT_ID,
  COCO_WORKLOAD_ID,
  type LifecycleStatus,
} from "../models.js";
import type { ControlPlaneRepository } from "../ports/control-plane-repository.js";

export interface BootstrapCocoInput {
  readonly ownerHumanIdentityId: string;
  readonly workloadSecret: string;
  readonly actorReference: string;
}

export interface WorkforceContext {
  readonly humanIdentityId: string;
  readonly tenantId: string;
  readonly productId: string;
  readonly tenantActive: boolean;
  readonly productActive: boolean;
  readonly membershipActive: boolean;
  readonly participationActive: boolean;
  readonly entitlementActive: boolean;
  readonly workforceContextSatisfied: boolean;
}

export interface AuthenticatedWorkload {
  readonly workloadId: string;
  readonly productId: string;
}

type AtomicExecutor = <T>(work: () => Promise<T>) => Promise<T>;

function active(status: LifecycleStatus | undefined): boolean {
  return status === "active";
}

export class ControlPlane {
  constructor(
    private readonly repository: ControlPlaneRepository,
    private readonly identities: HumanIdentityRepository,
    private readonly passwords: PasswordHasher & PasswordVerifier,
    private readonly clock: Clock,
    private readonly atomically: AtomicExecutor = async (work) => work(),
  ) {}

  async bootstrapCoco(input: BootstrapCocoInput): Promise<void> {
    return this.atomically(() => this.bootstrapCocoAtomically(input));
  }

  private async bootstrapCocoAtomically(input: BootstrapCocoInput): Promise<void> {
    if (input.workloadSecret.length < 24) {
      throw new Error("COCO_WORKLOAD_SECRET must be at least 24 characters");
    }
    const owner = await this.identities.findById(HumanIdentityId.from(input.ownerHumanIdentityId));
    if (owner === null || owner.status !== "active") {
      throw new Error("COCO_OWNER_HUMAN_IDENTITY_ID must identify an active Human Identity");
    }

    await this.repository.saveProduct({ id: COCO_PRODUCT_ID, displayName: "Coco the Llama", status: "active" });
    await this.repository.saveTenant({ id: COCO_DEVELOPMENT_TENANT_ID, displayName: "Coco Development", status: "active" });
    await this.repository.saveWorkload({
      id: COCO_WORKLOAD_ID,
      productId: COCO_PRODUCT_ID,
      secretHash: (await this.passwords.hash(input.workloadSecret)).value,
      status: "active",
    });
    await this.repository.saveMembership({ tenantId: COCO_DEVELOPMENT_TENANT_ID, humanIdentityId: input.ownerHumanIdentityId, status: "active" });
    await this.repository.saveParticipation({ tenantId: COCO_DEVELOPMENT_TENANT_ID, productId: COCO_PRODUCT_ID, status: "active" });
    await this.repository.saveEntitlement({ tenantId: COCO_DEVELOPMENT_TENANT_ID, productId: COCO_PRODUCT_ID, humanIdentityId: input.ownerHumanIdentityId, status: "active" });

    for (const [eventType, subjectReference] of [
      ["product.registered", COCO_PRODUCT_ID],
      ["workload.identity.established", COCO_WORKLOAD_ID],
      ["tenant.membership.granted", `${COCO_DEVELOPMENT_TENANT_ID}:${input.ownerHumanIdentityId}`],
      ["product.participation.established", `${COCO_DEVELOPMENT_TENANT_ID}:${COCO_PRODUCT_ID}`],
      ["product.entitlement.granted", `${COCO_DEVELOPMENT_TENANT_ID}:${COCO_PRODUCT_ID}:${input.ownerHumanIdentityId}`],
    ] as const) {
      await this.repository.appendAudit({
        id: randomUUID(), eventType, actorReference: input.actorReference, subjectReference,
        productId: COCO_PRODUCT_ID, tenantId: COCO_DEVELOPMENT_TENANT_ID, occurredAt: this.clock.now(),
      });
    }
  }

  async workforceContext(humanIdentityId: string, tenantId: string, productId: string): Promise<WorkforceContext> {
    const [tenant, product, membership, participation, entitlement] = await Promise.all([
      this.repository.findTenant(tenantId), this.repository.findProduct(productId),
      this.repository.findMembership(tenantId, humanIdentityId),
      this.repository.findParticipation(tenantId, productId),
      this.repository.findEntitlement(tenantId, productId, humanIdentityId),
    ]);
    const tenantActive = active(tenant?.status);
    const productActive = active(product?.status);
    const membershipActive = active(membership?.status);
    const participationActive = active(participation?.status);
    const entitlementActive = active(entitlement?.status);
    return { humanIdentityId, tenantId, productId, tenantActive, productActive, membershipActive, participationActive, entitlementActive,
      workforceContextSatisfied: tenantActive && productActive && membershipActive && participationActive && entitlementActive };
  }

  async authenticateWorkload(workloadId: string, secret: string): Promise<AuthenticatedWorkload | null> {
    const workload = await this.repository.findWorkload(workloadId);
    if (workload === null || !active(workload.status)) return null;
    const product = await this.repository.findProduct(workload.productId);
    if (product === null || !active(product.status)) return null;
    const verified = await this.passwords.verify(secret, PasswordHash.from(workload.secretHash));
    return verified ? { workloadId: workload.id, productId: workload.productId } : null;
  }
}
