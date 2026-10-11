import { randomUUID } from "node:crypto";
import type { AdministrationPrincipals } from "./administration-principals.js";
import type { ControlPlaneRepository } from "../ports/control-plane-repository.js";
import type { Clock } from "../../shared/clock.js";

export interface InspectionMethod {
  readonly method: string;
  readonly status: string;
  readonly email: string | null;
  readonly emailVerified: boolean | null;
}
export interface InspectedHuman {
  readonly humanIdentityId: string;
  readonly displayName: string | null;
  readonly status: string;
  readonly authenticationMethods: readonly InspectionMethod[];
}
export type InspectionRequest =
  | { readonly mode: "search"; readonly query: string; readonly cursor?: string | undefined }
  | { readonly mode: "duplicates"; readonly cursor?: string | undefined }
  | { readonly mode: "details"; readonly humanIdentityIds: readonly string[] };
export interface DuplicateGroup {
  readonly email: string;
  readonly humanIdentityIds: readonly string[];
}
export interface InspectionPage {
  readonly identities: readonly InspectedHuman[];
  readonly duplicateGroups: readonly DuplicateGroup[];
  readonly nextCursor: string | null;
}
export interface IdentityInspectionRepository {
  inspect(input: InspectionRequest): Promise<InspectionPage>;
}

/** Only authentication metadata is read. Authority is rechecked for every page/comparison. */
export class IdentityExplorer {
  constructor(
    private readonly principals: AdministrationPrincipals,
    private readonly inspection: IdentityInspectionRepository,
    private readonly repository: ControlPlaneRepository,
    private readonly clock: Clock,
  ) {}

  async inspect(actor: string, input: InspectionRequest) {
    const principal = await this.principals.platform(actor);
    const page = await this.inspection.inspect(input);
    const identities = await Promise.all(page.identities.map(async (identity) => {
      // Only actual Human entitlements, never the Tenant's entire product catalog.
      const entitlements = await this.repository.listEntitlementsForHumanAcrossTenants(identity.humanIdentityId);
      const productAssociations = await Promise.all(entitlements.map(async (entitlement) => {
        const [product, tenant, membership, participation] = await Promise.all([
          this.repository.findProduct(entitlement.productId),
          this.repository.findTenant(entitlement.tenantId),
          this.repository.findMembership(entitlement.tenantId, identity.humanIdentityId),
          this.repository.findParticipation(entitlement.tenantId, entitlement.productId),
        ]);
        return {
          tenantId: entitlement.tenantId,
          tenantName: tenant?.displayName ?? null,
          productId: entitlement.productId,
          productName: product?.displayName ?? null,
          productStatus: product?.status ?? null,
          entitlementStatus: entitlement.status,
          membershipStatus: membership?.status ?? null,
          participationStatus: participation?.status ?? null,
        };
      }));
      // Explicit allowlist: never serialize a domain credential or provider relationship.
      return {
        humanIdentityId: identity.humanIdentityId,
        displayName: identity.displayName,
        status: identity.status,
        authenticationMethods: identity.authenticationMethods.map((method) => ({
          method: method.method, status: method.status, email: method.email, emailVerified: method.emailVerified,
        })),
        productAssociations,
      };
    }));
    // Await the audit before returning any personal information; failure closes the request.
    await this.repository.appendAudit({
      id: randomUUID(), eventType: "platform.identity.inspected",
      actorReference: principal.actorReference, subjectReference: "identity-explorer",
      eventData: {
        authorityScope: principal.kind, mode: input.mode,
        resultCount: String(identities.length), duplicateGroupCount: String(page.duplicateGroups.length),
        // No email, name, search text, credentials or provider subject in audit data.
        ...(input.mode === "details" ? { humanIdentityIds: input.humanIdentityIds.join(",") } : {}),
      },
      occurredAt: this.clock.now(),
    });
    return { identities, duplicateGroups: page.duplicateGroups, nextCursor: page.nextCursor };
  }
}

export function inspectionPage(humans: readonly InspectedHuman[], input: InspectionRequest): InspectionPage {
  if (input.mode === "details") return {
    identities: humans.filter((human) => input.humanIdentityIds.includes(human.humanIdentityId)),
    duplicateGroups: [], nextCursor: null,
  };
  if (input.mode === "duplicates") {
    const emails = new Map<string, Set<string>>();
    for (const human of humans) for (const method of human.authenticationMethods) {
      if (!method.email) continue;
      const email = method.email.trim().toLowerCase();
      if (!email) continue;
      const owners = emails.get(email) ?? new Set<string>();
      owners.add(human.humanIdentityId); emails.set(email, owners);
    }
    const groups = [...emails].filter(([email, ids]) => ids.size > 1 && email > (input.cursor ?? ""))
      .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
      .map(([email, ids]) => ({ email, humanIdentityIds: [...ids].sort() }));
    return { identities: [], duplicateGroups: groups.slice(0, 50), nextCursor: groups.length > 50 ? groups[49]!.email : null };
  }
  const query = input.query.trim().toLowerCase();
  const matches = humans.filter((human) => human.humanIdentityId > (input.cursor ?? "") && (
    human.humanIdentityId.toLowerCase().includes(query) || human.displayName?.toLowerCase().includes(query)
    || human.authenticationMethods.some((method) => method.email?.toLowerCase().includes(query))
  )).sort((a, b) => a.humanIdentityId < b.humanIdentityId ? -1 : a.humanIdentityId > b.humanIdentityId ? 1 : 0);
  return { identities: matches.slice(0, 50), duplicateGroups: [], nextCursor: matches.length > 50 ? matches[49]!.humanIdentityId : null };
}
