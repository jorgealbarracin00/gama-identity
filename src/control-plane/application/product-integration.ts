import { z } from "zod";

/** Operator-reviewed facts. Authentication configuration is not proof of live integration. */
export const productIntegrationSchema = z.array(z.object({
  productId: z.string().regex(/^[a-z][a-z0-9-]{0,63}$/u),
  integrationStatus: z.enum(["gama_identity", "cloudkit_only", "login_free", "other_identity", "unknown"]),
  participationRecording: z.enum(["verified", "missing", "not_applicable", "unknown"]),
  evidenceReference: z.string().trim().min(1).max(240).regex(/^[^\p{Cc}\p{Cf}]+$/u),
  verifiedAt: z.iso.datetime(),
  warnings: z.array(z.string().trim().min(1).max(240).regex(/^[^\p{Cc}\p{Cf}]+$/u)).max(10).default([]),
  // Explicitly opt in server-side web access reporting. No client receives a workload secret.
  webAppIds: z.array(z.string().regex(/^[a-z][a-z0-9-]{0,63}$/u)).max(20).default([]),
  reportingWorkloadId: z.string().min(1).max(200).optional(),
}).strict()).max(100).superRefine((items, context) => {
  const products = new Set<string>(), apps = new Set<string>();
  for (const item of items) {
    if (products.has(item.productId)) context.addIssue({ code: "custom", message: "Integration product identifiers must be unique" });
    products.add(item.productId);
    for (const id of item.webAppIds) {
      if (apps.has(id)) context.addIssue({ code: "custom", message: "A web application must map to only one registered product" });
      apps.add(id);
    }
    if (item.webAppIds.length && (item.integrationStatus !== "gama_identity" || !item.reportingWorkloadId)) {
      context.addIssue({ code: "custom", message: "Web participation reporting requires GAMA Identity integration and a reporting workload" });
    }
    if (["cloudkit_only", "login_free", "other_identity"].includes(item.integrationStatus) && item.participationRecording !== "not_applicable") {
      context.addIssue({ code: "custom", message: "Products using another identity model cannot claim GAMA participation recording" });
    }
  }
});

export type ProductIntegration = z.infer<typeof productIntegrationSchema>[number];
export type AssociationKind = "participation" | "entitlement" | "all";
export interface HumanProductAssociation {
  readonly productId: string;
  readonly displayName: string;
  readonly participationStatus: string | null;
  readonly entitlements: readonly { tenantId: string; status: string }[];
}

export function integrationFacts(integration: ProductIntegration | undefined) {
  return {
    integrationStatus: integration?.integrationStatus ?? "unknown",
    participationRecording: integration?.participationRecording ?? "unknown",
    integrationEvidenceReference: integration?.evidenceReference ?? null,
    integrationVerifiedAt: integration?.verifiedAt ?? null,
    integrationWarnings: integration?.warnings ?? ["Current product integration and participation reporting have not been verified."],
  };
}
