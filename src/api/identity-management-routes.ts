import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { z } from "zod";
import type { IdentityServices } from "./services.js";
import { SessionId } from "../sessions/domain/session-id.js";
import { AppError } from "../shared/errors.js";
import { AdministrationAuthorizationError } from "../control-plane/application/administration-principals.js";
const human = z.string().min(1).max(200),
  uuid = z.uuid();
const action = z.enum(["suspend", "reactivate", "retire"]);
const lifecycle = z
  .object({
    humanIdentityId: human,
    action,
    requestId: uuid,
    reviewDigest: z.string().regex(/^[a-f0-9]{64}$/),
    confirmation: z.string().max(500),
    revokeSessions: z.boolean(),
  })
  .strict();
function parse<T>(schema: z.ZodType<T>, body: unknown): T {
  const p = schema.safeParse(body);
  if (!p.success)
    throw new AppError("The request is invalid", "INVALID_REQUEST", 400);
  return p.data;
}
export function identityManagementRoutes(
  services: IdentityServices,
): FastifyPluginAsync {
  return async (app) => {
    const service = () => {
      const m = services.administration.identityManagement;
      if (!m)
        throw new AppError(
          "Identity management is unavailable",
          "IDENTITY_MANAGEMENT_UNAVAILABLE",
          503,
        );
      return m;
    };
    const routes: Record<
      string,
      (
        m: NonNullable<
          IdentityServices["administration"]["identityManagement"]
        >,
        s: SessionId,
        r: FastifyRequest,
      ) => Promise<unknown>
    > = {
      inspect: (m, s, r) =>
        m.inspect(
          s,
          parse(z.object({ humanIdentityId: human }).strict(), r.body)
            .humanIdentityId,
        ),
      classify: (m, s, r) =>
        m.classify(
          s,
          parse(
            z
              .object({
                humanIdentityId: human,
                purpose: z.enum(["production", "test", "unknown"]),
                reason: z
                  .string()
                  .trim()
                  .min(1)
                  .max(500)
                  .regex(/^[^\p{Cc}\p{Cf}]+$/u),
                expectedRevision: z.number().int().min(0).max(2147483646),
                requestId: uuid,
              })
              .strict(),
            r.body,
          ),
        ),
      "lifecycle/preview": (m, s, r) => {
        const p = parse(
          z
            .object({
              humanIdentityIds: z
                .array(human)
                .min(1)
                .max(50)
                .refine((v) => new Set(v).size === v.length),
              action,
            })
            .strict(),
          r.body,
        );
        return m.previewLifecycle(s, p.humanIdentityIds, p.action);
      },
      "lifecycle/execute": (m, s, r) =>
        m.lifecycle(s, parse(lifecycle, r.body)),
      "bulk/execute": (m, s, r) => {
        const p = parse(
          z
            .object({
              items: z
                .array(lifecycle)
                .min(1)
                .max(50)
                .refine(
                  (v) =>
                    new Set(v.map((x) => x.humanIdentityId)).size ===
                      v.length &&
                    new Set(v.map((x) => x.requestId)).size === v.length,
                ),
              confirmation: z.string().max(100),
            })
            .strict(),
          r.body,
        );
        return m.bulk(s, p.items, p.confirmation);
      },
      "recovery/prepare": (m, s, r) => {
        const p = parse(
          z
            .object({
              sourceHumanIdentityId: human,
              targetHumanIdentityId: human,
              provider: z.literal("google"),
            })
            .strict(),
          r.body,
        );
        return m.prepareRecovery(
          s,
          p.sourceHumanIdentityId,
          p.targetHumanIdentityId,
        );
      },
      "recovery/prove": (m, s, r) =>
        m.proveRecovery(
          s,
          parse(
            z
              .object({
                caseId: uuid,
                sourceSession: z.string().min(1).max(200),
                targetSession: z.string().min(1).max(200),
                identityToken: z.string().min(1).max(16384),
              })
              .strict(),
            r.body,
          ),
        ),
      "recovery/preview": (m, s, r) =>
        m.previewRecovery(
          s,
          parse(z.object({ caseId: uuid }).strict(), r.body).caseId,
        ),
      "recovery/execute": (m, s, r) =>
        m.executeRecovery(
          s,
          parse(
            z
              .object({
                caseId: uuid,
                requestId: uuid,
                reviewDigest: z.string().regex(/^[a-f0-9]{64}$/),
                confirmation: z.string().max(600),
                revokeSourceSessions: z.boolean(),
                acceptSourceLossOfAccess: z.boolean(),
              })
              .strict(),
            r.body,
          ),
        ),
      "dependencies/inspector": (m, s, r) => {
        const p = parse(
          z.object({ productId: human, workloadId: human }).strict(),
          r.body,
        );
        return m.registerInspector(s, p.productId, p.workloadId);
      },
    };
    for (const [path, work] of Object.entries(routes))
      app.post(
        `/administration/platform/identity-management/${path}`,
        async (req, rep) => {
          rep.header("Cache-Control", "no-store");
          const match = /^Bearer ([^\s]+)$/.exec(
            req.headers.authorization ?? "",
          );
          if (!match?.[1])
            throw new AppError("Sign in to continue", "SESSION_INVALID", 401);
          try {
            return await work(service(), SessionId.from(match[1]), req);
          } catch (e) {
            if (e instanceof AppError) throw e;
            if (e instanceof AdministrationAuthorizationError)
              throw new AppError(
                "Platform Administrator access is required",
                e.code,
                403,
              );
            throw new AppError(
              "The operation failed without committing changes",
              "IDENTITY_MANAGEMENT_FAILED",
              500,
            );
          }
        },
      );
    app.post("/control/identity-dependencies", async (req, rep) => {
      rep.header("Cache-Control", "no-store");
      const w = req.headers["x-gama-workload-id"],
        secret = req.headers["x-gama-workload-secret"];
      if (
        typeof w !== "string" ||
        typeof secret !== "string" ||
        w.length > 200 ||
        secret.length > 4096
      )
        throw new AppError(
          "Product authorization is required",
          "WORKLOAD_INVALID",
          401,
        );
      const count = z.number().int().min(0).max(2147483647);
      const p = parse(
        z
          .object({
            humanIdentityId: human,
            counts: z
              .object({
                localAccounts: count,
                subscriptions: count,
                permissions: count,
                ownership: count,
                backgroundJobs: count,
                pendingOperations: count,
                externalReferences: count,
                retention: count,
              })
              .strict(),
            evidenceReference: z.string().regex(/^[a-zA-Z0-9._:-]{1,120}$/),
            observedAt: z.iso.datetime(),
          })
          .strict(),
        req.body,
      );
      try {
        return await service().reportDependencies(w, secret, p);
      } catch (e) {
        if (e instanceof AppError) throw e;
        throw new AppError(
          "Dependency evidence was not recorded",
          "DEPENDENCY_REPORT_FAILED",
          500,
        );
      }
    });
  };
}
