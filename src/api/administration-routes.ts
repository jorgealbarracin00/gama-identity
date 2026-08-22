import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { z } from "zod";

import { AdministrationAuthorizationError } from "../control-plane/application/administration-principals.js";
import { PlatformAdministrationError } from "../control-plane/application/platform-administration.js";
import type { TenantAdministrationContext } from "../control-plane/application/tenant-team-administration.js";
import { WorkforceAdministrationError } from "../control-plane/application/workforce-administration.js";
import { SessionId } from "../sessions/domain/session-id.js";
import { AppError } from "../shared/errors.js";
import type { IdentityServices } from "./services.js";

const tenantPath = z.object({ tenantId: z.string().min(1) });
const tenantProductPath = tenantPath.extend({ productId: z.string().min(1) });
const memberPath = tenantPath.extend({ humanIdentityId: z.string().min(1) });
const productMemberPath = memberPath.extend({ productId: z.string().min(1) });
const teamMemberPath = z.object({ humanIdentityId: z.string().min(1) });
const identityLookup = z.object({ email: z.email() }).strict();
const tenantProvisioning = z.object({
  idempotencyKey: z.uuid(),
  displayName: z.string().trim().min(1).max(160),
  initialOwnerHumanIdentityId: z.string().min(1).max(200),
}).strict();
const platformGrant = z.object({
  productId: z.string().min(1),
  humanIdentityId: z.string().min(1),
  tenantRole: z.string().min(1),
}).strict();
const roleChange = z.object({ tenantRole: z.string().min(1) }).strict();
const addTeamMember = z.object({ email: z.email(), tenantRole: z.string().min(1) }).strict();

export function administrationRoutes(services: IdentityServices): FastifyPluginAsync {
  return async (app) => {
    app.get("/administration/platform/tenants", async (request, reply) => {
      const actor = await authenticatedHumanIdentity(services, request);
      return reply.send(await administer(() => services.administration.platform.listTenants(actor)));
    });

    app.post("/administration/platform/tenants", async (request, reply) => {
      const actor = await authenticatedHumanIdentity(services, request);
      const input = parse(tenantProvisioning, request.body);
      const result = await administer(() => services.administration.platform.provisionTenant(actor, input));
      return reply.code(result.created ? 201 : 200).send({
        tenant: result.tenant,
        initialOwnerMembership: result.initialOwnerMembership,
      });
    });

    app.get("/administration/platform/products", async (request, reply) => {
      const actor = await authenticatedHumanIdentity(services, request);
      return reply.send(await administer(() => services.administration.platform.listProducts(actor)));
    });

    app.get("/administration/platform/tenants/:tenantId/products", async (request, reply) => {
      const actor = await authenticatedHumanIdentity(services, request);
      const { tenantId } = parse(tenantPath, request.params);
      return reply.send(await administer(() => services.administration.platform.listTenantProducts(actor, tenantId)));
    });

    app.put("/administration/platform/tenants/:tenantId/products/:productId", async (request, reply) => {
      const actor = await authenticatedHumanIdentity(services, request);
      const { tenantId, productId } = parse(tenantProductPath, request.params);
      return reply.send(await administer(() => services.administration.platform.assignTenantProduct(actor, tenantId, productId)));
    });

    app.get("/administration/platform/identities/resolve", async (request, reply) => {
      const actor = await authenticatedHumanIdentity(services, request);
      const input = parse(identityLookup, request.query);
      return reply.send(await administer(() => services.administration.platform.resolveHumanIdentityByEmail(actor, input.email)));
    });

    app.get("/administration/platform/tenants/:tenantId/team", async (request, reply) => {
      const actor = await authenticatedHumanIdentity(services, request);
      const { tenantId } = parse(tenantPath, request.params);
      return reply.send(await administer(() => services.administration.platform.listTenantWorkforce(actor, tenantId)));
    });

    app.get("/administration/platform/tenants/:tenantId/team/:humanIdentityId", async (request, reply) => {
      const actor = await authenticatedHumanIdentity(services, request);
      const { tenantId, humanIdentityId } = parse(memberPath, request.params);
      return reply.send(await administer(() => services.administration.platform.inspectTenantMembership(actor, tenantId, humanIdentityId)));
    });

    app.post("/administration/platform/tenants/:tenantId/team", async (request, reply) => {
      const actor = await authenticatedHumanIdentity(services, request);
      const { tenantId } = parse(tenantPath, request.params);
      const input = parse(platformGrant, request.body);
      return reply.send(await administer(() => services.administration.platform.grantProductWorkforceAccess(actor, { tenantId, ...input })));
    });

    app.patch("/administration/platform/tenants/:tenantId/team/:humanIdentityId/role", async (request, reply) => {
      const actor = await authenticatedHumanIdentity(services, request);
      const { tenantId, humanIdentityId } = parse(memberPath, request.params);
      const { tenantRole } = parse(roleChange, request.body);
      return reply.send(await administer(() => services.administration.platform.changeTenantRole(actor, tenantId, humanIdentityId, tenantRole)));
    });

    app.delete("/administration/platform/tenants/:tenantId/team/:humanIdentityId/products/:productId", async (request, reply) => {
      const actor = await authenticatedHumanIdentity(services, request);
      const { tenantId, humanIdentityId, productId } = parse(productMemberPath, request.params);
      return reply.send(await administer(() => services.administration.platform.revokeProductAccess(actor, tenantId, productId, humanIdentityId)));
    });

    app.delete("/administration/platform/tenants/:tenantId/team/:humanIdentityId", async (request, reply) => {
      const actor = await authenticatedHumanIdentity(services, request);
      const { tenantId, humanIdentityId } = parse(memberPath, request.params);
      return reply.send(await administer(() => services.administration.platform.revokeTenantMembership(actor, tenantId, humanIdentityId)));
    });

    app.get("/administration/team", async (request, reply) => {
      const context = await tenantAdministrationContext(services, request);
      return reply.send(await administer(() => services.administration.tenantTeam.listTeam(context)));
    });

    app.post("/administration/team", async (request, reply) => {
      const context = await tenantAdministrationContext(services, request);
      const input = parse(addTeamMember, request.body);
      return reply.send(await administer(() => services.administration.tenantTeam.addTeamMember(context, input.email, input.tenantRole)));
    });

    app.patch("/administration/team/:humanIdentityId/role", async (request, reply) => {
      const context = await tenantAdministrationContext(services, request);
      const { humanIdentityId } = parse(teamMemberPath, request.params);
      const { tenantRole } = parse(roleChange, request.body);
      return reply.send(await administer(() => services.administration.tenantTeam.changeTeamMemberRole(context, humanIdentityId, tenantRole)));
    });

    app.put("/administration/team/:humanIdentityId/product-access", async (request, reply) => {
      const context = await tenantAdministrationContext(services, request);
      const { humanIdentityId } = parse(teamMemberPath, request.params);
      return reply.send(await administer(() => services.administration.tenantTeam.grantProductAccess(context, humanIdentityId)));
    });

    app.delete("/administration/team/:humanIdentityId/product-access", async (request, reply) => {
      const context = await tenantAdministrationContext(services, request);
      const { humanIdentityId } = parse(teamMemberPath, request.params);
      return reply.send(await administer(() => services.administration.tenantTeam.revokeProductAccess(context, humanIdentityId)));
    });

    app.delete("/administration/team/:humanIdentityId", async (request, reply) => {
      const context = await tenantAdministrationContext(services, request);
      const { humanIdentityId } = parse(teamMemberPath, request.params);
      return reply.send(await administer(() => services.administration.tenantTeam.removeTeamMember(context, humanIdentityId)));
    });
  };
}

async function authenticatedHumanIdentity(services: IdentityServices, request: FastifyRequest): Promise<string> {
  const session = await services.validateSession.execute(bearerSessionId(request));
  if (session.outcome !== "authenticated") {
    throw new AppError("Session is not authenticated", `SESSION_${session.outcome.toUpperCase()}`, 401);
  }
  return session.humanIdentityId;
}

async function tenantAdministrationContext(
  services: IdentityServices,
  request: FastifyRequest,
): Promise<TenantAdministrationContext> {
  const actorHumanIdentityId = await authenticatedHumanIdentity(services, request);
  const workloadId = request.headers["x-gama-workload-id"];
  const workloadSecret = request.headers["x-gama-workload-secret"];
  const tenantId = request.headers["x-gama-tenant-id"];
  if (typeof workloadId !== "string" || typeof workloadSecret !== "string" || typeof tenantId !== "string" || tenantId.length === 0) {
    throw new AppError("Authenticated Product workload context is required", "WORKLOAD_CONTEXT_REQUIRED", 401);
  }
  const workload = await services.controlPlane.authenticateWorkload(workloadId, workloadSecret);
  if (workload === null) throw new AppError("Product workload is not authenticated", "WORKLOAD_INVALID", 401);
  return { actorHumanIdentityId, tenantId, productId: workload.productId };
}

function bearerSessionId(request: FastifyRequest): SessionId {
  const match = /^Bearer ([^\s]+)$/.exec(request.headers.authorization ?? "");
  if (match?.[1] === undefined) throw new AppError("A bearer session is required", "SESSION_INVALID", 401);
  return SessionId.from(match[1]);
}

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new AppError("Invalid administration request", "INVALID_REQUEST", 400);
  return parsed.data;
}

async function administer<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (
      error instanceof AdministrationAuthorizationError ||
      error instanceof PlatformAdministrationError ||
      error instanceof WorkforceAdministrationError
    ) {
      throw administrationAppError(error.code, error.message);
    }
    throw error;
  }
}

function administrationAppError(code: string, message: string): AppError {
  if ([
    "NOT_PLATFORM_ADMIN",
    "NOT_TENANT_ADMIN",
    "ROLE_ESCALATION_FORBIDDEN",
    "CROSS_TENANT_FORBIDDEN",
    "PRODUCT_SCOPE_FORBIDDEN",
    "SELF_MUTATION_FORBIDDEN",
    "NOT_AUTHORIZED",
  ].includes(code)) return new AppError(message, code, 403);
  if (["IDENTITY_NOT_FOUND", "TENANT_NOT_FOUND", "PRODUCT_NOT_FOUND", "MEMBERSHIP_NOT_FOUND"].includes(code)) {
    return new AppError(message, code, 404);
  }
  if ([
    "LAST_OWNER",
    "MEMBERSHIP_RETIRED",
    "MEMBERSHIP_INACTIVE",
    "ENTITLEMENT_RETIRED",
    "PRODUCT_NOT_AVAILABLE",
    "PRODUCT_PARTICIPATION_RETIRED",
    "TENANT_INACTIVE",
    "INITIAL_OWNER_ALREADY_ESTABLISHED",
    "IDEMPOTENCY_KEY_REUSED",
    "TENANT_PROVISIONING_CONFLICT",
    "TENANT_ID_CONFLICT",
    "TENANT_PROVISIONING_INCOMPLETE",
  ].includes(code)) {
    return new AppError(message, code, 409);
  }
  return new AppError(message, code, 400);
}
