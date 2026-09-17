import type { FastifyPluginAsync, FastifyRequest } from "fastify";
import { z } from "zod";

import { EmailAlreadyInUseError, InvalidEmailError, InvalidPasswordError } from "../authentication/credentials/domain/errors.js";
import { InvalidLoginError } from "../operations/application/errors.js";
import type { IdentityServices } from "./services.js";
import { SessionId } from "../sessions/domain/session-id.js";
import { AppError } from "../shared/errors.js";
import { FederatedAuthenticationError } from "../authentication/federated/application/errors.js";
import { FederatedAuthenticationMethodError } from "../authentication/federated/application/manage-federated-authentication-methods.js";
import { SessionRenewalError } from "../sessions/application/use-cases.js";

const credentialsSchema = z.object({
  email: z.string(),
  password: z.string(),
});
const federatedProviderSchema = z.object({
  provider: z.string().min(1).max(32),
});
const federatedCredentialSchema = z.object({
  identityToken: z.string().min(1).max(16_384),
  nonce: z.string().min(32).max(256),
}).strict();
const sessionRenewalSchema = z.object({
  renewalToken: z.string().min(32).max(512),
}).strict();

export function identityRoutes(
  services: IdentityServices,
): FastifyPluginAsync {
  return async (app) => {
    app.post("/register", async (request, reply) => {
      const input = parseCredentials(request.body);
      try {
        const result = await services.register.execute(input);
        return reply.status(201).send(result);
      } catch (error) {
        throw translateRegistrationError(error);
      }
    });

    app.post("/login", async (request, reply) => {
      const input = parseCredentials(request.body);
      try {
        const session = await services.login.execute(input);
        return reply.send({ session });
      } catch (error) {
        if (error instanceof InvalidLoginError) {
          throw new AppError(
            "Invalid email or password",
            "INVALID_CREDENTIALS",
            401,
          );
        }
        throw error;
      }
    });

    app.post("/authentication/federated/:provider", async (request, reply) => {
      const provider = federatedProviderSchema.safeParse(request.params);
      const credential = federatedCredentialSchema.safeParse(request.body);
      if (!provider.success || !credential.success) {
        throw new AppError("Invalid request body", "INVALID_REQUEST", 400);
      }
      try {
        const result = await services.authenticateFederated.execute({
          provider: provider.data.provider,
          ...credential.data,
        });
        return reply.send({
          session: result.session,
          account: { email: result.providerEmail },
        });
      } catch (error) {
        throw translateFederatedAuthenticationError(error);
      }
    });

    app.post("/authentication/federated/:provider/resolve", async (request, reply) => {
      const provider = federatedProviderSchema.safeParse(request.params);
      const credential = federatedCredentialSchema.safeParse(request.body);
      if (!provider.success || !credential.success) {
        throw new AppError("Invalid request body", "INVALID_REQUEST", 400);
      }
      try {
        return reply.send(await services.resolveFederatedIdentity.execute({
          provider: provider.data.provider,
          ...credential.data,
        }));
      } catch (error) {
        throw translateFederatedAuthenticationError(error);
      }
    });

    app.get("/authentication/methods", async (request, reply) => {
      try {
        const methods = await services.federatedAuthenticationMethods.list(bearerSessionId(request));
        return reply.send({ methods });
      } catch (error) {
        throw translateAuthenticationMethodsError(error);
      }
    });

    app.post("/authentication/federated/:provider/link", async (request, reply) => {
      const provider = federatedProviderSchema.safeParse(request.params);
      const credential = federatedCredentialSchema.safeParse(request.body);
      if (!provider.success || !credential.success) {
        throw new AppError("Invalid request body", "INVALID_REQUEST", 400);
      }
      try {
        return reply.send(await services.federatedAuthenticationMethods.link(
          bearerSessionId(request),
          { provider: provider.data.provider, ...credential.data },
        ));
      } catch (error) {
        throw translateAuthenticationMethodsError(error);
      }
    });

    app.delete("/authentication/federated/:provider/link", async (request, reply) => {
      const provider = federatedProviderSchema.safeParse(request.params);
      if (!provider.success) {
        throw new AppError("Invalid provider", "INVALID_REQUEST", 400);
      }
      try {
        return reply.send(await services.federatedAuthenticationMethods.unlink(
          bearerSessionId(request),
          provider.data.provider,
        ));
      } catch (error) {
        throw translateAuthenticationMethodsError(error);
      }
    });

    app.post("/logout", async (request, reply) => {
      const sessionId = bearerSessionId(request);
      await services.logout.execute(sessionId);
      return reply.status(204).send();
    });

    app.post("/session/refresh", async (request, reply) => {
      const input = sessionRenewalSchema.safeParse(request.body);
      if (!input.success) {
        throw new AppError("Invalid request body", "INVALID_REQUEST", 400);
      }
      try {
        return reply.send({ session: await services.renewSession.execute(input.data.renewalToken) });
      } catch (error) {
        if (error instanceof SessionRenewalError) {
          throw new AppError(
            "Session cannot be renewed",
            `SESSION_RENEWAL_${error.reason.toUpperCase()}`,
            401,
          );
        }
        throw error;
      }
    });

    app.get("/session", async (request, reply) => {
      const sessionId = bearerSessionId(request);
      const result = await services.validateSession.execute(sessionId);
      if (result.outcome !== "authenticated") {
        throw new AppError(
          "Session is not authenticated",
          `SESSION_${result.outcome.toUpperCase()}`,
          401,
        );
      }
      return reply.send(result);
    });
  };
}

function translateAuthenticationMethodsError(error: unknown): Error {
  if (error instanceof FederatedAuthenticationError) {
    return translateFederatedAuthenticationError(error);
  }
  if (!(error instanceof FederatedAuthenticationMethodError)) {
    return error instanceof Error ? error : new Error("Authentication method operation failed");
  }
  if (error.code.startsWith("SESSION_")) {
    return new AppError("Session is not authenticated", error.code, 401);
  }
  if (error.code === "IDENTITY_UNAVAILABLE") {
    return new AppError("The Human Identity is unavailable", error.code, 403);
  }
  if (error.code === "FEDERATED_IDENTITY_LINK_CONFLICT") {
    return new AppError("A different provider identity is already connected", error.code, 409);
  }
  if (error.code === "FEDERATED_IDENTITY_RECONCILIATION_REQUIRED") {
    return new AppError("This provider identity belongs to another account and cannot be safely reconciled", error.code, 409);
  }
  return new AppError("The last authentication method cannot be removed", error.code, 409);
}

function translateFederatedAuthenticationError(error: unknown): Error {
  if (!(error instanceof FederatedAuthenticationError)) {
    return error instanceof Error ? error : new Error("Federated authentication failed");
  }
  if (error.code === "PROVIDER_UNSUPPORTED") {
    return new AppError("The federated identity provider is unsupported", "FEDERATED_PROVIDER_UNSUPPORTED", 400);
  }
  if (error.code === "VERIFICATION_UNAVAILABLE") {
    return new AppError("Federated authentication is temporarily unavailable", "FEDERATED_VERIFICATION_UNAVAILABLE", 503);
  }
  if (error.code === "IDENTITY_UNAVAILABLE" || error.code === "FEDERATED_IDENTITY_UNAVAILABLE") {
    return new AppError("Federated authentication is unavailable", "FEDERATED_AUTHENTICATION_UNAVAILABLE", 403);
  }
  if (error.code === "FEDERATED_IDENTITY_CONFLICT") {
    return new AppError("Federated authentication cannot be completed", "FEDERATED_IDENTITY_CONFLICT", 409);
  }
  return new AppError("The federated credential was not accepted", "FEDERATED_CREDENTIAL_INVALID", 401);
}

function parseCredentials(body: unknown): {
  email: string;
  password: string;
} {
  const parsed = credentialsSchema.safeParse(body);
  if (!parsed.success) {
    throw new AppError("Invalid request body", "INVALID_REQUEST", 400);
  }
  return parsed.data;
}

function bearerSessionId(request: FastifyRequest): SessionId {
  const authorization = request.headers.authorization;
  const match = /^Bearer ([^\s]+)$/.exec(authorization ?? "");
  if (match?.[1] === undefined) {
    throw new AppError(
      "A bearer session is required",
      "SESSION_INVALID",
      401,
    );
  }
  return SessionId.from(match[1]);
}

function translateRegistrationError(error: unknown): Error {
  if (error instanceof EmailAlreadyInUseError) {
    return new AppError(
      "An account cannot be created with these details",
      "REGISTRATION_UNAVAILABLE",
      409,
    );
  }
  if (error instanceof InvalidEmailError || error instanceof InvalidPasswordError) {
    return new AppError(
      "Registration details are invalid",
      "INVALID_REGISTRATION_DETAILS",
      400,
    );
  }
  return error instanceof Error ? error : new Error("Registration failed");
}
